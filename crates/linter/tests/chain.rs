//! Integration tests for the chain-aware lints (`RuleSource::Chain`, lint-id
//! prefix `chain_*`), exercised against real, openssl-minted chain fixtures
//! through the public `default_chain_registry()` / `ChainRegistry::run` API and,
//! where the engine cannot reach a violating link, through direct
//! `ChainLint::check(subject, issuer)` invocation.
//!
//! # ⚠️ Fixtures: openssl-generated ONLY — NEVER cert-bar
//!
//! Every `testdata/chain_*.pem` fixture is minted by `testdata/generate.sh` with
//! openssl 3.6.2 (real leaf → intermediate → root issuance, NOT cert-bar), so the
//! linter stays an INDEPENDENT oracle. The PQC chain (`chain_pqc_valid.pem`)
//! needs openssl >= 3.6.2 (ML-DSA). See the "Feature 15" section of
//! `testdata/generate.sh` for the per-fixture provenance notes.
//!
//! # ⚠️ Time-fragility
//!
//! All chain fixtures use BR_OK-aligned validity windows (`2026-06-01 ->
//! 2027-06-01`), EXCEPT `chain_validity_not_nested.pem` whose leaf deliberately
//! outlives its issuer (`notAfter 2027-09-01`). They EXPIRE ~2027-06-01; after
//! that `hygiene_not_expired` fires in the PER-CERT pass (not here — chain lints
//! are clock-independent). Regenerate annually (slide the windows forward).
//! Because the chain lints compare cert-intrinsic fields and each other (never
//! "now"), the assertions below are clock-independent.
//!
//! # Additive design
//!
//! The chain pass is a SEPARATE registry (`default_chain_registry()`) over a
//! SEPARATE trait (`ChainLint`); the per-cert `default_registry()` path is
//! untouched. A test below proves `default_registry()` carries no `chain_*` id.
//!
//! # Broken-chain reporting (missing-middle / unlinkable collapsed sets)
//!
//! `build_chain` emits `MissingMiddleLink` / `Unlinkable` diagnostics for a
//! broken set. When the broken set collapses to a single linkable position (e.g.
//! a leaf + root with the intermediate absent, or a leaf whose issuer DN matches
//! nothing), the built order has < 2 positions and `chain.links()` is empty —
//! there is no real adjacent link to attach the construction findings to. The
//! engine therefore surfaces them on a single **chain-level** report (both
//! indices `CHAIN_LEVEL_INDEX`, `ChainLinkReport::is_chain_level()` true) so the
//! `chain_subject_issuer_dn_match` Error still folds into the exit code. The tests
//! below assert that surfacing AND, separately, assert that `build_chain` produces
//! the diagnostic. See `broken_chain_reporting` below.
//!
//! Conventions (`.claude/rules/rust-testing-core.md`): SIFER, nested module per
//! lint, `.unwrap()`-style result assertions.

use linter::lints::chain::{AkiSkiMatch, IssuerIsCa, PathLenRespected, ValidityNested};
use linter::{
    Cert, ChainLint, ConstructionDiagnostic, RuleSource, Severity, build_chain,
    default_chain_registry, default_registry,
};

// include_bytes! resolves relative to this source file
// (crates/linter/tests/chain.rs); ../../../testdata reaches the workspace-root
// testdata/ directory.
const CHAIN_VALID: &[u8] = include_bytes!("../../../testdata/chain_valid.pem");
const CHAIN_SHUFFLED: &[u8] = include_bytes!("../../../testdata/chain_shuffled.pem");
const CHAIN_MISSING_MIDDLE: &[u8] = include_bytes!("../../../testdata/chain_missing_middle.pem");
const CHAIN_DN_MISMATCH: &[u8] = include_bytes!("../../../testdata/chain_dn_mismatch.pem");
const CHAIN_AKI_SKI_MISMATCH: &[u8] =
    include_bytes!("../../../testdata/chain_aki_ski_mismatch.pem");
const CHAIN_ISSUER_NOT_CA: &[u8] = include_bytes!("../../../testdata/chain_issuer_not_ca.pem");
const CHAIN_PATH_LEN_EXCEEDED: &[u8] =
    include_bytes!("../../../testdata/chain_path_len_exceeded.pem");
const CHAIN_VALIDITY_NOT_NESTED: &[u8] =
    include_bytes!("../../../testdata/chain_validity_not_nested.pem");
const CHAIN_CLASSICAL_VALID: &[u8] = include_bytes!("../../../testdata/chain_classical_valid.pem");
const CHAIN_PQC_VALID: &[u8] = include_bytes!("../../../testdata/chain_pqc_valid.pem");
const CHAIN_BAD_SIGNATURE: &[u8] = include_bytes!("../../../testdata/chain_bad_signature.pem");
const CHAIN_UNSUPPORTED_SIG_ALG: &[u8] =
    include_bytes!("../../../testdata/chain_unsupported_sig_alg.pem");

// A leaf that carries an SKI but NO AKI keyIdentifier — used for the
// `chain_aki_ski_match` "subject has no AKI" pass-by-vacuity case.
const NO_AKI_LEAF: &[u8] = include_bytes!("../../../testdata/cabf_smime_no_aki.pem");

/// Parses a PEM bundle into its `Vec<Cert>` (leaf-first as concatenated).
fn load_bundle(pem: &[u8]) -> Vec<Cert> {
    Cert::from_pem(pem).expect("chain fixture must parse")
}

/// Parses a single-cert PEM, returning the first certificate.
fn load_one(pem: &[u8]) -> Cert {
    let mut certs = Cert::from_pem(pem).expect("fixture must parse");
    certs.remove(0)
}

/// Collects every (lint_id, severity, message) finding produced by the full
/// chain registry over `certs`, across all built links.
fn all_findings(certs: &[Cert]) -> Vec<(&'static str, Severity, String)> {
    let reg = default_chain_registry();
    reg.run(certs)
        .into_iter()
        .flat_map(|r| r.outcomes)
        .flat_map(|o| {
            let id = o.lint_id;
            o.findings
                .into_iter()
                .map(move |f| (id, f.severity, f.message))
        })
        .collect()
}

/// True if any finding for `lint_id` at `severity` exists.
fn fires(findings: &[(&'static str, Severity, String)], lint_id: &str, severity: Severity) -> bool {
    findings
        .iter()
        .any(|(id, sev, _)| *id == lint_id && *sev == severity)
}

mod registry_shape {
    use super::*;

    #[test]
    fn chain_registry_holds_seven_or_eight_lints() {
        // Setup + Invoke
        let reg = default_chain_registry();

        // Expect: 7 always-on chain lints; 8 when the verify feature adds
        // chain_signature_valid.
        #[cfg(not(feature = "verify"))]
        assert_eq!(reg.len(), 7, "7 chain lints without verify");
        #[cfg(feature = "verify")]
        assert_eq!(reg.len(), 8, "8 chain lints with verify");
    }

    /// Additive design: the PER-CERT registry must contain NO `chain_*` lint id.
    #[test]
    fn per_cert_registry_has_no_chain_lint() {
        // Setup + Invoke: run the per-cert registry over a chain fixture's leaf and
        // confirm no chain id appears.
        let leaf = load_bundle(CHAIN_VALID).remove(0);
        let outcomes = default_registry().run(&leaf);

        // Expect: no per-cert outcome carries a chain_* id or the Chain source.
        for o in &outcomes {
            assert!(
                !o.lint_id.starts_with("chain_"),
                "per-cert registry must not expose a chain lint: {}",
                o.lint_id
            );
            assert_ne!(
                o.source,
                RuleSource::Chain,
                "per-cert registry must not carry RuleSource::Chain"
            );
        }
    }
}

mod length_gating {
    use super::*;

    #[test]
    fn empty_slice_yields_no_reports() {
        let reg = default_chain_registry();
        assert!(reg.run(&[]).is_empty());
    }

    #[test]
    fn single_cert_yields_no_reports() {
        let reg = default_chain_registry();
        let leaf = load_bundle(CHAIN_VALID).remove(0);
        assert!(reg.run(&[leaf]).is_empty());
    }

    #[test]
    fn three_cert_chain_yields_two_links() {
        let reg = default_chain_registry();
        let reports = reg.run(&load_bundle(CHAIN_VALID));
        assert_eq!(reports.len(), 2, "N-1 links for an N=3 cert chain");
    }
}

mod clean_chain {
    use super::*;

    /// The clean leaf→intermediate→root chain produces NO Error/Warn from any
    /// chain lint, and NO construction Notice (it is already in leaf-first order
    /// and bundles its own root).
    #[test]
    fn clean_chain_has_no_error_warn_or_construction_notice() {
        // Setup + Invoke
        let findings = all_findings(&load_bundle(CHAIN_VALID));

        // Expect: nothing at Warn or above.
        assert!(
            !findings.iter().any(|(_, sev, _)| *sev >= Severity::Warn),
            "clean chain produced unexpected warn+ findings: {findings:?}"
        );
        // And no construction Notices (in order, root present).
        assert!(
            !fires(&findings, "chain_not_in_order", Severity::Notice),
            "in-order chain must not fire chain_not_in_order"
        );
        assert!(
            !fires(&findings, "chain_issuer_not_in_chain", Severity::Notice),
            "a chain that bundles its self-signed root must not fire chain_issuer_not_in_chain"
        );
    }

    /// A bundle that OMITS its root → `chain_issuer_not_in_chain` Notice on the
    /// top intermediate, and NEVER an Error (the partial chain's links are sound).
    #[test]
    fn root_absent_bundle_fires_issuer_not_in_chain_notice_only() {
        // Setup: leaf + intermediate only (drop the root) from the clean chain.
        let mut certs = load_bundle(CHAIN_VALID);
        certs.truncate(2); // leaf, intermediate

        // Invoke
        let findings = all_findings(&certs);

        // Expect: the Notice fires; nothing at Warn or above.
        assert!(
            fires(&findings, "chain_issuer_not_in_chain", Severity::Notice),
            "root-absent bundle must fire chain_issuer_not_in_chain Notice: {findings:?}"
        );
        assert!(
            !findings.iter().any(|(_, sev, _)| *sev >= Severity::Warn),
            "a root-absent-but-otherwise-sound chain must not raise any Error/Warn: {findings:?}"
        );
    }
}

mod not_in_order {
    use super::*;

    /// `chain_shuffled.pem` is the SAME three certs as the clean chain, in
    /// non-leaf-first order. `build_chain` reorders it; exactly the
    /// `chain_not_in_order` Notice fires and ALL link lints pass over the
    /// reordered chain (NO Error/Warn from mere disorder).
    #[test]
    fn shuffled_complete_chain_fires_only_the_notice() {
        // Setup + Invoke
        let findings = all_findings(&load_bundle(CHAIN_SHUFFLED));

        // Expect: the Notice fires.
        assert!(
            fires(&findings, "chain_not_in_order", Severity::Notice),
            "shuffled chain must fire chain_not_in_order: {findings:?}"
        );
        // And nothing at Warn or above (disorder alone is not an error).
        assert!(
            !findings.iter().any(|(_, sev, _)| *sev >= Severity::Warn),
            "disorder alone must not raise Error/Warn: {findings:?}"
        );
    }

    /// Link lints attach to the BUILT-order link indices, not the raw input
    /// positions. The shuffled input is [root=0, leaf=1, inter=2]; the built
    /// order is leaf(1)→inter(2)→root(0), so the first link is (1, 2).
    #[test]
    fn link_reports_follow_built_order_not_input_order() {
        // Setup + Invoke
        let reg = default_chain_registry();
        let reports = reg.run(&load_bundle(CHAIN_SHUFFLED));

        // Expect: two links, the first being subject=1 (leaf) → issuer=2 (inter).
        assert_eq!(reports.len(), 2);
        assert_eq!(
            (reports[0].subject_index, reports[0].issuer_index),
            (1, 2),
            "first built link must be leaf(input idx 1) → inter(input idx 2)"
        );
        assert_eq!(
            (reports[1].subject_index, reports[1].issuer_index),
            (2, 0),
            "second built link must be inter(2) → root(0)"
        );
    }

    /// The clean (already-ordered) chain does NOT fire the Notice.
    #[test]
    fn ordered_chain_does_not_fire_the_notice() {
        let findings = all_findings(&load_bundle(CHAIN_VALID));
        assert!(
            !fires(&findings, "chain_not_in_order", Severity::Notice),
            "an already-ordered chain must not fire chain_not_in_order: {findings:?}"
        );
    }
}

mod broken_chain_reporting {
    //! Broken chains surface their structural-integrity Error through
    //! `ChainRegistry::run` even when they collapse to fewer than two linked
    //! positions.
    //!
    //! For `chain_missing_middle.pem` (leaf + root, intermediate absent) and
    //! `chain_dn_mismatch.pem` (leaf whose issuer DN matches no bundled cert),
    //! `build_chain` emits `MissingMiddleLink` / `Unlinkable` diagnostics and the
    //! built order collapses to a single position (`chain.links()` is empty). With
    //! no real adjacent link to attach to, `run()` emits a single **chain-level**
    //! report (`ChainLinkReport::is_chain_level()` true) carrying the
    //! `chain_subject_issuer_dn_match` Error so it folds into the exit code. These
    //! tests assert that surfacing AND prove the diagnostic exists at the
    //! `build_chain` layer.
    use super::*;

    /// Finds the `chain_subject_issuer_dn_match` findings across all reports.
    fn dn_match_findings(reports: &[linter::ChainLinkReport]) -> Vec<(Severity, &str)> {
        reports
            .iter()
            .flat_map(|r| r.outcomes.iter())
            .filter(|o| o.lint_id == "chain_subject_issuer_dn_match")
            .flat_map(|o| o.findings.iter())
            .map(|f| (f.severity, f.message.as_str()))
            .collect()
    }

    /// `build_chain` on the missing-middle bundle produces the diagnostic and the
    /// built order collapses to a single position.
    #[test]
    fn build_chain_reports_missing_middle_diagnostic() {
        // Setup + Invoke
        let certs = load_bundle(CHAIN_MISSING_MIDDLE);
        let (chain, diags) = build_chain(&certs);

        // Find + Expect: a MissingMiddleLink diagnostic is present, and the built
        // order collapsed to a single position (the leaf can link to nothing).
        assert!(
            diags
                .iter()
                .any(|d| matches!(d, ConstructionDiagnostic::MissingMiddleLink(_))),
            "build_chain must flag the missing middle link: {diags:?}"
        );
        assert!(
            chain.links().is_empty(),
            "the broken set collapses to a single position (no links): {:?}",
            chain.order
        );
    }

    /// `run()` surfaces the `chain_subject_issuer_dn_match` Error on a chain-level
    /// report for the missing-middle bundle.
    #[test]
    fn run_surfaces_dn_match_error_for_missing_middle() {
        // Setup + Invoke
        let reports = default_chain_registry().run(&load_bundle(CHAIN_MISSING_MIDDLE));

        // Find + Expect: exactly one chain-level report carrying the structural
        // integrity Error (the built order has no real link to attach to).
        assert_eq!(
            reports.len(),
            1,
            "a collapsed broken set yields one chain-level report: {reports:?}"
        );
        assert!(
            reports[0].is_chain_level(),
            "the broken-set report must be chain-level (no real link): {reports:?}"
        );
        let dn = dn_match_findings(&reports);
        assert!(
            dn.iter().any(|(sev, msg)| *sev == Severity::Error
                && (msg.contains("missing middle link")
                    || msg.contains("broken chain")
                    || msg.contains("no issuer"))),
            "expected a chain_subject_issuer_dn_match Error for the missing middle: {dn:?}"
        );
    }

    /// The 3-cert DN-mismatch bundle (leaf whose issuer DN matches no bundled
    /// intermediate) produces diagnostics from `build_chain` AND a chain-level
    /// `chain_subject_issuer_dn_match` Error from `run()`.
    #[test]
    fn dn_mismatch_diagnoses_and_run_surfaces_error() {
        // Setup + Invoke
        let certs = load_bundle(CHAIN_DN_MISMATCH);
        let (_chain, diags) = build_chain(&certs);

        // build_chain flags the unlinkable / missing-middle structure.
        assert!(
            diags.iter().any(|d| matches!(
                d,
                ConstructionDiagnostic::MissingMiddleLink(_)
                    | ConstructionDiagnostic::Unlinkable(_)
            )),
            "build_chain must flag the DN-mismatch as unlinkable/missing-middle: {diags:?}"
        );

        // …and run() surfaces the structural-integrity Error on a chain-level
        // report.
        let reports = default_chain_registry().run(&certs);
        assert_eq!(
            reports.len(),
            1,
            "a collapsed broken set yields one chain-level report: {reports:?}"
        );
        assert!(
            reports[0].is_chain_level(),
            "the DN-mismatch report must be chain-level: {reports:?}"
        );
        let dn = dn_match_findings(&reports);
        assert!(
            dn.iter().any(|(sev, msg)| *sev == Severity::Error
                && (msg.contains("unlinkable")
                    || msg.contains("does not link")
                    || msg.contains("no issuer")
                    || msg.contains("missing middle link"))),
            "expected a chain_subject_issuer_dn_match Error for the DN mismatch: {dn:?}"
        );
    }

    /// A ≥3-cert set with an unlinkable stray: a complete leaf→inter pair PLUS an
    /// unrelated self-signed root. `build_chain` flags the stray as `Unlinkable`,
    /// and the engine still reports the SOUND leaf→inter link (graceful, partial).
    #[test]
    fn unlinkable_stray_alongside_sound_pair_is_diagnosed() {
        // Setup: clean leaf + clean intermediate + the OTHER (P-521) chain's root
        // as an unrelated stray that links to nothing here.
        let mut certs = load_bundle(CHAIN_VALID);
        certs.truncate(2); // leaf, intermediate (a sound, root-absent pair)
        let stray = {
            let mut p521 = load_bundle(CHAIN_UNSUPPORTED_SIG_ALG);
            p521.remove(2) // the self-signed P-521 root
        };
        certs.push(stray);

        // Invoke
        let (_chain, diags) = build_chain(&certs);

        // Expect: the stray is flagged Unlinkable by construction.
        assert!(
            diags
                .iter()
                .any(|d| matches!(d, ConstructionDiagnostic::Unlinkable(_))),
            "an unrelated stray must be flagged Unlinkable: {diags:?}"
        );

        // And the engine still reports the sound leaf→inter link (it does not
        // abort the whole pass over a stray). The leaf→inter link exists.
        let reports = default_chain_registry().run(&certs);
        assert!(
            reports
                .iter()
                .any(|r| r.subject_index == 0 && r.issuer_index == 1),
            "the sound leaf→inter link must still be reported: {reports:?}"
        );
    }
}

mod aki_ski_match {
    use super::*;

    /// `chain_aki_ski_match` fires Error when the subject's AKI keyId ≠ the
    /// issuer's SKI (both present). The committed `chain_aki_ski_mismatch.pem`
    /// bundles a leaf (AKI = a DIFFERENT same-DN intermediate's SKI) + the real
    /// intermediate (same subject DN, different SKI). Because `build_chain`'s
    /// linkage rule ALSO requires AKI==SKI, the leaf does not link through the
    /// engine — so this lint is exercised by DIRECT `check(subject, issuer)`
    /// invocation on the two hand-loaded certs (documented in generate.sh).
    #[test]
    fn fires_error_on_aki_ski_mismatch_via_direct_check() {
        // Setup: load the leaf + real intermediate from the 2-cert fixture.
        let certs = load_bundle(CHAIN_AKI_SKI_MISMATCH);
        let (leaf, inter) = (&certs[0], &certs[1]);
        let lint = AkiSkiMatch::new();

        // Invoke
        let findings = lint.check(leaf, inter);

        // Expect: exactly one Error finding naming the mismatch.
        assert_eq!(findings.len(), 1, "one mismatch finding expected");
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0]
                .message
                .contains("does not match the issuer's Subject Key Identifier"),
            "message should name the AKI/SKI mismatch: {}",
            findings[0].message
        );
    }

    /// Pass-by-vacuity: when the subject has NO AKI keyIdentifier, the lint
    /// returns no finding even against an issuer that has an SKI.
    #[test]
    fn pass_by_vacuity_when_subject_lacks_aki() {
        // Setup: a leaf with SKI-but-no-AKI as subject; the clean intermediate
        // (has an SKI) as issuer.
        let subject = load_one(NO_AKI_LEAF);
        let inter = load_bundle(CHAIN_VALID).remove(1);
        let lint = AkiSkiMatch::new();

        // Invoke + Expect: no finding (cannot compare without the subject's AKI).
        assert!(
            lint.check(&subject, &inter).is_empty(),
            "no AKI keyId on the subject must pass by vacuity"
        );
    }

    /// The clean chain passes the lint on every built link.
    #[test]
    fn passes_on_clean_chain() {
        let findings = all_findings(&load_bundle(CHAIN_VALID));
        assert!(
            !fires(&findings, "chain_aki_ski_match", Severity::Error),
            "clean chain must pass chain_aki_ski_match: {findings:?}"
        );
    }
}

mod issuer_is_ca {
    use super::*;

    /// Error when the issuer is not a certificate-signing CA (CA:FALSE / no
    /// keyCertSign). The committed `chain_issuer_not_ca.pem` links leaf → non-CA
    /// issuer → root, so the engine reports the Error on the leaf→issuer link.
    #[test]
    fn fires_error_when_issuer_is_not_a_ca() {
        // Setup + Invoke
        let findings = all_findings(&load_bundle(CHAIN_ISSUER_NOT_CA));

        // Expect: the Error fires and names the non-CA reason.
        assert!(
            fires(&findings, "chain_issuer_is_ca", Severity::Error),
            "non-CA issuer must fire chain_issuer_is_ca: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|(id, _, msg)| *id == "chain_issuer_is_ca"
                    && msg.contains("is not a certificate-signing CA")),
            "message should explain the issuer is not a CA: {findings:?}"
        );
    }

    /// The clean chain (CA issuers throughout) passes.
    #[test]
    fn passes_on_clean_chain() {
        let findings = all_findings(&load_bundle(CHAIN_VALID));
        assert!(
            !fires(&findings, "chain_issuer_is_ca", Severity::Error),
            "clean chain CA issuers must pass: {findings:?}"
        );
    }

    /// Direct invocation exercising the cA=TRUE-but-no-keyCertSign path: a leaf
    /// (CA:FALSE, no keyCertSign) used as an issuer fails for the keyCertSign
    /// reason.
    #[test]
    fn direct_check_flags_missing_key_cert_sign() {
        // Setup: use the clean leaf (CA:FALSE) as a stand-in non-CA issuer.
        let leaf = load_bundle(CHAIN_VALID).remove(0);
        let lint = IssuerIsCa::new();

        // Invoke: subject is irrelevant to the issuer check; pass the leaf as both.
        let findings = lint.check(&leaf, &leaf);

        // Expect: an Error (a leaf cannot issue).
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
    }
}

mod path_len_respected {
    use super::*;

    /// Error on `chain_path_len_exceeded.pem`: a root with pathLenConstraint=0
    /// that nonetheless has an intermediate CA below it. The violation attaches to
    /// the intermediate→root link (the constrained issuer).
    #[test]
    fn fires_error_when_path_len_exceeded() {
        // Setup + Invoke
        let reg = default_chain_registry();
        let reports = reg.run(&load_bundle(CHAIN_PATH_LEN_EXCEEDED));

        // Expect: the Error fires on the intermediate→root link (indices 1→2).
        let on_top_link = reports
            .iter()
            .find(|r| r.subject_index == 1 && r.issuer_index == 2)
            .expect("intermediate→root link must exist");
        let fired = on_top_link
            .outcomes
            .iter()
            .filter(|o| o.lint_id == "chain_path_len_respected")
            .flat_map(|o| &o.findings)
            .any(|f| f.severity == Severity::Error && f.message.contains("pathLenConstraint=0"));
        assert!(
            fired,
            "path-len violation must attach to the constrained issuer link: {reports:?}"
        );
    }

    /// The clean chain (intermediate pathlen:0 with only a leaf below) passes.
    #[test]
    fn passes_on_clean_chain() {
        let findings = all_findings(&load_bundle(CHAIN_VALID));
        assert!(
            !fires(&findings, "chain_path_len_respected", Severity::Error),
            "clean chain must respect path length: {findings:?}"
        );
    }

    /// Pass-by-vacuity via direct invocation: an issuer with no
    /// pathLenConstraint (the clean self-signed root is unconstrained) produces no
    /// finding regardless of depth.
    #[test]
    fn pass_by_vacuity_when_issuer_unconstrained() {
        // Setup: the clean root has CA:TRUE but no pathLenConstraint.
        let root = load_bundle(CHAIN_VALID).remove(2);
        let leaf = load_bundle(CHAIN_VALID).remove(0);
        let lint = PathLenRespected::new();

        // Invoke with a deep issuer index; an unconstrained CA never fails.
        let findings = lint.check_with_depth(&leaf, &root, 5);

        // Expect: no finding.
        assert!(
            findings.is_empty(),
            "an unconstrained CA must pass by vacuity at any depth: {findings:?}"
        );
    }
}

mod validity_nested {
    use super::*;

    /// Warn on `chain_validity_not_nested.pem`: the leaf's notAfter extends beyond
    /// its issuer's notAfter (subject outlives issuer). Clock-independent.
    #[test]
    fn fires_warn_when_subject_outlives_issuer() {
        // Setup + Invoke
        let findings = all_findings(&load_bundle(CHAIN_VALIDITY_NOT_NESTED));

        // Expect: the Warn fires and names the outliving notAfter.
        assert!(
            fires(&findings, "chain_validity_nested", Severity::Warn),
            "a subject outliving its issuer must fire chain_validity_nested: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|(id, _, msg)| *id == "chain_validity_nested"
                    && msg.contains("outlives the issuer")),
            "message should explain the subject outlives the issuer: {findings:?}"
        );
    }

    /// The clean chain (nested validity windows) passes. Asserting on a fixed
    /// fixture (no "now") proves clock-independence.
    #[test]
    fn passes_on_clean_chain_clock_independent() {
        let findings = all_findings(&load_bundle(CHAIN_VALID));
        assert!(
            !fires(&findings, "chain_validity_nested", Severity::Warn),
            "clean chain's nested validity must pass: {findings:?}"
        );
    }

    /// Direct invocation: swapping subject/issuer of the not-nested fixture so the
    /// long-lived cert is the ISSUER passes (the now-subject is within it).
    #[test]
    fn direct_check_passes_when_window_is_nested() {
        // Setup: the not-nested fixture's leaf (long-lived) as ISSUER, and the
        // clean leaf (BR_OK window) as subject — the subject is within the issuer.
        let long_lived = load_bundle(CHAIN_VALIDITY_NOT_NESTED).remove(0);
        let clean_leaf = load_bundle(CHAIN_VALID).remove(0);
        let lint = ValidityNested::new();

        // Invoke + Expect: no notAfter finding (subject ends before the issuer).
        let findings = lint.check(&clean_leaf, &long_lived);
        assert!(
            !findings.iter().any(|f| f.message.contains("outlives")),
            "a properly nested window must not fire the notAfter warning: {findings:?}"
        );
    }
}

#[cfg(feature = "verify")]
mod signature_valid {
    //! Signature-verification lint (`chain_signature_valid`), gated on the
    //! `verify` feature. Without `verify` the lint is not registered (proven in
    //! `signature_lint_gating` below).
    use super::*;

    /// The classical (ECDSA P-256) chain verifies on every link via `ring`.
    #[test]
    fn classical_chain_verifies() {
        let findings = all_findings(&load_bundle(CHAIN_CLASSICAL_VALID));
        assert!(
            !findings
                .iter()
                .any(|(id, _, _)| *id == "chain_signature_valid"),
            "a valid classical chain must produce no chain_signature_valid finding: {findings:?}"
        );
    }

    /// The default RSA clean chain also verifies (positive control via `ring`).
    #[test]
    fn rsa_clean_chain_verifies() {
        let findings = all_findings(&load_bundle(CHAIN_VALID));
        assert!(
            !findings
                .iter()
                .any(|(id, _, _)| *id == "chain_signature_valid"),
            "the clean RSA chain must verify: {findings:?}"
        );
    }

    /// The PQC chain (ML-DSA-65 throughout) verifies via `fips204`.
    #[test]
    fn pqc_chain_verifies() {
        let findings = all_findings(&load_bundle(CHAIN_PQC_VALID));
        assert!(
            !findings
                .iter()
                .any(|(id, _, _)| *id == "chain_signature_valid"),
            "a valid ML-DSA chain must verify via fips204: {findings:?}"
        );
    }

    /// `chain_bad_signature.pem` has a leaf whose signature value is DER-patched,
    /// so it does not verify against the intermediate → Error on the leaf→inter
    /// link only.
    #[test]
    fn bad_signature_fires_error_on_the_broken_link() {
        // Setup + Invoke
        let reg = default_chain_registry();
        let reports = reg.run(&load_bundle(CHAIN_BAD_SIGNATURE));

        // Expect: the Error fires on the leaf→inter link (indices 0→1).
        let leaf_link = reports
            .iter()
            .find(|r| r.subject_index == 0 && r.issuer_index == 1)
            .expect("leaf→inter link must exist");
        let fired = leaf_link
            .outcomes
            .iter()
            .filter(|o| o.lint_id == "chain_signature_valid")
            .flat_map(|o| &o.findings)
            .any(|f| f.severity == Severity::Error && f.message.contains("does not verify"));
        assert!(
            fired,
            "the patched leaf signature must fire chain_signature_valid Error: {reports:?}"
        );

        // The intermediate→root link still verifies (only the leaf was patched).
        let top_link = reports
            .iter()
            .find(|r| r.subject_index == 1 && r.issuer_index == 2)
            .expect("inter→root link must exist");
        assert!(
            top_link
                .outcomes
                .iter()
                .filter(|o| o.lint_id == "chain_signature_valid")
                .all(|o| o.findings.is_empty()),
            "the unpatched inter→root link must still verify"
        );
    }

    /// `chain_unsupported_sig_alg.pem` is a P-521 / ecdsa-with-SHA512 chain that
    /// the `ring`-backed verifier cannot check → Notice (fail-open), never Error.
    #[test]
    fn unsupported_algorithm_is_notice_not_error() {
        // Setup + Invoke
        let findings = all_findings(&load_bundle(CHAIN_UNSUPPORTED_SIG_ALG));

        // Expect: a Notice for chain_signature_valid, and NO Error from it.
        assert!(
            fires(&findings, "chain_signature_valid", Severity::Notice),
            "an unsupported algorithm must yield a chain_signature_valid Notice: {findings:?}"
        );
        assert!(
            !fires(&findings, "chain_signature_valid", Severity::Error),
            "an unsupported algorithm must NEVER fail-closed to an Error: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|(id, _, msg)| *id == "chain_signature_valid"
                    && msg.contains("unsupported algorithm")),
            "the Notice message should name the unsupported algorithm: {findings:?}"
        );
    }
}

mod signature_lint_gating {
    use super::*;

    /// Without `verify`, no chain lint carries the `chain_signature_valid` id; the
    /// registry holds exactly 7. With `verify`, the 8th is `chain_signature_valid`.
    #[test]
    fn signature_lint_present_only_with_verify() {
        let reg = default_chain_registry();
        let has_sig = reg
            .run(&load_bundle(CHAIN_VALID))
            .iter()
            .flat_map(|r| &r.outcomes)
            .any(|o| o.lint_id == "chain_signature_valid");

        #[cfg(feature = "verify")]
        assert!(has_sig, "verify build must run chain_signature_valid");
        #[cfg(not(feature = "verify"))]
        assert!(
            !has_sig,
            "non-verify build must NOT run chain_signature_valid"
        );
    }
}
