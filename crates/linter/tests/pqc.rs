//! Integration tests for the post-quantum (`pqc`) lint source (features 13 + 16).
//!
//! These drive the shipped [`default_registry`] over the openssl-generated PQC
//! fixtures in `testdata/` through the public crate API only. The `pqc` source
//! now carries **nine** lints: the five feature-13 **signature** (ML-DSA /
//! SLH-DSA) lints plus the four feature-16 **ML-KEM** (key-establishment) lints.
//! They pin the load-bearing properties of the family:
//!
//! 1. **Per-lint isolation** — each violating fixture surfaces exactly its one
//!    target `pqc_*` finding (at the documented severity, naming the offending
//!    value), and every clean PQC leaf surfaces no `pqc` finding at all.
//! 2. **Universal-but-self-gated scoping** — every signature `pqc` lint
//!    [`Applies`](Applicability::Applies) on a *signature* PQC leaf and is
//!    [`NotApplicable`](Applicability::NotApplicable) on a classical (RSA) or an
//!    ML-KEM leaf; every ML-KEM `pqc` lint Applies on an ML-KEM leaf and is
//!    NotApplicable on an RSA or a *signature* PQC leaf. The two PQC families
//!    self-gate independently on the SPKI algorithm.
//! 3. **No cascade (both directions)** — the `pqc` lints stay NotApplicable on the
//!    RSA `good.pem` (the universal source does not touch classical keys), and
//!    symmetrically the RSA/EC key-strength hygiene lints stay NotApplicable on a
//!    PQC leaf; and the clean ML-KEM leaf, resolved to its `Auto` purpose, trips
//!    NO finding from ANY source (no spurious `cabf_br_*` / `hygiene_*`).
//!
//! # Isolation mechanism
//!
//! The clean PQC leaves are non-CA leaves WITHOUT a serverAuth EKU, so they
//! resolve to the `generic` purpose under [`Registry::run`]. To pin a single
//! lint regardless of purpose resolution we use
//! [`Registry::run_filtered`]`(&cert, &[RuleSource::Pqc])`, which runs ONLY the
//! nine `pqc` lints — exactly the per-lint isolation the test plan asks for. The
//! no-cascade proofs use [`Registry::run`] (full registry) for the
//! classical/signature directions and a purpose-resolved
//! [`CertPurpose::Auto`]`.allowed_sources(..)` filter for the clean-KEM-leaf
//! cross-source assertion (the same source set the CLI would run).
//!
//! # Part 3 — `pqc_key_usage_consistency` encryption-bit extension
//!
//! Feature 16 part 3 extended the existing signature KeyUsage lint to also Error
//! on `dataEncipherment` (bit 3), `encipherOnly` (bit 7) and `decipherOnly`
//! (bit 8). The bit-3/7/8 *messages* are unit-covered in
//! `src/lints/pqc/key_usage_consistency.rs` (no openssl-native ML-DSA fixture
//! asserts those bits, and the tester touch budget does not add one). Here we
//! cover the path end-to-end through the public registry by (a) the feature-13
//! `pqc_bad_key_usage.pem` (an ML-DSA leaf asserting `keyEncipherment`, the
//! sibling encryption-class bit governed by the same rule) and (b) an in-memory,
//! length-preserving DER patch of the clean ML-DSA leaf's KeyUsage BIT STRING that
//! sets `dataEncipherment` — proving bit 3 surfaces through `Cert::load` + the
//! registry without committing a new fixture (openssl follows the LAMPS profile
//! and will not emit `dataEncipherment` on a signature key; the patch breaks the
//! issuer signature, which a structural linter never verifies).
//!
//! # ⚠️ Time-fragility (see `testdata/generate.sh` PQC sections)
//!
//! All PQC fixtures (ML-DSA / SLH-DSA *and* ML-KEM) use the `BR_OK` window
//! (`2026-06-01 -> 2027-06-01`). The pqc-filtered isolation runs are clock
//! independent, but the full-registry no-cascade runs pin the clock to
//! [`TEST_NOW`] (2026-12-01) via [`default_registry_with_now`] so
//! `hygiene_not_expired` cannot trip regardless of the wall clock. Because the
//! clock is pinned, these fixtures do NOT need annual regeneration; the fixed
//! window is kept for byte-reproducibility.
//!
//! # ⚠️ openssl 3.5+ required to regenerate
//!
//! `testdata/generate.sh` produces the signature fixtures with native ML-DSA /
//! SLH-DSA and the ML-KEM fixtures via an ML-DSA CA signing an
//! `x509 -req -force_pubkey <ml-kem.pub>` (ML-KEM keys cannot self-sign), both
//! requiring openssl 3.5+ (verified on 3.6.2). The clean leaves are
//! openssl-native; the deviating fixtures are documented DER byte-patches
//! (openssl follows the LAMPS profile and will not emit the deviations).

use linter::{
    Applicability, CertPurpose, Finding, RuleSource, Severity, default_registry,
    default_registry_with_now,
};

/// A reference "now" inside every currently-valid fixture window (2026-12-01 in
/// Unix seconds), used to pin the clock for full-registry runs that include the
/// hygiene source so `hygiene_not_expired` cannot trip once the real date passes
/// the fixtures' `notAfter`.
const TEST_NOW: i64 = 1_796_083_200;

/// Loads the single leaf certificate from a PEM fixture under `testdata/`.
///
/// `CARGO_MANIFEST_DIR` here is `crates/linter`; `../../testdata` reaches the
/// workspace-root fixture directory.
fn load_fixture(name: &str) -> linter::Cert {
    let path = format!("{}/../../testdata/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let mut certs = linter::Cert::load(&bytes).unwrap();
    certs.remove(0)
}

/// Loads a fixture's PEM bytes (used by the in-memory KU-patch part-3 test).
fn load_fixture_bytes(name: &str) -> Vec<u8> {
    let path = format!("{}/../../testdata/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

/// Runs ONLY the `pqc` lints over the fixture (purpose-independent per-lint
/// isolation; see the module-level "Isolation mechanism" note).
fn run_pqc(name: &str) -> Vec<linter::LintOutcome> {
    let cert = load_fixture(name);
    default_registry().run_filtered(&cert, &[RuleSource::Pqc])
}

/// Every (lint_id, finding) pair across the `pqc`-filtered outcomes.
fn pqc_findings(name: &str) -> Vec<(&'static str, Finding)> {
    run_pqc(name)
        .into_iter()
        .flat_map(|o| o.findings.into_iter().map(move |f| (o.lint_id, f)))
        .collect()
}

/// The five shipped *signature* `pqc` lint ids (feature 13).
const PQC_SIG_LINT_IDS: [&str; 5] = [
    "pqc_algorithm_known",
    "pqc_spki_parameters_absent",
    "pqc_signature_parameters_absent",
    "pqc_public_key_length",
    "pqc_key_usage_consistency",
];

/// The four shipped *ML-KEM* `pqc` lint ids (feature 16).
const PQC_MLKEM_LINT_IDS: [&str; 4] = [
    "pqc_mlkem_algorithm_known",
    "pqc_mlkem_spki_parameters_absent",
    "pqc_mlkem_public_key_length",
    "pqc_mlkem_key_usage_consistency",
];

/// All nine shipped `pqc` lint ids (signature + ML-KEM), in registry order.
const PQC_LINT_IDS: [&str; 9] = [
    "pqc_algorithm_known",
    "pqc_spki_parameters_absent",
    "pqc_signature_parameters_absent",
    "pqc_public_key_length",
    "pqc_key_usage_consistency",
    "pqc_mlkem_algorithm_known",
    "pqc_mlkem_spki_parameters_absent",
    "pqc_mlkem_public_key_length",
    "pqc_mlkem_key_usage_consistency",
];

/// Total `pqc`-sourced outcomes produced for any single certificate (every `pqc`
/// lint reports one outcome, applicable or not).
const PQC_OUTCOME_COUNT: usize = 9;

mod clean_leaves {
    use super::*;

    /// The clean ML-DSA-65 leaf passes every `pqc` lint: each of the nine applies
    /// (signature) or is N/A (ML-KEM), none finds anything.
    #[test]
    fn mldsa_good_passes_all_pqc_lints() {
        // Setup + Invoke.
        let outcomes = run_pqc("pqc_mldsa_good.pem");

        // Find + Expect: nine outcomes, the five signature lints Apply, the four
        // ML-KEM lints are N/A (an ML-DSA key is not a KEM key), zero findings.
        assert_eq!(outcomes.len(), PQC_OUTCOME_COUNT);
        for o in &outcomes {
            let expected = if PQC_SIG_LINT_IDS.contains(&o.lint_id) {
                Applicability::Applies
            } else {
                Applicability::NotApplicable
            };
            assert_eq!(
                o.applicability, expected,
                "{} applicability on the ML-DSA leaf",
                o.lint_id
            );
        }
        let findings = pqc_findings("pqc_mldsa_good.pem");
        assert!(
            findings.is_empty(),
            "clean ML-DSA leaf must surface no pqc finding; got {findings:?}"
        );
    }

    /// The clean SLH-DSA-SHA2-128s leaf passes every `pqc` lint.
    #[test]
    fn slhdsa_good_passes_all_pqc_lints() {
        // Setup + Invoke.
        let outcomes = run_pqc("pqc_slhdsa_good.pem");

        // Find + Expect.
        assert_eq!(outcomes.len(), PQC_OUTCOME_COUNT);
        let findings = pqc_findings("pqc_slhdsa_good.pem");
        assert!(
            findings.is_empty(),
            "clean SLH-DSA leaf must surface no pqc finding; got {findings:?}"
        );
    }

    /// The clean ML-KEM-768 leaf passes all FOUR ML-KEM lints: each ML-KEM lint
    /// applies (the gate engages on the "kems" arc) and finds nothing, and the
    /// five *signature* lints are N/A (an ML-KEM key is not a signature key).
    #[test]
    fn mlkem_good_passes_all_mlkem_lints() {
        // Setup + Invoke.
        let outcomes = run_pqc("pqc_mlkem_good.pem");

        // Find + Expect: nine outcomes, the four ML-KEM lints Apply, the five
        // signature lints are N/A, zero findings overall.
        assert_eq!(outcomes.len(), PQC_OUTCOME_COUNT);
        for o in &outcomes {
            let expected = if PQC_MLKEM_LINT_IDS.contains(&o.lint_id) {
                Applicability::Applies
            } else {
                Applicability::NotApplicable
            };
            assert_eq!(
                o.applicability, expected,
                "{} applicability on the ML-KEM leaf",
                o.lint_id
            );
        }
        let findings = pqc_findings("pqc_mlkem_good.pem");
        assert!(
            findings.is_empty(),
            "clean ML-KEM leaf must surface no pqc finding; got {findings:?}"
        );
    }
}

mod per_lint_isolation {
    use super::*;

    /// Asserts the `pqc`-filtered run over `fixture` surfaces EXACTLY one finding,
    /// from `lint_id`, at `severity`, whose message contains `needle`.
    fn assert_isolates(fixture: &str, lint_id: &str, severity: Severity, needle: &str) {
        // Find: every finding across the pqc set.
        let findings = pqc_findings(fixture);

        // Expect: precisely one, from the target lint, at the documented severity,
        // naming the offending value.
        assert_eq!(
            findings.len(),
            1,
            "{fixture} must isolate exactly one pqc finding; got {findings:?}"
        );
        let (got_id, finding) = &findings[0];
        assert_eq!(*got_id, lint_id, "{fixture} fired the wrong pqc lint");
        assert_eq!(finding.severity, severity, "{fixture} wrong severity");
        assert!(
            finding.message.contains(needle),
            "{fixture} message must name the offending value ({needle:?}); got {:?}",
            finding.message
        );
    }

    // ---- feature-13 signature deviations -----------------------------------

    /// The unknown-arc OID (`.32`) fires ONLY `pqc_algorithm_known` (Error); the
    /// length / family lints stay silent because there is no known length for an
    /// unassigned set — so the unknown-arc fixture isolates exactly this lint.
    #[test]
    fn unknown_param_set_isolates_algorithm_known() {
        assert_isolates(
            "pqc_unknown_param_set.pem",
            "pqc_algorithm_known",
            Severity::Error,
            "2.16.840.1.101.3.4.3.32",
        );
    }

    /// A present SPKI `parameters` field (NULL) fires ONLY
    /// `pqc_spki_parameters_absent` (Error).
    #[test]
    fn spki_params_present_isolates_spki_parameters_absent() {
        assert_isolates(
            "pqc_spki_params_present.pem",
            "pqc_spki_parameters_absent",
            Severity::Error,
            "SPKI AlgorithmIdentifier.parameters",
        );
    }

    /// A present signature `parameters` field (NULL on the outer
    /// signatureAlgorithm) fires ONLY `pqc_signature_parameters_absent` (Error).
    #[test]
    fn sig_params_present_isolates_signature_parameters_absent() {
        assert_isolates(
            "pqc_sig_params_present.pem",
            "pqc_signature_parameters_absent",
            Severity::Error,
            "signature AlgorithmIdentifier.parameters",
        );
    }

    /// A 1951-byte (one short) ML-DSA-65 public key fires ONLY
    /// `pqc_public_key_length` (Error), with a message naming the parameter set
    /// and the expected-vs-actual lengths.
    #[test]
    fn bad_key_length_isolates_public_key_length() {
        assert_isolates(
            "pqc_bad_key_length.pem",
            "pqc_public_key_length",
            Severity::Error,
            "1952-byte public key, but the SPKI carries a 1951-byte",
        );
    }

    /// A signature key asserting `keyEncipherment` fires ONLY
    /// `pqc_key_usage_consistency` (Error), naming the offending KU bit.
    #[test]
    fn bad_key_usage_isolates_key_usage_consistency() {
        assert_isolates(
            "pqc_bad_key_usage.pem",
            "pqc_key_usage_consistency",
            Severity::Error,
            "keyEncipherment key usage bit",
        );
    }

    // ---- feature-16 ML-KEM deviations --------------------------------------

    /// An ML-KEM arc OID in an unassigned slot (`.4`) fires ONLY
    /// `pqc_mlkem_algorithm_known` (Error); the ML-KEM length lint stays silent
    /// (no known length for an unknown set), so this isolates exactly this lint.
    #[test]
    fn mlkem_unknown_param_set_isolates_mlkem_algorithm_known() {
        assert_isolates(
            "pqc_mlkem_unknown_param_set.pem",
            "pqc_mlkem_algorithm_known",
            Severity::Error,
            "2.16.840.1.101.3.4.4.4",
        );
    }

    /// A present SPKI `parameters` field (NULL) on an ML-KEM key fires ONLY
    /// `pqc_mlkem_spki_parameters_absent` (Error).
    #[test]
    fn mlkem_spki_params_present_isolates_mlkem_spki_parameters_absent() {
        assert_isolates(
            "pqc_mlkem_spki_params_present.pem",
            "pqc_mlkem_spki_parameters_absent",
            Severity::Error,
            "MUST be absent for an ML-KEM public key",
        );
    }

    /// A 1183-byte (one short) ML-KEM-768 encapsulation key fires ONLY
    /// `pqc_mlkem_public_key_length` (Error), naming the set + expected-vs-actual
    /// lengths.
    #[test]
    fn mlkem_bad_key_length_isolates_mlkem_public_key_length() {
        assert_isolates(
            "pqc_mlkem_bad_key_length.pem",
            "pqc_mlkem_public_key_length",
            Severity::Error,
            "ML-KEM-768 mandates a 1184-byte encapsulation key, but the SPKI carries a 1183-byte",
        );
    }

    /// An ML-KEM leaf asserting `digitalSignature` (plus `keyEncipherment`, so the
    /// missing-encryption-bit Warn is suppressed) fires ONLY
    /// `pqc_mlkem_key_usage_consistency` (Error, the forbidden-signing-bit path),
    /// naming the offending KU bit.
    #[test]
    fn mlkem_bad_key_usage_isolates_mlkem_key_usage_consistency() {
        assert_isolates(
            "pqc_mlkem_bad_key_usage.pem",
            "pqc_mlkem_key_usage_consistency",
            Severity::Error,
            "digitalSignature key usage bit",
        );
    }
}

mod scoping {
    use super::*;

    /// Every *signature* `pqc` lint reports `Applies` on a signature PQC leaf, and
    /// every *ML-KEM* `pqc` lint reports `NotApplicable` there (the two families
    /// self-gate independently).
    #[test]
    fn signature_lints_apply_on_signature_pqc_leaves_mlkem_lints_do_not() {
        for fixture in ["pqc_mldsa_good.pem", "pqc_slhdsa_good.pem"] {
            let outcomes = run_pqc(fixture);
            assert_eq!(
                outcomes.len(),
                PQC_OUTCOME_COUNT,
                "{fixture}: expected 9 pqc outcomes"
            );
            for o in &outcomes {
                assert_eq!(o.source, RuleSource::Pqc);
                let expected = if PQC_SIG_LINT_IDS.contains(&o.lint_id) {
                    Applicability::Applies
                } else {
                    Applicability::NotApplicable
                };
                assert_eq!(
                    o.applicability, expected,
                    "{fixture}: {} applicability on a signature PQC leaf",
                    o.lint_id
                );
            }
            assert_id_set(&outcomes);
        }
    }

    /// Every *ML-KEM* `pqc` lint reports `Applies` on the ML-KEM leaf, and every
    /// *signature* `pqc` lint reports `NotApplicable` there.
    #[test]
    fn mlkem_lints_apply_on_mlkem_leaf_signature_lints_do_not() {
        let outcomes = run_pqc("pqc_mlkem_good.pem");
        assert_eq!(outcomes.len(), PQC_OUTCOME_COUNT);
        for o in &outcomes {
            assert_eq!(o.source, RuleSource::Pqc);
            let expected = if PQC_MLKEM_LINT_IDS.contains(&o.lint_id) {
                Applicability::Applies
            } else {
                Applicability::NotApplicable
            };
            assert_eq!(
                o.applicability, expected,
                "{} applicability on the ML-KEM leaf",
                o.lint_id
            );
        }
        assert_id_set(&outcomes);
    }

    /// Every `pqc` lint (signature AND ML-KEM) reports `NotApplicable` on the
    /// classical RSA `good.pem` (the self-gate keeps the universal source off
    /// non-PQC keys).
    #[test]
    fn all_pqc_lints_not_applicable_on_rsa_leaf() {
        let outcomes = run_pqc("good.pem");
        assert_eq!(outcomes.len(), PQC_OUTCOME_COUNT);
        for o in &outcomes {
            assert_eq!(o.source, RuleSource::Pqc);
            assert_eq!(
                o.applicability,
                Applicability::NotApplicable,
                "{} must be NotApplicable on an RSA leaf",
                o.lint_id
            );
            assert!(
                o.findings.is_empty(),
                "a NotApplicable pqc lint must carry no findings: {o:?}"
            );
        }
        assert_id_set(&outcomes);
    }

    /// Asserts the outcomes carry exactly the nine known `pqc` lint ids.
    fn assert_id_set(outcomes: &[linter::LintOutcome]) {
        let mut ids: Vec<&str> = outcomes.iter().map(|o| o.lint_id).collect();
        ids.sort_unstable();
        let mut expected: Vec<&str> = PQC_LINT_IDS.to_vec();
        expected.sort_unstable();
        assert_eq!(ids, expected, "unexpected pqc lint set");
    }
}

mod key_usage_part3 {
    use super::*;

    /// The feature-13 `pqc_bad_key_usage.pem` (an ML-DSA leaf asserting
    /// `keyEncipherment`) drives `pqc_key_usage_consistency` to an Error through
    /// the full registry — the encryption-class-bit branch the part-3 rule
    /// governs, surfacing end-to-end via the public API.
    #[test]
    fn key_encipherment_on_signature_key_errors_through_registry() {
        // Setup + Invoke.
        let cert = load_fixture("pqc_bad_key_usage.pem");
        let outcomes = default_registry_with_now(Some(TEST_NOW)).run(&cert);

        // Find: the pqc_key_usage_consistency outcome.
        let outcome = outcomes
            .iter()
            .find(|o| o.lint_id == "pqc_key_usage_consistency")
            .expect("registry must contain pqc_key_usage_consistency");

        // Expect: applicable on the ML-DSA leaf, one Error naming the wrong bit.
        assert_eq!(outcome.applicability, Applicability::Applies);
        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.findings[0].severity, Severity::Error);
        assert!(
            outcome.findings[0].message.contains("keyEncipherment"),
            "finding should name the offending KU bit: {:?}",
            outcome.findings[0].message
        );
    }

    /// Part 3 end-to-end for the **`dataEncipherment` (bit 3)** path: an in-memory,
    /// length-preserving DER patch of the clean ML-DSA leaf's KeyUsage BIT STRING
    /// adds `dataEncipherment` (keeping `digitalSignature`). Loaded through
    /// `Cert::load` and run over the full registry, `pqc_key_usage_consistency`
    /// surfaces exactly one Error naming `dataEncipherment` — proving the
    /// feature-16 part-3 bit fires through the public API without committing a new
    /// fixture (openssl follows the LAMPS profile and will not emit it on a
    /// signature key). The patch invalidates the issuer signature, which a
    /// structural linter never verifies.
    ///
    /// Bits 7 (`encipherOnly`) and 8 (`decipherOnly`) are message-covered in the
    /// dev-03 unit tests in `src/lints/pqc/key_usage_consistency.rs`; this
    /// integration test pins the bit-3 path end-to-end as the representative
    /// new-encryption-bit case.
    #[test]
    fn data_encipherment_on_signature_key_errors_through_registry() {
        // Setup: clean ML-DSA leaf -> DER, patch KU BIT STRING in place.
        let pem = load_fixture_bytes("pqc_mldsa_good.pem");
        let der = pem_to_der(&pem);
        let patched = patch_ku_add_data_encipherment(der);
        let mut certs = linter::Cert::load(&patched).expect("patched cert must parse");
        let cert = certs.remove(0);

        // Invoke.
        let outcomes = default_registry_with_now(Some(TEST_NOW)).run(&cert);

        // Find: the pqc_key_usage_consistency outcome.
        let outcome = outcomes
            .iter()
            .find(|o| o.lint_id == "pqc_key_usage_consistency")
            .expect("registry must contain pqc_key_usage_consistency");

        // Expect: applicable; exactly one finding, an Error naming dataEncipherment
        // (digitalSignature is still asserted, so no missing-signing-bit Warn).
        assert_eq!(outcome.applicability, Applicability::Applies);
        assert_eq!(
            outcome.findings.len(),
            1,
            "expected exactly the dataEncipherment Error: {:?}",
            outcome.findings
        );
        assert_eq!(outcome.findings[0].severity, Severity::Error);
        assert!(
            outcome.findings[0].message.contains("dataEncipherment"),
            "finding should name dataEncipherment: {:?}",
            outcome.findings[0].message
        );
    }

    /// Decodes the single PEM certificate to DER.
    fn pem_to_der(pem: &[u8]) -> Vec<u8> {
        let text = std::str::from_utf8(pem).expect("PEM is UTF-8");
        let b64: String = text
            .lines()
            .skip_while(|l| !l.contains("BEGIN CERTIFICATE"))
            .skip(1)
            .take_while(|l| !l.contains("END CERTIFICATE"))
            .collect();
        base64_decode(&b64)
    }

    /// Minimal standard-alphabet base64 decoder (no padding-strictness needed for
    /// the fixed test fixture); avoids pulling a base64 crate into the test.
    fn base64_decode(s: &str) -> Vec<u8> {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut val = [255u8; 256];
        for (i, &c) in T.iter().enumerate() {
            val[c as usize] = i as u8;
        }
        let mut bits = 0u32;
        let mut nbits = 0;
        let mut out = Vec::new();
        for &c in s.as_bytes() {
            if c == b'=' || c == b'\n' || c == b'\r' {
                continue;
            }
            let v = val[c as usize];
            assert!(v != 255, "invalid base64 char");
            bits = (bits << 6) | v as u32;
            nbits += 6;
            if nbits >= 8 {
                nbits -= 8;
                out.push((bits >> nbits) as u8);
            }
        }
        out
    }

    /// Sets bit 3 (`dataEncipherment`) in the KeyUsage BIT STRING of the clean
    /// ML-DSA leaf, in place and length-preserving:
    /// `04 04 03 02 07 80` (digitalSignature, 7 unused bits) ->
    /// `04 04 03 02 04 90` (digitalSignature + dataEncipherment, 4 unused bits).
    fn patch_ku_add_data_encipherment(mut der: Vec<u8>) -> Vec<u8> {
        const FROM: [u8; 6] = [0x04, 0x04, 0x03, 0x02, 0x07, 0x80];
        const TO: [u8; 6] = [0x04, 0x04, 0x03, 0x02, 0x04, 0x90];
        let pos = der
            .windows(FROM.len())
            .position(|w| w == FROM)
            .expect("KU BIT STRING (digitalSignature only) must appear once");
        assert!(
            der.windows(FROM.len()).filter(|w| *w == FROM).count() == 1,
            "KU BIT STRING pattern must be unique to patch safely"
        );
        der[pos..pos + TO.len()].copy_from_slice(&TO);
        der
    }
}

mod no_cascade {
    use super::*;

    /// No-cascade direction 1 (PQC lints do not touch classical keys): a raw
    /// `default_registry().run()` over the RSA `good.pem` yields nine `pqc`
    /// outcomes, ALL `NotApplicable` with empty findings. This proves the
    /// universal `Pqc` source does not cascade onto an RSA/EC certificate.
    #[test]
    fn raw_run_on_rsa_good_has_all_pqc_outcomes_not_applicable() {
        // Setup + Invoke: the FULL shipped registry on a classical cert.
        let cert = load_fixture("good.pem");
        let outcomes = default_registry_with_now(Some(TEST_NOW)).run(&cert);

        // Find: just the pqc-sourced outcomes.
        let pqc: Vec<&linter::LintOutcome> = outcomes
            .iter()
            .filter(|o| o.source == RuleSource::Pqc)
            .collect();

        // Expect: all nine present, all NotApplicable, all empty.
        assert_eq!(
            pqc.len(),
            PQC_OUTCOME_COUNT,
            "expected the 9 pqc outcomes in the full run"
        );
        for o in &pqc {
            assert_eq!(
                o.applicability,
                Applicability::NotApplicable,
                "{} must not cascade onto the RSA good.pem",
                o.lint_id
            );
            assert!(o.findings.is_empty());
        }
        let mut ids: Vec<&str> = pqc.iter().map(|o| o.lint_id).collect();
        ids.sort_unstable();
        let mut expected = PQC_LINT_IDS.to_vec();
        expected.sort_unstable();
        assert_eq!(ids, expected);
    }

    /// No-cascade direction 2 (RSA/EC hygiene lints do not touch PQC keys): on the
    /// ML-KEM leaf, the key-strength hygiene lints `hygiene_rsa_key_min_2048` and
    /// `hygiene_ecdsa_curve_allowlist` are `NotApplicable` (an ML-KEM key is
    /// neither RSA nor EC), so a PQC key never trips the classical hygiene checks.
    #[test]
    fn raw_run_on_mlkem_leaf_leaves_rsa_ec_hygiene_not_applicable() {
        // Setup + Invoke.
        let cert = load_fixture("pqc_mlkem_good.pem");
        let outcomes = default_registry_with_now(Some(TEST_NOW)).run(&cert);

        // Find + Expect: each key-strength hygiene lint is present and N/A.
        for id in ["hygiene_rsa_key_min_2048", "hygiene_ecdsa_curve_allowlist"] {
            let o = outcomes
                .iter()
                .find(|o| o.lint_id == id)
                .unwrap_or_else(|| panic!("default registry must contain {id}"));
            assert_eq!(o.source, RuleSource::Hygiene);
            assert_eq!(
                o.applicability,
                Applicability::NotApplicable,
                "{id} must be NotApplicable on an ML-KEM key"
            );
        }
    }

    /// Cross-source no-cascade for the clean ML-KEM leaf (plan Open Question 3):
    /// resolved to its `Auto` purpose — a generic, no-serverAuth, `CA:FALSE` leaf
    /// resolves to `[Rfc5280, Pqc, Hygiene]` — the leaf trips NO finding from ANY
    /// source. In particular the serverAuth-scoped `cabf_br_*` lints are not even
    /// in the resolved source set, so the clean KEM leaf produces no spurious
    /// `cabf_br_*` (nor `cabf_ev_*` / `hygiene_*`) finding, and the four ML-KEM
    /// lints all pass.
    #[test]
    fn clean_mlkem_leaf_under_resolved_purpose_trips_no_finding() {
        // Setup: the source set the CLI would run for this leaf.
        let cert = load_fixture("pqc_mlkem_good.pem");
        let sources = CertPurpose::Auto.allowed_sources(&cert);

        // Sanity: a generic leaf resolves to the universal sources only (no
        // serverAuth EKU => no CabfBr / CabfEv).
        assert!(
            !sources.contains(&RuleSource::CabfBr),
            "a generic ML-KEM leaf must NOT resolve into the CabfBr source set: {sources:?}"
        );

        // Invoke.
        let outcomes = default_registry_with_now(Some(TEST_NOW)).run_filtered(&cert, &sources);

        // Find: every finding across the resolved-purpose run.
        let findings: Vec<(&str, &Finding)> = outcomes
            .iter()
            .flat_map(|o| o.findings.iter().map(move |f| (o.lint_id, f)))
            .collect();

        // Expect: the clean KEM leaf passes every in-profile lint — no spurious
        // cabf_br / cabf_ev / hygiene / pqc finding.
        assert!(
            findings.is_empty(),
            "clean ML-KEM leaf must trip no finding under its resolved purpose; got {findings:?}"
        );

        // And all four ML-KEM lints applied (they are in scope and passed).
        for id in PQC_MLKEM_LINT_IDS {
            let o = outcomes
                .iter()
                .find(|o| o.lint_id == id)
                .unwrap_or_else(|| panic!("resolved run must contain {id}"));
            assert_eq!(
                o.applicability,
                Applicability::Applies,
                "{id} must Apply on the clean ML-KEM leaf"
            );
        }
    }

    /// PQC-set isolation guard on the clean ML-DSA leaf under the RAW full
    /// registry: across the WHOLE shipped registry, NO `pqc`-sourced finding
    /// surfaces — the clean leaf passes every pqc lint even when run alongside all
    /// other sources.
    ///
    /// NOTE: a raw `default_registry().run()` runs EVERY lint irrespective of
    /// purpose (purpose-based source filtering is the CLI's job via
    /// `run_filtered`). The ML-DSA leaf has no serverAuth EKU, so the broad
    /// `cabf_br_ext_key_usage_server_auth_present` lint DOES fire under the raw
    /// run — that is a `cabf_br` concern, not a `pqc` concern. Here we assert
    /// specifically that NO pqc finding surfaces.
    #[test]
    fn raw_run_on_mldsa_good_surfaces_no_pqc_finding() {
        // Setup + Invoke.
        let cert = load_fixture("pqc_mldsa_good.pem");
        let outcomes = default_registry_with_now(Some(TEST_NOW)).run(&cert);

        // Find: every (lint_id, finding) pair from the pqc-sourced outcomes only.
        let pqc: Vec<(&str, &Finding)> = outcomes
            .iter()
            .filter(|o| o.source == RuleSource::Pqc)
            .flat_map(|o| o.findings.iter().map(move |f| (o.lint_id, f)))
            .collect();

        // Expect: the clean leaf passes every pqc lint in the full run.
        assert!(
            pqc.is_empty(),
            "clean ML-DSA leaf must surface no pqc finding in the full run; got {pqc:?}"
        );
    }
}
