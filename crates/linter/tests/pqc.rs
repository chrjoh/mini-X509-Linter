//! Integration tests for the post-quantum (`pqc`) lint source (feature 13).
//!
//! These drive the shipped [`default_registry`] over the openssl-generated PQC
//! fixtures in `testdata/` through the public crate API only. They pin the three
//! load-bearing properties of the feature:
//!
//! 1. **Per-lint isolation** — each violating fixture surfaces exactly its one
//!    target `pqc_*` finding (at the documented severity, naming the offending
//!    value), and the two clean PQC leaves surface no `pqc` finding at all.
//! 2. **Universal-but-self-gated scoping** — every `pqc` lint reports
//!    [`Applicability::Applies`] on a PQC leaf and
//!    [`Applicability::NotApplicable`] on a classical (RSA) leaf.
//! 3. **No cascade (both directions)** — the `pqc` lints stay
//!    [`Applicability::NotApplicable`] on the RSA `good.pem` (the universal
//!    source does not touch classical keys), and symmetrically the RSA/EC
//!    key-strength hygiene lints stay `NotApplicable` on a PQC leaf.
//!
//! # Isolation mechanism
//!
//! The clean PQC leaves are non-CA leaves WITHOUT a serverAuth EKU, so they
//! resolve to the `generic` purpose under [`Registry::run`]. To pin a single
//! lint regardless of purpose resolution we use
//! [`Registry::run_filtered`]`(&cert, &[RuleSource::Pqc])`, which runs ONLY the
//! five `pqc` lints — exactly the per-lint isolation the test plan asks for. The
//! no-cascade proofs deliberately use the raw [`Registry::run`] to show the full
//! shipped registry behaves correctly on both a classical and a PQC cert.
//!
//! # ⚠️ Time-fragility (see `testdata/generate.sh` PQC section header)
//!
//! The PQC fixtures use the `BR_OK` window (`2026-06-01 -> 2027-06-01`) so they
//! straddle "now" and ONLY their intended `pqc` rule fires. They EXPIRE
//! 2027-06-01; after that `hygiene_not_expired` fires on them and the no-cascade
//! / isolation assertions break wholesale. Regenerate the fixtures annually (the
//! same chore as the BR_OK fixtures).
//!
//! # ⚠️ openssl 3.5+ required to regenerate
//!
//! `testdata/generate.sh` produces these fixtures with native ML-DSA / SLH-DSA,
//! available only on openssl 3.5+ (verified on 3.6.2). The two clean leaves are
//! openssl-native; the four deviating fixtures are documented DER byte-patches
//! (openssl follows the LAMPS profile and will not emit the deviations).

use linter::{Applicability, Finding, RuleSource, Severity, default_registry};

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

/// Runs ONLY the five `pqc` lints over the fixture (purpose-independent per-lint
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

/// The five shipped `pqc` lint ids, in registry order.
const PQC_LINT_IDS: [&str; 5] = [
    "pqc_algorithm_known",
    "pqc_spki_parameters_absent",
    "pqc_signature_parameters_absent",
    "pqc_public_key_length",
    "pqc_key_usage_consistency",
];

mod clean_leaves {
    use super::*;

    /// The clean ML-DSA-65 leaf passes every `pqc` lint: each applies, none finds
    /// anything.
    #[test]
    fn mldsa_good_passes_all_pqc_lints() {
        // Setup + Invoke.
        let outcomes = run_pqc("pqc_mldsa_good.pem");

        // Find + Expect: five outcomes, all Applies, zero findings overall.
        assert_eq!(outcomes.len(), 5);
        assert!(
            outcomes
                .iter()
                .all(|o| o.applicability == Applicability::Applies),
            "all pqc lints must Apply on a PQC leaf: {outcomes:?}"
        );
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
        assert_eq!(outcomes.len(), 5);
        assert!(
            outcomes
                .iter()
                .all(|o| o.applicability == Applicability::Applies)
        );
        let findings = pqc_findings("pqc_slhdsa_good.pem");
        assert!(
            findings.is_empty(),
            "clean SLH-DSA leaf must surface no pqc finding; got {findings:?}"
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
}

mod scoping {
    use super::*;

    /// Every `pqc` lint reports `Applies` on a PQC leaf (the gate engages on the
    /// ML-DSA / SLH-DSA arc).
    #[test]
    fn all_pqc_lints_apply_on_both_pqc_leaves() {
        for fixture in ["pqc_mldsa_good.pem", "pqc_slhdsa_good.pem"] {
            let outcomes = run_pqc(fixture);
            assert_eq!(outcomes.len(), 5, "{fixture}: expected 5 pqc outcomes");
            for o in &outcomes {
                assert_eq!(o.source, RuleSource::Pqc);
                assert_eq!(
                    o.applicability,
                    Applicability::Applies,
                    "{fixture}: {} must Apply on a PQC leaf",
                    o.lint_id
                );
            }
            // Sanity: exactly the five known ids, no more, no less.
            let mut ids: Vec<&str> = outcomes.iter().map(|o| o.lint_id).collect();
            ids.sort_unstable();
            let mut expected: Vec<&str> = PQC_LINT_IDS.to_vec();
            expected.sort_unstable();
            assert_eq!(ids, expected, "{fixture}: unexpected pqc lint set");
        }
    }

    /// Every `pqc` lint reports `NotApplicable` on the classical RSA `good.pem`
    /// (the self-gate keeps the universal source off non-PQC keys).
    #[test]
    fn all_pqc_lints_not_applicable_on_rsa_leaf() {
        let outcomes = run_pqc("good.pem");
        assert_eq!(outcomes.len(), 5);
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
    }
}

mod no_cascade {
    use super::*;

    /// No-cascade direction 1 (PQC lints do not touch classical keys): a raw
    /// `default_registry().run()` over the RSA `good.pem` yields five `pqc`
    /// outcomes, ALL `NotApplicable` with empty findings. This proves the
    /// universal `Pqc` source does not cascade onto an RSA/EC certificate.
    #[test]
    fn raw_run_on_rsa_good_has_all_pqc_outcomes_not_applicable() {
        // Setup + Invoke: the FULL shipped registry on a classical cert.
        let cert = load_fixture("good.pem");
        let outcomes = default_registry().run(&cert);

        // Find: just the pqc-sourced outcomes.
        let pqc: Vec<&linter::LintOutcome> = outcomes
            .iter()
            .filter(|o| o.source == RuleSource::Pqc)
            .collect();

        // Expect: all five present, all NotApplicable, all empty.
        assert_eq!(pqc.len(), 5, "expected the 5 pqc outcomes in the full run");
        for o in &pqc {
            assert_eq!(
                o.applicability,
                Applicability::NotApplicable,
                "{} must not cascade onto the RSA good.pem",
                o.lint_id
            );
            assert!(o.findings.is_empty());
        }
        // And the five ids are exactly the shipped set.
        let mut ids: Vec<&str> = pqc.iter().map(|o| o.lint_id).collect();
        ids.sort_unstable();
        let mut expected = PQC_LINT_IDS.to_vec();
        expected.sort_unstable();
        assert_eq!(ids, expected);
    }

    /// No-cascade direction 2 (RSA/EC hygiene lints do not touch PQC keys): on the
    /// PQC ML-DSA leaf, the key-strength hygiene lints `hygiene_rsa_key_min_2048`
    /// and `hygiene_ecdsa_curve_allowlist` are `NotApplicable` (a PQC key is
    /// neither RSA nor EC), so a PQC key never trips the classical hygiene checks.
    #[test]
    fn raw_run_on_pqc_leaf_leaves_rsa_ec_hygiene_not_applicable() {
        // Setup + Invoke.
        let cert = load_fixture("pqc_mldsa_good.pem");
        let outcomes = default_registry().run(&cert);

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
                "{id} must be NotApplicable on a PQC key"
            );
        }
    }

    /// PQC-set isolation guard on the clean ML-DSA leaf under the RAW full
    /// registry: across the WHOLE shipped registry, the only `pqc`-sourced
    /// findings are NONE — the clean leaf passes every pqc lint even when run
    /// alongside all other sources.
    ///
    /// NOTE: a raw `default_registry().run()` runs EVERY lint irrespective of
    /// purpose (purpose-based source filtering is the CLI's job via
    /// `run_filtered`). The ML-DSA leaf has no serverAuth EKU, so the broad
    /// `cabf_br_ext_key_usage_server_auth_present` lint DOES fire under the raw
    /// run — that is a `cabf_br` concern, not a `pqc` concern, and is why per-lint
    /// PQC isolation uses `run_filtered(&[RuleSource::Pqc])` (see the module-level
    /// "Isolation mechanism" note). Here we assert specifically that NO pqc
    /// finding surfaces.
    #[test]
    fn raw_run_on_mldsa_good_surfaces_no_pqc_finding() {
        // Setup + Invoke.
        let cert = load_fixture("pqc_mldsa_good.pem");
        let outcomes = default_registry().run(&cert);

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
