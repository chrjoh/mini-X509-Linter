//! Integration tests for the eight codeSigning-EKU-gated CA/Browser Forum
//! Code-Signing Baseline Requirements lints (`cabf_cs_*`), exercised against the
//! real committed `testdata/cabf_cs_*.pem` fixtures through the public `Cert`
//! facade and the `Registry`.
//!
//! # Scoping (NARROW, codeSigning-EKU-gated — load-bearing)
//!
//! Every `cabf_cs` lint's `applies()` returns `NotApplicable` unless the cert
//! asserts the `codeSigning` EKU (OID 1.3.6.1.5.5.7.3.3). This is the explicit
//! anti-cascade design (see the feature-09 plan's "Critical Design Decision"):
//! the CS lints are `NotApplicable` on every existing TLS/generic/hygiene
//! fixture, so NO existing fixture was regenerated for this feature.
//!
//! # Isolation mechanism (why `run_filtered([CabfCs])`, not the raw registry)
//!
//! The CS fixtures carry `codeSigning` but deliberately NOT `serverAuth`. Under a
//! RAW `default_registry().run()` (no purpose filter) the BROAD-scoped
//! `cabf_br_ext_key_usage_server_auth_present` lint examines every non-CA leaf
//! and therefore co-fires on the CS leaves. That co-fire is exactly the false
//! positive `--purpose code-signing` exists to suppress — it is NOT a fixture
//! defect. To assert CS rule isolation cleanly we run ONLY the CS source via
//! `registry.run_filtered(&cert, &[RuleSource::CabfCs])`; that is the robust
//! mechanism used by the per-lint tests below. The no-cascade property (CS lints
//! quiet on a non-codeSigning cert) is proved separately against the RAW
//! registry on the non-codeSigning `good.pem`.
//!
//! The `cabf_cs_ecdsa_bad_curve.pem` fixture (explicit EC params) also trips
//! `hygiene_ecdsa_curve_allowlist` under the raw registry (both lints fail-closed
//! on a `None` named curve); the CS source filter isolates the CS finding.
//!
//! # ⚠️ Time-fragility
//!
//! `cabf_cs_good.pem` (and the other non-validity CS fixtures) use a
//! currently-valid `<=460d` window `2026-06-01 -> 2027-06-01` (365d). The two
//! validity-violating fixtures straddle "now" (`cabf_cs_validity_40_months.pem`
//! 2024-06-01 -> 2027-10-01; `cabf_cs_validity_500_days.pem`
//! 2026-02-01 -> 2027-06-16). They all EXPIRE in 2027; after that
//! `hygiene_not_expired` fires on the CS fixtures and these isolation tests fail
//! wholesale. Regenerate `testdata/` annually (see `testdata/generate.sh`). If a
//! flood of `not_expired`-shaped failures appears, the window has lapsed.
//!
//! Conventions (`.claude/rules/rust-testing-core.md`): SIFER, nested module per
//! lint, `.unwrap()`-style result assertions.

use linter::lints::cabf_cs::EkuRequired;
use linter::{
    Applicability, Cert, Lint, RuleSource, Severity, default_registry, default_registry_with_now,
};

/// A reference "now" inside every currently-valid fixture window (2026-12-01 in
/// Unix seconds), used to pin the clock for full-registry runs that include the
/// hygiene source so `hygiene_not_expired` cannot trip once the real date passes
/// the fixtures' `notAfter`.
const TEST_NOW: i64 = 1_796_083_200;

// `include_bytes!` resolves relative to this source file
// (crates/linter/tests/cabf_cs.rs); `../../../testdata` reaches the
// workspace-root `testdata/` directory.
const CS_GOOD_PEM: &[u8] = include_bytes!("../../../testdata/cabf_cs_good.pem");
const CS_MISSING_KU_PEM: &[u8] = include_bytes!("../../../testdata/cabf_cs_missing_key_usage.pem");
const CS_RSA_2048_PEM: &[u8] = include_bytes!("../../../testdata/cabf_cs_rsa_2048.pem");
const CS_ECDSA_BAD_CURVE_PEM: &[u8] =
    include_bytes!("../../../testdata/cabf_cs_ecdsa_bad_curve.pem");
const CS_VALIDITY_40M_PEM: &[u8] =
    include_bytes!("../../../testdata/cabf_cs_validity_40_months.pem");
const CS_VALIDITY_500D_PEM: &[u8] =
    include_bytes!("../../../testdata/cabf_cs_validity_500_days.pem");
const CS_NO_AIA_PEM: &[u8] = include_bytes!("../../../testdata/cabf_cs_no_aia.pem");
const CS_NO_CRL_PEM: &[u8] = include_bytes!("../../../testdata/cabf_cs_no_crl.pem");

// A non-codeSigning leaf (serverAuth EKU only) — used for the no-cascade and the
// direct-invocation fail-closed tests.
const GOOD_PEM: &[u8] = include_bytes!("../../../testdata/good.pem");

/// The eight `cabf_cs` lint ids, in registry order.
const CS_LINT_IDS: [&str; 8] = [
    "cabf_cs_eku_required",
    "cabf_cs_key_usage_required",
    "cabf_cs_rsa_key_size",
    "cabf_cs_ecdsa_curve_params",
    "cabf_cs_validity_period_longer_than_39_months",
    "cabf_cs_validity_period_longer_than_460_days",
    "cabf_cs_authority_information_access",
    "cabf_cs_crl_distribution_points",
];

/// Loads the single leaf certificate from a PEM fixture; `unwrap` surfaces the
/// `CertError` if the fixture is malformed.
fn load_leaf(pem: &[u8]) -> Cert {
    let mut certs = Cert::load(pem).unwrap();
    certs.remove(0)
}

/// Runs ONLY the `cabf_cs` source over the fixture (the robust isolation
/// mechanism — see the module doc). Returns the 8 CS outcomes.
fn run_cs_only(cert: &Cert) -> Vec<linter::LintOutcome> {
    default_registry().run_filtered(cert, &[RuleSource::CabfCs])
}

/// Collects all findings for a specific lint id from a set of outcomes.
fn findings_for<'a>(
    outcomes: &'a [linter::LintOutcome],
    lint_id: &str,
) -> Vec<&'a linter::Finding> {
    outcomes
        .iter()
        .filter(|o| o.lint_id == lint_id)
        .flat_map(|o| o.findings.iter())
        .collect()
}

/// Asserts that, under the CS-only filter, EXACTLY the given lint id produced
/// findings and every other CS lint was silent. Returns that lint's findings.
fn assert_only_cs_lint_fires<'a>(
    outcomes: &'a [linter::LintOutcome],
    target: &str,
) -> Vec<&'a linter::Finding> {
    for id in CS_LINT_IDS {
        let fs = findings_for(outcomes, id);
        if id == target {
            assert!(
                !fs.is_empty(),
                "expected {target} to fire under the cabf_cs filter, but it was silent"
            );
        } else {
            assert!(
                fs.is_empty(),
                "expected ONLY {target} to fire, but {id} also produced {fs:?}"
            );
        }
    }
    findings_for(outcomes, target)
}

mod good_passes_the_whole_cs_set {
    use super::*;

    #[test]
    fn clean_cs_leaf_produces_no_cs_findings() {
        // Setup: the clean code-signing leaf.
        let cert = load_leaf(CS_GOOD_PEM);

        // Invoke: run only the CS source.
        let outcomes = run_cs_only(&cert);

        // Find + Expect: all 8 CS lints applied, none produced any finding.
        assert_eq!(
            outcomes.len(),
            8,
            "the cabf_cs filter must run all 8 CS lints"
        );
        for o in &outcomes {
            assert_eq!(o.source, RuleSource::CabfCs);
            assert_eq!(
                o.applicability,
                Applicability::Applies,
                "{} should apply to a codeSigning leaf",
                o.lint_id
            );
            assert!(
                o.findings.is_empty(),
                "{} produced unexpected findings on cabf_cs_good.pem: {:?}",
                o.lint_id,
                o.findings
            );
        }
    }

    #[test]
    fn clean_cs_leaf_passes_under_code_signing_purpose() {
        // The CLI's default `auto` purpose resolves a codeSigning leaf to the
        // code-signing purpose, whose sources are [Rfc5280, Hygiene, CabfCs] —
        // CabfBr is NOT run, so the broad serverAuth-present false positive never
        // surfaces. Running exactly those sources over the clean CS leaf must
        // produce zero Error/Warn findings (it is RFC-5280-/hygiene-clean too).
        let cert = load_leaf(CS_GOOD_PEM);

        let outcomes = default_registry().run_filtered(
            &cert,
            &[RuleSource::Rfc5280, RuleSource::Hygiene, RuleSource::CabfCs],
        );

        let offenders: Vec<_> = outcomes.iter().filter(|o| !o.findings.is_empty()).collect();
        assert!(
            offenders.is_empty(),
            "cabf_cs_good.pem should be clean under the code-signing purpose; offenders: {offenders:?}"
        );
    }
}

mod key_usage_required {
    use super::*;

    #[test]
    fn flags_a_codesigning_leaf_without_digital_signature() {
        // Setup: codeSigning leaf whose KU asserts only keyEncipherment.
        let cert = load_leaf(CS_MISSING_KU_PEM);

        // Invoke + isolate.
        let outcomes = run_cs_only(&cert);
        let findings = assert_only_cs_lint_fires(&outcomes, "cabf_cs_key_usage_required");

        // Expect: a single Error naming the digitalSignature requirement.
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0].message.contains("digitalSignature"),
            "message should name the missing KU bit: {:?}",
            findings[0].message
        );
    }
}

mod rsa_key_size {
    use super::*;

    #[test]
    fn flags_a_2048_bit_codesigning_key_and_names_the_size() {
        // Setup: codeSigning leaf with an RSA-2048 key (< CS's 3072 floor).
        let cert = load_leaf(CS_RSA_2048_PEM);

        let outcomes = run_cs_only(&cert);
        let findings = assert_only_cs_lint_fires(&outcomes, "cabf_cs_rsa_key_size");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0].message.contains("2048"),
            "message should name the observed bit size: {:?}",
            findings[0].message
        );
        assert!(
            findings[0].message.contains("3072"),
            "message should name the 3072-bit floor: {:?}",
            findings[0].message
        );
    }
}

mod ecdsa_curve_params {
    use super::*;

    #[test]
    fn flags_explicit_ec_parameters() {
        // Setup: codeSigning leaf with a P-256 key encoded with EXPLICIT (non-
        // named) parameters, so ec_named_curve() is None -> fail-closed Error.
        let cert = load_leaf(CS_ECDSA_BAD_CURVE_PEM);

        let outcomes = run_cs_only(&cert);
        let findings = assert_only_cs_lint_fires(&outcomes, "cabf_cs_ecdsa_curve_params");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        // The fixture uses explicit params; the lint reports the "explicit/
        // unrecognised curve parameters" message.
        assert!(
            findings[0].message.contains("explicit") || findings[0].message.contains("named curve"),
            "message should describe the curve-parameter problem: {:?}",
            findings[0].message
        );
    }
}

mod validity_period {
    use super::*;

    #[test]
    fn forty_month_window_fires_the_39_month_error_and_the_460_day_warn_co_fires() {
        // Setup: a ~40-month (1217-day) currently-valid window. A >39-month
        // window is necessarily >460 days, so BOTH validity lints fire by
        // construction. This is the documented co-fire exception to
        // "exactly one CS rule per fixture".
        let cert = load_leaf(CS_VALIDITY_40M_PEM);

        let outcomes = run_cs_only(&cert);

        // The 39-month Error fires and names the duration.
        let err = findings_for(&outcomes, "cabf_cs_validity_period_longer_than_39_months");
        assert_eq!(err.len(), 1);
        assert_eq!(err[0].severity, Severity::Error);
        assert!(
            err[0].message.contains("1217"),
            "39-month message should name the observed days: {:?}",
            err[0].message
        );

        // The 460-day Warn co-fires (documented; expected).
        let warn = findings_for(&outcomes, "cabf_cs_validity_period_longer_than_460_days");
        assert_eq!(warn.len(), 1);
        assert_eq!(warn[0].severity, Severity::Warn);
        assert!(
            warn[0].message.contains("1217"),
            "460-day message should name the observed days: {:?}",
            warn[0].message
        );

        // No OTHER CS lint fires.
        for id in CS_LINT_IDS {
            if id == "cabf_cs_validity_period_longer_than_39_months"
                || id == "cabf_cs_validity_period_longer_than_460_days"
            {
                continue;
            }
            assert!(
                findings_for(&outcomes, id).is_empty(),
                "{id} should be silent on the 40-month fixture"
            );
        }
    }

    #[test]
    fn five_hundred_day_window_fires_only_the_460_day_warn() {
        // Setup: a 500-day window (> 460, <= 39 months) — isolates the 460-day
        // Warn ALONE; the 39-month Error must NOT fire.
        let cert = load_leaf(CS_VALIDITY_500D_PEM);

        let outcomes = run_cs_only(&cert);
        let findings =
            assert_only_cs_lint_fires(&outcomes, "cabf_cs_validity_period_longer_than_460_days");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(
            findings[0].message.contains("500"),
            "message should name the 500-day window: {:?}",
            findings[0].message
        );
    }
}

mod authority_information_access {
    use super::*;

    #[test]
    fn warns_when_aia_is_absent() {
        // Setup: codeSigning leaf with NO AIA extension (CRL-DP kept).
        let cert = load_leaf(CS_NO_AIA_PEM);

        let outcomes = run_cs_only(&cert);
        let findings = assert_only_cs_lint_fires(&outcomes, "cabf_cs_authority_information_access");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(
            findings[0].message.contains("Authority Information Access"),
            "message should name the missing extension: {:?}",
            findings[0].message
        );
    }
}

mod crl_distribution_points {
    use super::*;

    #[test]
    fn warns_when_crl_dp_is_absent() {
        // Setup: codeSigning leaf with NO CRL-DP extension (AIA kept).
        let cert = load_leaf(CS_NO_CRL_PEM);

        let outcomes = run_cs_only(&cert);
        let findings = assert_only_cs_lint_fires(&outcomes, "cabf_cs_crl_distribution_points");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(
            findings[0].message.contains("CRL Distribution Points"),
            "message should name the missing extension: {:?}",
            findings[0].message
        );
    }
}

mod eku_required_direct_invocation {
    use super::*;

    // cabf_cs_eku_required has NO through-the-registry violating fixture: a cert
    // without codeSigning is gated `NotApplicable`, so it can never reach this
    // lint's `check()` via `Registry::run`. We therefore exercise its fail-closed
    // Error path by calling `check()` DIRECTLY on a non-codeSigning leaf
    // (`good.pem`, which asserts serverAuth and NOT codeSigning).

    #[test]
    fn applies_is_not_applicable_on_a_non_codesigning_leaf() {
        // Setup: a serverAuth-only leaf.
        let cert = load_leaf(GOOD_PEM);
        let lint = EkuRequired::new();

        // Expect: the gate keeps the lint out of scope for this cert.
        assert_eq!(lint.applies(&cert), Applicability::NotApplicable);
    }

    #[test]
    fn direct_check_emits_the_fail_closed_error_on_a_non_codesigning_leaf() {
        // Setup: the same serverAuth-only leaf, but bypass the gate by calling
        // `check()` directly (mimicking a future caller outside the registry).
        let cert = load_leaf(GOOD_PEM);
        let lint = EkuRequired::new();

        // Invoke the lint's check directly.
        let findings = lint.check(&cert);

        // Expect: a single defensive Error naming the codeSigning EKU.
        assert_eq!(findings.len(), 1, "fail-closed path must emit one Error");
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0].message.contains("codeSigning"),
            "message should name the required EKU: {:?}",
            findings[0].message
        );
    }

    #[test]
    fn applies_and_passes_on_a_codesigning_leaf() {
        // Conversely, on a codeSigning leaf the lint applies and stays silent.
        let cert = load_leaf(CS_GOOD_PEM);
        let lint = EkuRequired::new();

        assert_eq!(lint.applies(&cert), Applicability::Applies);
        assert!(
            lint.check(&cert).is_empty(),
            "codeSigning leaf must pass eku_required"
        );
    }
}

mod scoping_and_no_cascade {
    use super::*;

    #[test]
    fn all_eight_cs_lints_apply_to_a_codesigning_leaf() {
        // Setup + Invoke: CS-only filter over the codeSigning leaf.
        let cert = load_leaf(CS_GOOD_PEM);
        let outcomes = run_cs_only(&cert);

        // Expect: 8 outcomes, all CabfCs, all Applies, the 8 known ids.
        assert_eq!(outcomes.len(), 8);
        let ids: Vec<&str> = outcomes.iter().map(|o| o.lint_id).collect();
        for id in CS_LINT_IDS {
            assert!(ids.contains(&id), "missing CS lint {id} under the filter");
        }
        assert!(outcomes.iter().all(|o| o.source == RuleSource::CabfCs));
        assert!(
            outcomes
                .iter()
                .all(|o| o.applicability == Applicability::Applies)
        );
    }

    #[test]
    fn no_cascade_all_eight_cs_lints_not_applicable_on_a_non_codesigning_cert() {
        // The load-bearing no-cascade proof: run the RAW full registry over a
        // non-codeSigning cert (good.pem, serverAuth-only). Every cabf_cs
        // outcome must be NotApplicable with empty findings — confirming the CS
        // set never engages on existing TLS/generic fixtures.
        let cert = load_leaf(GOOD_PEM);

        let outcomes = default_registry_with_now(Some(TEST_NOW)).run(&cert);

        let cs_outcomes: Vec<_> = outcomes
            .iter()
            .filter(|o| o.source == RuleSource::CabfCs)
            .collect();
        assert_eq!(
            cs_outcomes.len(),
            8,
            "the full registry must emit all 8 CS outcomes (as NotApplicable)"
        );
        for o in cs_outcomes {
            assert_eq!(
                o.applicability,
                Applicability::NotApplicable,
                "{} must be NotApplicable on a non-codeSigning cert",
                o.lint_id
            );
            assert!(
                o.findings.is_empty(),
                "{} must produce no findings when NotApplicable",
                o.lint_id
            );
        }
    }
}
