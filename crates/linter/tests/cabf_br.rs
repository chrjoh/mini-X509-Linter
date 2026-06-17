//! Integration tests for the four broad-scoped CA/Browser Forum Baseline
//! Requirements lints (`cabf_br_validity_max_398_days`, `cabf_br_cn_in_san`,
//! `cabf_br_no_internal_names_or_reserved_ip`,
//! `cabf_br_ext_key_usage_server_auth_present`), exercised against the real
//! committed `testdata/` fixtures through the public `Cert` facade.
//!
//! # Scoping (BROAD — load-bearing)
//!
//! Every BR lint applies to EVERY non-CA leaf and is `NotApplicable` for CA
//! certs; they are NOT EKU-gated. Each fixture below is a leaf that is
//! BR-compliant EXCEPT its single intended violation, so running it over the
//! FULL `default_registry()` (14 lints) surfaces exactly one rule.
//!
//! # Fixture naming
//!
//! The reserved-name classifier treats `.example`, `.test`, `.local`,
//! `.internal`, and single-label names as internal/reserved, so the
//! BR-compliant SANs use genuinely public `*.example.com` names (TLD `com`,
//! which is not a reserved suffix). `cabf_br_internal_san.pem` deliberately adds
//! `internal.local` + `10.0.0.1` to trip the internal/reserved lint.
//!
//! # ⚠️ Time-fragility
//!
//! BR-compliant leaves use a currently-valid `<=398d` window
//! (`2026-06-01 -> 2027-06-01`); `cabf_br_validity_400_days.pem` uses
//! `2026-06-01 -> 2027-07-06`. They EXPIRE in 2027; after that
//! `hygiene_not_expired` fires on every leaf and these isolation tests fail
//! wholesale. Regenerate `testdata/` annually (see `testdata/generate.sh`).
//!
//! Conventions (`.claude/rules/rust-testing-core.md`): SIFER, nested module per
//! lint, `.unwrap()`-style result assertions.

use linter::lints::cabf_br::{
    CnInSan, ExtKeyUsageServerAuthPresent, NoInternalNamesOrReservedIp, ValidityMax398Days,
};
use linter::{Applicability, Cert, Lint, Severity, default_registry};

// `include_bytes!` resolves relative to this source file
// (crates/linter/tests/cabf_br.rs); `../../../testdata` reaches the
// workspace-root `testdata/` directory.
const GOOD_PEM: &[u8] = include_bytes!("../../../testdata/good.pem");
const VALIDITY_400_PEM: &[u8] = include_bytes!("../../../testdata/cabf_br_validity_400_days.pem");
const CN_NOT_IN_SAN_PEM: &[u8] = include_bytes!("../../../testdata/cabf_br_cn_not_in_san.pem");
const INTERNAL_SAN_PEM: &[u8] = include_bytes!("../../../testdata/cabf_br_internal_san.pem");
const MISSING_SERVERAUTH_PEM: &[u8] =
    include_bytes!("../../../testdata/cabf_br_missing_serverauth.pem");
const EMPTY_SUBJECT_NO_SAN_PEM: &[u8] =
    include_bytes!("../../../testdata/rfc5280_empty_subject_no_san.pem");
const CA_BC_NOT_CRITICAL_PEM: &[u8] =
    include_bytes!("../../../testdata/rfc5280_ca_bc_not_critical.pem");

/// Loads the single leaf certificate from a PEM fixture; `unwrap` surfaces the
/// `CertError` if the fixture is malformed.
fn load_leaf(pem: &[u8]) -> Cert {
    let mut certs = Cert::load(pem).unwrap();
    certs.remove(0)
}

/// Asserts `findings` contains at least one `Error` whose message contains
/// `needle`.
fn assert_error_mentions(findings: &[linter::Finding], needle: &str) {
    assert!(
        findings.iter().any(|f| f.severity == Severity::Error),
        "expected at least one Error finding, got {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.severity == Severity::Error && f.message.contains(needle)),
        "no Error finding mentioned {needle:?}; findings were {findings:?}"
    );
}

mod validity_max_398_days {
    use super::*;

    #[test]
    fn flags_400_day_leaf_and_names_the_duration() {
        // Setup: a currently-valid leaf with a 400-day window (> 398).
        let cert = load_leaf(VALIDITY_400_PEM);
        let lint = ValidityMax398Days::new();

        // Precondition: in scope (a non-CA leaf).
        assert_eq!(lint.applies(&cert), Applicability::Applies);

        // Invoke.
        let findings = lint.check(&cert);

        // Find + Expect: one Error naming the actual duration and the 398 limit.
        assert_error_mentions(&findings, "400");
        assert_error_mentions(&findings, "398");
    }

    #[test]
    fn passes_for_good_365_day_leaf_at_the_boundary() {
        // good.pem is 365 days (well within 398) — the rule must stay silent.
        let cert = load_leaf(GOOD_PEM);

        let findings = ValidityMax398Days::new().check(&cert);

        assert!(findings.is_empty(), "good.pem must pass; got {findings:?}");
    }

    #[test]
    fn not_applicable_on_ca_certificate() {
        let cert = load_leaf(CA_BC_NOT_CRITICAL_PEM);

        assert_eq!(
            ValidityMax398Days::new().applies(&cert),
            Applicability::NotApplicable
        );
    }
}

mod cn_in_san {
    use super::*;

    #[test]
    fn flags_cn_absent_from_san_and_names_it() {
        // Setup: CN=cn-missing.example.com but SAN lists only other.example.com.
        let cert = load_leaf(CN_NOT_IN_SAN_PEM);
        let lint = CnInSan::new();

        assert_eq!(lint.applies(&cert), Applicability::Applies);

        // Invoke.
        let findings = lint.check(&cert);

        // Find + Expect: one Error naming the offending CN.
        assert_error_mentions(&findings, "cn-missing.example.com");
    }

    #[test]
    fn passes_when_cn_present_in_san() {
        // good.pem: CN == the sole SAN dNSName, so the rule stays silent.
        let cert = load_leaf(GOOD_PEM);

        let findings = CnInSan::new().check(&cert);

        assert!(findings.is_empty(), "good.pem must pass; got {findings:?}");
    }

    #[test]
    fn silent_when_subject_has_no_common_name() {
        // The empty-subject fixture has no CN, so there is nothing to require:
        // the rule emits no finding (it applies, but yields nothing).
        let cert = load_leaf(EMPTY_SUBJECT_NO_SAN_PEM);
        let lint = CnInSan::new();

        assert_eq!(lint.applies(&cert), Applicability::Applies);

        let findings = lint.check(&cert);

        assert!(
            findings.is_empty(),
            "a subject with no CN must not trip cn_in_san; got {findings:?}"
        );
    }

    #[test]
    fn not_applicable_on_ca_certificate() {
        let cert = load_leaf(CA_BC_NOT_CRITICAL_PEM);

        assert_eq!(CnInSan::new().applies(&cert), Applicability::NotApplicable);
    }
}

mod no_internal_names_or_reserved_ip {
    use super::*;

    #[test]
    fn flags_internal_name_and_reserved_ip_with_multiple_findings() {
        // Setup: a leaf whose SAN carries a public name (= CN, so cn_in_san is
        // quiet) PLUS internal.local AND 10.0.0.1 — two offending entries.
        let cert = load_leaf(INTERNAL_SAN_PEM);
        let lint = NoInternalNamesOrReservedIp::new();

        assert_eq!(lint.applies(&cert), Applicability::Applies);

        // Invoke.
        let findings = lint.check(&cert);

        // Find + Expect: one finding per offending entry (two), naming each.
        assert_eq!(
            findings.len(),
            2,
            "expected one finding per offending SAN entry; got {findings:?}"
        );
        assert!(findings.iter().all(|f| f.severity == Severity::Error));
        assert_error_mentions(&findings, "internal.local");
        assert_error_mentions(&findings, "10.0.0.1");
    }

    #[test]
    fn passes_for_good_public_san() {
        // good.pem has only a public dNSName, so the rule stays silent.
        let cert = load_leaf(GOOD_PEM);

        let findings = NoInternalNamesOrReservedIp::new().check(&cert);

        assert!(findings.is_empty(), "good.pem must pass; got {findings:?}");
    }

    #[test]
    fn not_applicable_on_ca_certificate() {
        let cert = load_leaf(CA_BC_NOT_CRITICAL_PEM);

        assert_eq!(
            NoInternalNamesOrReservedIp::new().applies(&cert),
            Applicability::NotApplicable
        );
    }
}

mod ext_key_usage_server_auth_present {
    use super::*;

    #[test]
    fn flags_leaf_without_server_auth() {
        // Setup: a leaf whose EKU carries clientAuth only (no serverAuth).
        let cert = load_leaf(MISSING_SERVERAUTH_PEM);
        let lint = ExtKeyUsageServerAuthPresent::new();

        assert_eq!(lint.applies(&cert), Applicability::Applies);

        // Invoke.
        let findings = lint.check(&cert);

        // Find + Expect: one Error naming the missing serverAuth EKU.
        assert_error_mentions(&findings, "serverAuth");
    }

    #[test]
    fn passes_for_good_leaf_with_server_auth() {
        // good.pem asserts serverAuth, so the rule stays silent.
        let cert = load_leaf(GOOD_PEM);

        let findings = ExtKeyUsageServerAuthPresent::new().check(&cert);

        assert!(findings.is_empty(), "good.pem must pass; got {findings:?}");
    }

    #[test]
    fn not_applicable_on_ca_certificate() {
        let cert = load_leaf(CA_BC_NOT_CRITICAL_PEM);

        assert_eq!(
            ExtKeyUsageServerAuthPresent::new().applies(&cert),
            Applicability::NotApplicable
        );
    }
}

mod ca_scoping {
    use super::*;

    /// All four BR lints must report `NotApplicable` for a CA certificate —
    /// the load-bearing broad-scoping invariant (CA => out of BR scope).
    #[test]
    fn all_four_br_lints_not_applicable_on_ca() {
        let cert = load_leaf(CA_BC_NOT_CRITICAL_PEM);

        assert_eq!(
            ValidityMax398Days::new().applies(&cert),
            Applicability::NotApplicable
        );
        assert_eq!(CnInSan::new().applies(&cert), Applicability::NotApplicable);
        assert_eq!(
            NoInternalNamesOrReservedIp::new().applies(&cert),
            Applicability::NotApplicable
        );
        assert_eq!(
            ExtKeyUsageServerAuthPresent::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    /// The dual of the CA invariant: all four BR lints must report `Applies`
    /// for a single non-CA leaf — confirming broad scoping is uniform and NOT
    /// EKU-gated (the leaf is in scope for all four regardless of its EKU).
    #[test]
    fn all_four_br_lints_apply_on_a_non_ca_leaf() {
        let cert = load_leaf(GOOD_PEM);

        assert_eq!(
            ValidityMax398Days::new().applies(&cert),
            Applicability::Applies
        );
        assert_eq!(CnInSan::new().applies(&cert), Applicability::Applies);
        assert_eq!(
            NoInternalNamesOrReservedIp::new().applies(&cert),
            Applicability::Applies
        );
        assert_eq!(
            ExtKeyUsageServerAuthPresent::new().applies(&cert),
            Applicability::Applies
        );
    }
}

mod default_registry_isolation {
    use super::*;

    /// Each BR fixture, run over the FULL 14-lint registry, surfaces its single
    /// intended `Error`/`Fatal` violation and no other — proving the fixture
    /// isolates exactly one rule end-to-end across rfc5280 + hygiene + cabf_br.
    #[test]
    fn each_br_fixture_isolates_exactly_one_violation() {
        // (fixture bytes, the lint_id expected to fire).
        let cases: &[(&[u8], &str)] = &[
            (VALIDITY_400_PEM, "cabf_br_validity_max_398_days"),
            (CN_NOT_IN_SAN_PEM, "cabf_br_cn_in_san"),
            (INTERNAL_SAN_PEM, "cabf_br_no_internal_names_or_reserved_ip"),
            (
                MISSING_SERVERAUTH_PEM,
                "cabf_br_ext_key_usage_server_auth_present",
            ),
        ];

        let registry = default_registry();

        for (pem, expected_lint) in cases {
            let cert = load_leaf(pem);
            let outcomes = registry.run(&cert);

            // The lint_ids of every outcome carrying an Error/Fatal finding.
            let firing: Vec<&str> = outcomes
                .iter()
                .filter(|o| o.findings.iter().any(|f| f.severity >= Severity::Error))
                .map(|o| o.lint_id)
                .collect();

            assert_eq!(
                firing,
                vec![*expected_lint],
                "fixture for {expected_lint} must violate exactly that rule; \
                 firing lints were {firing:?}"
            );
        }
    }

    /// The internal-SAN fixture is the multi-finding case: over the full
    /// registry it produces exactly two findings, both from the
    /// internal/reserved lint (one per offending SAN entry) and nothing else.
    #[test]
    fn internal_san_fixture_yields_two_findings_from_one_lint() {
        let registry = default_registry();
        let cert = load_leaf(INTERNAL_SAN_PEM);

        let outcomes = registry.run(&cert);

        let all: Vec<(&str, &linter::Finding)> = outcomes
            .iter()
            .flat_map(|o| o.findings.iter().map(move |f| (o.lint_id, f)))
            .collect();

        assert_eq!(
            all.len(),
            2,
            "internal SAN fixture must surface exactly two findings; got {all:?}"
        );
        assert!(
            all.iter()
                .all(|(id, _)| *id == "cabf_br_no_internal_names_or_reserved_ip"),
            "all findings must come from the internal/reserved lint; got {all:?}"
        );
    }

    /// Regression guard: the clean leaf `good.pem` passes the entire 14-lint
    /// registry (including all four BR lints) with no `Error`/`Fatal` finding.
    #[test]
    fn good_pem_yields_no_error_or_fatal_findings() {
        let registry = default_registry();
        let cert = load_leaf(GOOD_PEM);

        let outcomes = registry.run(&cert);

        let offending: Vec<_> = outcomes
            .iter()
            .flat_map(|o| o.findings.iter().map(move |f| (o.lint_id, f)))
            .filter(|(_, f)| f.severity >= Severity::Error)
            .collect();
        assert!(
            offending.is_empty(),
            "good.pem should pass every lint, but found: {offending:?}"
        );
    }
}
