//! Integration tests for the six RFC 5280 structural lints.
//!
//! Each lint owns a dedicated fixture under `testdata/` that violates EXACTLY
//! that rule and passes every other RFC 5280 lint (and `not_expired`, via a
//! far-future `notAfter`). These tests load the real committed fixtures through
//! the public `Cert` facade, construct each lint directly, and assert:
//!
//! - the violating fixture yields at least one `Error` finding with a message
//!   substring tying it to the rule;
//! - `good.pem` (a clean leaf) produces no findings, or `NotApplicable` for the
//!   lints scoped out of a non-CA / non-empty-subject leaf;
//! - the CA-only lints report `NotApplicable` on the leaf, and
//!   `san_present_if_subject_empty` reports `NotApplicable` when the subject is
//!   populated;
//! - the full `default_registry()` over `good.pem` yields no `Error`/`Fatal`
//!   findings.
//!
//! Conventions (`.claude/rules/rust-testing-core.md`): SIFER, nested module per
//! lint, `.unwrap()`/`.unwrap_err()`-style result assertions.

use linter::lints::rfc5280::{
    BasicConstraintsCriticalOnCa, KeyUsagePresentWhenCa, SanPresentIfSubjectEmpty,
    SerialNumberPositive, ValidityNotAfterAfterNotBefore, VersionIsV3,
};
use linter::{Applicability, Cert, Lint, Severity, default_registry};

// `include_bytes!` resolves relative to this source file
// (crates/linter/tests/rfc5280.rs); `../../../testdata` reaches the
// workspace-root `testdata/` directory.
const GOOD_PEM: &[u8] = include_bytes!("../../../testdata/good.pem");
const VERSION_NOT_V3_PEM: &[u8] = include_bytes!("../../../testdata/rfc5280_version_not_v3.pem");
const SERIAL_ZERO_PEM: &[u8] = include_bytes!("../../../testdata/rfc5280_serial_number_zero.pem");
const VALIDITY_INVERTED_PEM: &[u8] =
    include_bytes!("../../../testdata/rfc5280_validity_inverted.pem");
const CA_BC_NOT_CRITICAL_PEM: &[u8] =
    include_bytes!("../../../testdata/rfc5280_ca_bc_not_critical.pem");
const CA_MISSING_KEYCERTSIGN_PEM: &[u8] =
    include_bytes!("../../../testdata/rfc5280_ca_missing_keycertsign.pem");
const EMPTY_SUBJECT_NO_SAN_PEM: &[u8] =
    include_bytes!("../../../testdata/rfc5280_empty_subject_no_san.pem");

/// Loads the single leaf certificate from a PEM fixture; `unwrap` surfaces the
/// `CertError` if the fixture is malformed.
fn load_leaf(pem: &[u8]) -> Cert {
    let mut certs = Cert::load(pem).unwrap();
    certs.remove(0)
}

/// Asserts that `findings` contains at least one `Error` whose message contains
/// `needle`, returning a readable panic otherwise.
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

mod version_is_v3 {
    use super::*;

    #[test]
    fn flags_v1_certificate_that_carries_extensions() {
        // Setup: a cert whose DER version byte was patched to v1 while keeping
        // its extensions TLV — exactly the case the rule forbids.
        let cert = load_leaf(VERSION_NOT_V3_PEM);
        let lint = VersionIsV3::new();

        // Invoke.
        let findings = lint.check(&cert);

        // Find + Expect: one Error tying the failure to the version/extension rule.
        assert_error_mentions(&findings, "extensions");
    }

    #[test]
    fn passes_for_good_leaf() {
        let cert = load_leaf(GOOD_PEM);

        let findings = VersionIsV3::new().check(&cert);

        assert!(findings.is_empty(), "good.pem must pass; got {findings:?}");
    }

    #[test]
    fn applies_to_any_certificate() {
        let cert = load_leaf(GOOD_PEM);

        assert_eq!(VersionIsV3::new().applies(&cert), Applicability::Applies);
    }
}

mod serial_number_positive {
    use super::*;

    #[test]
    fn flags_zero_serial() {
        // Setup: a leaf signed with serial 0.
        let cert = load_leaf(SERIAL_ZERO_PEM);
        let lint = SerialNumberPositive::new();

        // Invoke.
        let findings = lint.check(&cert);

        // Find + Expect.
        assert_error_mentions(&findings, "zero");
    }

    #[test]
    fn passes_for_good_leaf() {
        let cert = load_leaf(GOOD_PEM);

        let findings = SerialNumberPositive::new().check(&cert);

        assert!(findings.is_empty(), "good.pem must pass; got {findings:?}");
    }

    #[test]
    fn applies_to_any_certificate() {
        let cert = load_leaf(GOOD_PEM);

        assert_eq!(
            SerialNumberPositive::new().applies(&cert),
            Applicability::Applies
        );
    }
}

mod validity_window {
    use super::*;

    #[test]
    fn flags_non_positive_validity_window() {
        // Setup: a leaf whose notAfter == notBefore (an empty window), which the
        // rule forbids (it requires notAfter strictly later than notBefore).
        let cert = load_leaf(VALIDITY_INVERTED_PEM);
        let lint = ValidityNotAfterAfterNotBefore::new();

        // Invoke.
        let findings = lint.check(&cert);

        // Find + Expect.
        assert_error_mentions(&findings, "notAfter");
    }

    #[test]
    fn passes_for_good_leaf() {
        let cert = load_leaf(GOOD_PEM);

        let findings = ValidityNotAfterAfterNotBefore::new().check(&cert);

        assert!(findings.is_empty(), "good.pem must pass; got {findings:?}");
    }
}

mod basic_constraints_critical_on_ca {
    use super::*;

    #[test]
    fn flags_ca_with_non_critical_basic_constraints() {
        // Setup: a CA whose BasicConstraints is NOT marked critical (but whose
        // keyUsage does carry keyCertSign, so only THIS rule is violated).
        let cert = load_leaf(CA_BC_NOT_CRITICAL_PEM);
        let lint = BasicConstraintsCriticalOnCa::new();

        // Precondition: the lint must consider this CA in scope.
        assert_eq!(lint.applies(&cert), Applicability::Applies);

        // Invoke.
        let findings = lint.check(&cert);

        // Find + Expect.
        assert_error_mentions(&findings, "critical");
    }

    #[test]
    fn not_applicable_on_leaf() {
        // A non-CA leaf is out of scope for this CA-only rule.
        let cert = load_leaf(GOOD_PEM);

        assert_eq!(
            BasicConstraintsCriticalOnCa::new().applies(&cert),
            Applicability::NotApplicable
        );
    }
}

mod key_usage_present_when_ca {
    use super::*;

    #[test]
    fn flags_ca_missing_key_cert_sign() {
        // Setup: a CA with critical BasicConstraints whose keyUsage lacks the
        // keyCertSign bit — only THIS rule is violated.
        let cert = load_leaf(CA_MISSING_KEYCERTSIGN_PEM);
        let lint = KeyUsagePresentWhenCa::new();

        // Precondition: in scope (it is a CA).
        assert_eq!(lint.applies(&cert), Applicability::Applies);

        // Invoke.
        let findings = lint.check(&cert);

        // Find + Expect.
        assert_error_mentions(&findings, "keyCertSign");
    }

    #[test]
    fn not_applicable_on_leaf() {
        // A non-CA leaf is out of scope for this CA-only rule.
        let cert = load_leaf(GOOD_PEM);

        assert_eq!(
            KeyUsagePresentWhenCa::new().applies(&cert),
            Applicability::NotApplicable
        );
    }
}

mod san_present_if_subject_empty {
    use super::*;

    #[test]
    fn flags_empty_subject_without_san() {
        // Setup: a non-CA leaf with an empty subject DN and no SAN — only THIS
        // rule is violated (CA lints are N/A on a non-CA cert).
        let cert = load_leaf(EMPTY_SUBJECT_NO_SAN_PEM);
        let lint = SanPresentIfSubjectEmpty::new();

        // Precondition: in scope (the subject is empty).
        assert_eq!(lint.applies(&cert), Applicability::Applies);

        // Invoke.
        let findings = lint.check(&cert);

        // Find + Expect.
        assert_error_mentions(&findings, "subjectAltName");
    }

    #[test]
    fn not_applicable_when_subject_present() {
        // good.pem has a non-empty subject, so the rule is out of scope.
        let cert = load_leaf(GOOD_PEM);

        assert_eq!(
            SanPresentIfSubjectEmpty::new().applies(&cert),
            Applicability::NotApplicable
        );
    }
}

mod default_registry_over_good {
    use super::*;

    /// The clean leaf `good.pem` must pass the entire shipped registry: no
    /// finding at `Error` or `Fatal` from any lint (the CA-only lints and the
    /// SAN lint are `NotApplicable`, the structural lints pass).
    #[test]
    fn good_pem_yields_no_error_or_fatal_findings() {
        // Setup.
        let registry = default_registry();
        let cert = load_leaf(GOOD_PEM);

        // Invoke.
        let outcomes = registry.run(&cert);

        // Find + Expect: scan every finding across every outcome.
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

    /// Each RFC 5280 fixture, run through the FULL registry, must surface its
    /// single intended violation and no other Error/Fatal finding — proving the
    /// fixture isolates exactly one rule end-to-end.
    #[test]
    fn each_fixture_isolates_exactly_one_rfc5280_violation() {
        // (fixture bytes, the lint_id expected to fire).
        let cases: &[(&[u8], &str)] = &[
            (VERSION_NOT_V3_PEM, "rfc5280_version_is_v3"),
            (SERIAL_ZERO_PEM, "rfc5280_serial_number_positive"),
            (
                VALIDITY_INVERTED_PEM,
                "rfc5280_validity_not_after_after_not_before",
            ),
            (
                CA_BC_NOT_CRITICAL_PEM,
                "rfc5280_basic_constraints_critical_on_ca",
            ),
            (
                CA_MISSING_KEYCERTSIGN_PEM,
                "rfc5280_key_usage_present_when_ca",
            ),
            (
                EMPTY_SUBJECT_NO_SAN_PEM,
                "rfc5280_san_present_if_subject_empty",
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
}
