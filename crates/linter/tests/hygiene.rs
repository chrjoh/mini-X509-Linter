//! Integration tests for the three crypto-hygiene lints introduced in feature 04
//! (`hygiene_no_sha1_signature`, `hygiene_rsa_key_min_2048`,
//! `hygiene_ecdsa_curve_allowlist`), exercised against the real committed
//! `testdata/` fixtures through the public `Cert` facade.
//!
//! Each new fixture is a CLEAN LEAF (CA:FALSE, non-empty subject, no SAN, v3,
//! small positive serial, far-future validity) that violates EXACTLY its one
//! hygiene rule and passes every other shipped lint. These tests assert, per
//! lint:
//!
//! - the violating fixture yields exactly one `Error` finding whose message
//!   names the offending algorithm / bit length / curve;
//! - the key-strength lints scope correctly (`rsa_key_min_2048` is
//!   `NotApplicable` on the EC fixture; `ecdsa_curve_allowlist` is
//!   `NotApplicable` on the RSA fixtures);
//! - run over the FULL `default_registry()`, each fixture surfaces its single
//!   intended `Error`/`Fatal` violation and no other — proving one-rule
//!   isolation end-to-end across rfc5280 + hygiene;
//! - `good.pem` (a clean RSA-2048 / SHA-256 leaf) stays free of any
//!   `Error`/`Fatal` finding across the whole registry (regression guard).
//!
//! Conventions (`.claude/rules/rust-testing-core.md`): SIFER, nested module per
//! lint, `.unwrap()`-style result assertions.
//!
//! # Note on feature 05 (CA/Browser Forum BR lints)
//!
//! The default registry now also contains the four broad-scoped `cabf_br_*`
//! lints, so `default_registry()` runs 14 lints. To keep the isolation tests
//! below valid under broad scoping, every non-CA leaf fixture (including these
//! hygiene fixtures) was regenerated BR-compliant-except-its-target: each gains a
//! `serverAuth` EKU, a SAN whose dNSName equals the subject CN (a public
//! `*.example.com` name), and a currently-valid `<=398d` window. That is why
//! these hygiene fixtures now carry SAN/EKU; the assertion logic is UNCHANGED.
//!
//! ⚠️ Time-fragility: those leaves EXPIRE on 2027-06-01; regenerate `testdata/`
//! annually (see `testdata/generate.sh`).

use linter::lints::hygiene::{EcdsaCurveAllowlist, NoSha1Signature, RsaKeyMin2048};
use linter::{Applicability, Cert, Lint, Severity, default_registry_with_now};

/// A reference "now" inside every currently-valid fixture window (2026-12-01 in
/// Unix seconds), used to pin the clock for full-registry runs that include the
/// hygiene source so `hygiene_not_expired` cannot trip once the real date passes
/// the fixtures' `notAfter` (these leaves expire 2027-06-01).
const TEST_NOW: i64 = 1_796_083_200;

// `include_bytes!` resolves relative to this source file
// (crates/linter/tests/hygiene.rs); `../../../testdata` reaches the
// workspace-root `testdata/` directory.
const GOOD_PEM: &[u8] = include_bytes!("../../../testdata/good.pem");
const SHA1_SIGNATURE_PEM: &[u8] = include_bytes!("../../../testdata/hygiene_sha1_signature.pem");
const RSA_1024_PEM: &[u8] = include_bytes!("../../../testdata/hygiene_rsa_1024.pem");
const ECDSA_BAD_CURVE_PEM: &[u8] = include_bytes!("../../../testdata/hygiene_ecdsa_bad_curve.pem");

/// Loads the single leaf certificate from a PEM fixture; `unwrap` surfaces the
/// `CertError` if the fixture is malformed.
fn load_leaf(pem: &[u8]) -> Cert {
    let mut certs = Cert::load(pem).unwrap();
    certs.remove(0)
}

/// Asserts that `findings` is exactly one `Error` whose message contains
/// `needle`, returning a readable panic otherwise.
fn assert_single_error_mentions(findings: &[linter::Finding], needle: &str) {
    assert_eq!(
        findings.len(),
        1,
        "expected exactly one finding, got {findings:?}"
    );
    assert_eq!(
        findings[0].severity,
        Severity::Error,
        "expected the finding to be an Error, got {:?}",
        findings[0]
    );
    assert!(
        findings[0].message.contains(needle),
        "finding message {:?} did not mention {needle:?}",
        findings[0].message
    );
}

mod no_sha1_signature {
    use super::*;

    #[test]
    fn flags_sha1_signed_certificate() {
        // Setup: an RSA-2048 leaf SIGNED WITH SHA-1 (sha1WithRSAEncryption).
        let cert = load_leaf(SHA1_SIGNATURE_PEM);
        let lint = NoSha1Signature::new();

        // Precondition: the rule applies to every certificate.
        assert_eq!(lint.applies(&cert), Applicability::Applies);

        // Invoke.
        let findings = lint.check(&cert);

        // Find + Expect: one Error naming the SHA-1 RSA algorithm.
        assert_single_error_mentions(&findings, "sha1WithRSAEncryption");
    }

    #[test]
    fn passes_for_good_sha256_leaf() {
        // good.pem is signed sha256WithRSAEncryption — the rule must stay silent.
        let cert = load_leaf(GOOD_PEM);

        let findings = NoSha1Signature::new().check(&cert);

        assert!(findings.is_empty(), "good.pem must pass; got {findings:?}");
    }
}

mod rsa_key_min_2048 {
    use super::*;

    #[test]
    fn flags_rsa_1024_key() {
        // Setup: a leaf carrying a 1024-bit RSA key (below the 2048-bit floor).
        let cert = load_leaf(RSA_1024_PEM);
        let lint = RsaKeyMin2048::new();

        // Precondition: in scope (the key is RSA).
        assert_eq!(lint.applies(&cert), Applicability::Applies);

        // Invoke.
        let findings = lint.check(&cert);

        // Find + Expect: one Error naming the offending bit length.
        assert_single_error_mentions(&findings, "1024");
    }

    #[test]
    fn passes_for_good_rsa_2048_leaf() {
        let cert = load_leaf(GOOD_PEM);

        let findings = RsaKeyMin2048::new().check(&cert);

        assert!(findings.is_empty(), "good.pem must pass; got {findings:?}");
    }

    #[test]
    fn not_applicable_on_ec_certificate() {
        // The EC fixture has no RSA key, so this RSA-only rule is out of scope.
        let cert = load_leaf(ECDSA_BAD_CURVE_PEM);

        assert_eq!(
            RsaKeyMin2048::new().applies(&cert),
            Applicability::NotApplicable
        );
    }
}

mod ecdsa_curve_allowlist {
    use super::*;

    #[test]
    fn flags_non_allowlisted_named_curve() {
        // Setup: an EC leaf on secp224r1 (P-224) — a named curve outside the
        // {P-256,P-384,P-521} allowlist, so the rule fires on the "not
        // allowlisted" path.
        let cert = load_leaf(ECDSA_BAD_CURVE_PEM);
        let lint = EcdsaCurveAllowlist::new();

        // Precondition: in scope (the key is EC).
        assert_eq!(lint.applies(&cert), Applicability::Applies);

        // Invoke.
        let findings = lint.check(&cert);

        // Find + Expect: one Error naming the offending curve (by OID or name).
        // secp224r1 / P-224 — OID 1.3.132.0.33.
        assert_single_error_mentions(&findings, "1.3.132.0.33");
    }

    #[test]
    fn not_applicable_on_rsa_good_leaf() {
        // good.pem carries an RSA key, so this EC-only rule is out of scope.
        let cert = load_leaf(GOOD_PEM);

        assert_eq!(
            EcdsaCurveAllowlist::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn not_applicable_on_rsa_1024_leaf() {
        // The RSA-1024 fixture is also non-EC — confirms scoping is by key
        // algorithm, independent of key strength.
        let cert = load_leaf(RSA_1024_PEM);

        assert_eq!(
            EcdsaCurveAllowlist::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn not_applicable_on_sha1_signed_rsa_leaf() {
        // The SHA-1 fixture is RSA-2048 — EC lint must be N/A here too.
        let cert = load_leaf(SHA1_SIGNATURE_PEM);

        assert_eq!(
            EcdsaCurveAllowlist::new().applies(&cert),
            Applicability::NotApplicable
        );
    }
}

mod default_registry_isolation {
    use super::*;

    /// Each new hygiene fixture, run through the FULL registry (rfc5280 +
    /// hygiene + not_expired), must surface its single intended violation and no
    /// other `Error`/`Fatal` finding — proving the fixture isolates exactly one
    /// rule end-to-end.
    #[test]
    fn each_hygiene_fixture_isolates_exactly_one_violation() {
        // (fixture bytes, the lint_id expected to fire).
        let cases: &[(&[u8], &str)] = &[
            (SHA1_SIGNATURE_PEM, "hygiene_no_sha1_signature"),
            (RSA_1024_PEM, "hygiene_rsa_key_min_2048"),
            (ECDSA_BAD_CURVE_PEM, "hygiene_ecdsa_curve_allowlist"),
        ];

        let registry = default_registry_with_now(Some(TEST_NOW));

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

    /// Regression guard: the clean leaf `good.pem` must pass the entire shipped
    /// registry with no `Error`/`Fatal` finding from any lint, including the new
    /// hygiene lints.
    #[test]
    fn good_pem_yields_no_error_or_fatal_findings() {
        let registry = default_registry_with_now(Some(TEST_NOW));
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
