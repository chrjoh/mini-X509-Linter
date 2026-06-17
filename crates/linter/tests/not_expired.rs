//! Integration tests for the `not_expired` lint and the [`Cert`] facade,
//! exercised against the shared `testdata/` PEM fixtures.
//!
//! These tests validate the public API end-to-end on real certificates:
//! `Cert::load` must parse the committed fixtures, and `NotExpired::check` must
//! emit findings for the expired one and stay silent for the good one. The
//! deterministic boundary cases pin "now" via the `with_now_unix` seam so the
//! result never depends on the wall clock.
//!
//! Fixtures (see `testdata/generate.sh` for how they were produced):
//! - `good.pem`    notBefore=2026-06-01, notAfter=2027-06-01 (currently valid)
//! - `expired.pem` notBefore=2024-01-01, notAfter=2024-06-01 (past)

use linter::lints::hygiene::not_expired::NotExpired;
use linter::{Applicability, Cert, Lint, Severity};

// `include_bytes!` resolves relative to this source file
// (crates/linter/tests/not_expired.rs); `../../../testdata` reaches the
// workspace-root `testdata/` directory.
const GOOD_PEM: &[u8] = include_bytes!("../../../testdata/good.pem");
const EXPIRED_PEM: &[u8] = include_bytes!("../../../testdata/expired.pem");

/// A "now" inside good.pem's validity window (2026-06-01 → 2027-06-01) and well
/// past expired.pem's notAfter (2024-06-01): 2026-12-01 in Unix seconds.
///
/// Time-fragile: this instant must stay strictly within good.pem's window. If
/// good.pem is regenerated with a different window (see `testdata/generate.sh`),
/// this constant must move too.
const NOW_IN_GOOD_WINDOW: i64 = 1_796_083_200;

/// Loads the single leaf certificate from a PEM fixture, surfacing the parse
/// error (via `unwrap`) if the fixture is malformed.
fn load_leaf(pem: &[u8]) -> Cert {
    let mut certs = Cert::load(pem).unwrap();
    certs.remove(0)
}

mod cert_load {
    use super::*;

    #[test]
    fn good_fixture_loads() {
        // Setup + Invoke: `unwrap` prints the CertError if loading fails.
        let certs = Cert::load(GOOD_PEM).unwrap();

        // Find + Expect: exactly one certificate in the fixture.
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn expired_fixture_loads() {
        let certs = Cert::load(EXPIRED_PEM).unwrap();

        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn der_input_is_auto_detected_and_loads() {
        // Setup: derive raw DER bytes from a PEM fixture so the DER load path is
        // exercised without committing a separate binary fixture. The DER here is
        // not PEM, so `Cert::load` must route it through `from_der`.
        let pem_cert = Cert::load(GOOD_PEM).unwrap().remove(0);
        let der = pem_cert.der_bytes().to_vec();
        assert!(!der.starts_with(b"-----BEGIN"));

        // Invoke: auto-detection on raw DER bytes.
        let certs = Cert::load(&der).unwrap();

        // Find + Expect: exactly one cert, and it round-trips to the same DER.
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].der_bytes(), der.as_slice());
    }

    #[test]
    fn der_loaded_cert_is_usable_by_a_lint() {
        // A cert loaded via the DER path must be fully functional: its validity
        // window is readable and drives the lint exactly as a PEM-loaded cert.
        let der = Cert::load(EXPIRED_PEM)
            .unwrap()
            .remove(0)
            .der_bytes()
            .to_vec();
        let cert = Cert::load(&der).unwrap().remove(0);

        let findings = NotExpired::with_now_unix(NOW_IN_GOOD_WINDOW).check(&cert);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
    }
}

mod not_expired_lint {
    use super::*;

    #[test]
    fn expired_fixture_yields_one_warn_finding() {
        // Setup: an expired cert and a deterministic "now" past its notAfter.
        let cert = load_leaf(EXPIRED_PEM);
        let lint = NotExpired::with_now_unix(NOW_IN_GOOD_WINDOW);

        // Invoke.
        let findings = lint.check(&cert);

        // Find + Expect: exactly one finding, at Warn severity.
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
    }

    #[test]
    fn good_fixture_yields_no_findings() {
        // Setup: a currently-valid cert and a "now" inside its window.
        let cert = load_leaf(GOOD_PEM);
        let lint = NotExpired::with_now_unix(NOW_IN_GOOD_WINDOW);

        // Invoke.
        let findings = lint.check(&cert);

        // Find + Expect: passing a lint means an empty findings vec.
        assert!(findings.is_empty());
    }

    #[test]
    fn expired_fixture_passes_when_now_is_before_not_after() {
        // Boundary: with "now" pinned at the Unix epoch (1970, before
        // expired.pem's notAfter of 2024-06-01 and even its notBefore), the
        // expired fixture is not yet expired — proving the comparison, not the
        // wall clock, decides.
        let cert = load_leaf(EXPIRED_PEM);
        let lint = NotExpired::with_now_unix(0); // 1970, before notBefore even

        let findings = lint.check(&cert);

        assert!(findings.is_empty());
    }

    #[test]
    fn lint_applies_to_any_certificate() {
        let cert = load_leaf(GOOD_PEM);

        let applicability = NotExpired::new().applies(&cert);

        assert_eq!(applicability, Applicability::Applies);
    }
}
