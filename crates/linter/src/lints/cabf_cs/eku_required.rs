//! The `cabf_cs_eku_required` lint (CA/Browser Forum CS BR §7.1.2.3).
//!
//! CS BR §7.1.2.3: a Code Signing Certificate MUST assert the `codeSigning`
//! extended key usage purpose (OID `1.3.6.1.5.5.7.3.3`). A certificate missing
//! that purpose is flagged as a [`Severity::Error`].
//!
//! # Why this lint can never fire through the registry
//!
//! Every `cabf_cs` lint — this one included — is `applies()`-gated on the
//! codeSigning EKU already being present (see [`applies_to_code_signing`]). So a
//! certificate that reaches this lint's [`check`](Lint::check) via the normal
//! `Registry::run` path *by construction* asserts `codeSigning`, and this check
//! cannot produce a finding through that path.
//!
//! It is retained deliberately, mirroring zlint's `lint_cs_eku_required`:
//!
//! - under `--purpose code-signing` the CS set is the *declared intent*, and the
//!   explicit assertion stays documented and self-describing; and
//! - it is a defensive, **fail-closed** assertion for any direct caller that
//!   invokes `check` outside the gate (e.g. a unit test) — such a caller on a
//!   non-codeSigning leaf gets the `Error`.
//!
//! Because of the gate, this lint has no through-the-registry violating fixture;
//! its failing path is exercised by calling `check` directly on a
//! non-codeSigning leaf.

use super::applies_to_code_signing;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires a code-signing certificate to assert the `codeSigning` EKU.
#[derive(Debug, Clone, Default)]
pub struct EkuRequired;

impl EkuRequired {
    /// Creates the lint.
    pub fn new() -> Self {
        EkuRequired
    }
}

/// Pure decision: turns "is `codeSigning` asserted?" into zero or one findings.
///
/// Kept separate so the fail-closed logic can be unit-tested without
/// constructing a certificate.
fn evaluate(has_code_signing: bool) -> Vec<Finding> {
    if has_code_signing {
        Vec::new()
    } else {
        vec![Finding {
            severity: Severity::Error,
            message: "the codeSigning EKU (OID 1.3.6.1.5.5.7.3.3) is required for a code-signing \
                      certificate (CA/Browser Forum CS BR §7.1.2.3)"
                .to_string(),
        }]
    }
}

impl Lint for EkuRequired {
    fn id(&self) -> &'static str {
        "cabf_cs_eku_required"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfCs
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_code_signing(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable EKU means we cannot evaluate; emit nothing.
        match cert.has_code_signing() {
            Ok(present) => evaluate(present),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    /// Loads the workspace `testdata/good.pem` fixture: a TLS leaf with
    /// serverAuth (NOT codeSigning), so every CS lint is `NotApplicable` and
    /// this lint's `check` exercises the fail-closed `Error` path when called
    /// directly.
    fn good_cert() -> Cert {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
        let bytes = std::fs::read(path).unwrap();
        let mut certs = Cert::from_pem(&bytes).unwrap();
        certs.remove(0)
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_when_code_signing_present() {
            assert!(evaluate(true).is_empty());
        }

        #[test]
        fn fires_when_code_signing_absent() {
            let findings = evaluate(false);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }
    }

    #[test]
    fn not_applicable_for_non_code_signing_leaf() {
        let cert = good_cert();
        assert_eq!(
            EkuRequired::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn check_fails_closed_when_invoked_directly_on_non_code_signing_leaf() {
        // good.pem has serverAuth but not codeSigning; calling `check` directly
        // (outside the gate) exercises the defensive fail-closed Error path.
        let cert = good_cert();
        let findings = EkuRequired::new().check(&cert);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = EkuRequired::new();
        assert_eq!(lint.id(), "cabf_cs_eku_required");
        assert_eq!(lint.source(), RuleSource::CabfCs);
    }
}
