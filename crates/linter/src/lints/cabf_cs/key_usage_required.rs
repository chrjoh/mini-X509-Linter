//! The `cabf_cs_key_usage_required` lint (CA/Browser Forum CS BR §7.1.2.3).
//!
//! CS BR §7.1.2.3: a Code Signing Certificate MUST assert the
//! `digitalSignature` key usage bit (RFC 5280 §4.2.1.3, bit 0). A certificate
//! whose Key Usage extension does not assert that bit — or which has no Key
//! Usage extension at all — is flagged as a [`Severity::Error`].
//!
//! codeSigning-EKU-gated (see [`applies_to_code_signing`]).

use super::applies_to_code_signing;
use crate::cert::{Cert, KeyUsageView};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires a code-signing certificate to assert the `digitalSignature` KU bit.
#[derive(Debug, Clone, Default)]
pub struct KeyUsageRequired;

impl KeyUsageRequired {
    /// Creates the lint.
    pub fn new() -> Self {
        KeyUsageRequired
    }
}

/// Pure decision: turns the (optional) Key Usage view into zero or one findings.
///
/// `None` models an absent Key Usage extension, which cannot assert
/// `digitalSignature` and therefore fires. Kept separate so the logic can be
/// unit-tested without constructing a certificate.
fn evaluate(key_usage: Option<KeyUsageView>) -> Vec<Finding> {
    let asserts_digital_signature = key_usage.is_some_and(|ku| ku.digital_signature);
    if asserts_digital_signature {
        Vec::new()
    } else {
        vec![Finding {
            severity: Severity::Error,
            message: "the digitalSignature key usage bit is required for a code-signing \
                      certificate (CA/Browser Forum CS BR §7.1.2.3)"
                .to_string(),
        }]
    }
}

impl Lint for KeyUsageRequired {
    fn id(&self) -> &'static str {
        "cabf_cs_key_usage_required"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfCs
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_code_signing(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable Key Usage extension means we cannot
        // evaluate; emit nothing.
        match cert.key_usage() {
            Ok(ku) => evaluate(ku),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    /// good.pem is a non-codeSigning TLS leaf — used only for scoping.
    fn good_cert() -> Cert {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
        let bytes = std::fs::read(path).unwrap();
        let mut certs = Cert::from_pem(&bytes).unwrap();
        certs.remove(0)
    }

    fn ku(digital_signature: bool) -> KeyUsageView {
        KeyUsageView {
            digital_signature,
            key_cert_sign: false,
            critical: true,
        }
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_when_digital_signature_asserted() {
            assert!(evaluate(Some(ku(true))).is_empty());
        }

        #[test]
        fn fires_when_digital_signature_not_asserted() {
            let findings = evaluate(Some(ku(false)));
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }

        #[test]
        fn fires_when_key_usage_absent() {
            let findings = evaluate(None);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }
    }

    #[test]
    fn not_applicable_for_non_code_signing_leaf() {
        let cert = good_cert();
        assert_eq!(
            KeyUsageRequired::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = KeyUsageRequired::new();
        assert_eq!(lint.id(), "cabf_cs_key_usage_required");
        assert_eq!(lint.source(), RuleSource::CabfCs);
    }
}
