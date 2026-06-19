//! The `cabf_smime_key_usage_present` lint
//! (CA/Browser Forum S/MIME BR §7.1.2.3).
//!
//! S/MIME BR §7.1.2.3: an S/MIME certificate MUST carry a Key Usage extension.
//! A certificate with no Key Usage extension is flagged as a [`Severity::Error`].
//!
//! This is a *presence* check only; the criticality of the extension is the
//! concern of [`KeyUsageCritical`](super::KeyUsageCritical), and specific bit
//! requirements are deferred (see the feature plan's curated-subset rationale).
//!
//! emailProtection-EKU-gated (see [`applies_to_smime_leaf`]).

use super::applies_to_smime_leaf;
use crate::cert::{Cert, KeyUsageView};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires an S/MIME certificate to carry a Key Usage extension.
#[derive(Debug, Clone, Default)]
pub struct KeyUsagePresent;

impl KeyUsagePresent {
    /// Creates the lint.
    pub fn new() -> Self {
        KeyUsagePresent
    }
}

/// Pure decision: turns the (optional) Key Usage view into zero or one findings.
///
/// `None` models an absent Key Usage extension, which fires. Kept separate so
/// the logic can be unit-tested without constructing a certificate.
fn evaluate(key_usage: Option<KeyUsageView>) -> Vec<Finding> {
    if key_usage.is_some() {
        Vec::new()
    } else {
        vec![Finding {
            severity: Severity::Error,
            message: "the Key Usage extension is required for an S/MIME certificate (CA/Browser \
                      Forum S/MIME BR §7.1.2.3)"
                .to_string(),
        }]
    }
}

impl Lint for KeyUsagePresent {
    fn id(&self) -> &'static str {
        "cabf_smime_key_usage_present"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfSmime
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_smime_leaf(cert)
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

    fn good_cert() -> Cert {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
        let bytes = std::fs::read(path).unwrap();
        let mut certs = Cert::from_pem(&bytes).unwrap();
        certs.remove(0)
    }

    fn ku() -> KeyUsageView {
        KeyUsageView {
            digital_signature: true,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            key_cert_sign: false,
            crl_sign: false,
            encipher_only: false,
            decipher_only: false,
            critical: true,
        }
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_when_key_usage_present() {
            assert!(evaluate(Some(ku())).is_empty());
        }

        #[test]
        fn fires_when_key_usage_absent() {
            let findings = evaluate(None);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }
    }

    #[test]
    fn not_applicable_for_non_smime_leaf() {
        let cert = good_cert();
        assert_eq!(
            KeyUsagePresent::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = KeyUsagePresent::new();
        assert_eq!(lint.id(), "cabf_smime_key_usage_present");
        assert_eq!(lint.source(), RuleSource::CabfSmime);
    }
}
