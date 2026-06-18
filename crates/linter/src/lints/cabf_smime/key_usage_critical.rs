//! The `cabf_smime_key_usage_critical` lint
//! (CA/Browser Forum S/MIME BR §7.1.2.3).
//!
//! S/MIME BR §7.1.2.3: the Key Usage extension SHOULD be marked critical. A Key
//! Usage extension that is present but not critical is flagged as a
//! [`Severity::Warn`].
//!
//! If the Key Usage extension is absent, this lint emits nothing — that is
//! [`KeyUsagePresent`](super::KeyUsagePresent)'s concern.
//!
//! emailProtection-EKU-gated (see [`applies_to_smime_leaf`]).

use super::applies_to_smime_leaf;
use crate::cert::{Cert, KeyUsageView};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Warns when a present Key Usage extension is not marked critical.
#[derive(Debug, Clone, Default)]
pub struct KeyUsageCritical;

impl KeyUsageCritical {
    /// Creates the lint.
    pub fn new() -> Self {
        KeyUsageCritical
    }
}

/// Pure decision: fires only when a Key Usage extension is present and not
/// critical. An absent extension (`None`) emits nothing.
///
/// Kept separate so the logic can be unit-tested without constructing a
/// certificate.
fn evaluate(key_usage: Option<KeyUsageView>) -> Vec<Finding> {
    match key_usage {
        Some(ku) if !ku.critical => vec![Finding {
            severity: Severity::Warn,
            message: "the Key Usage extension is not marked critical; CA/Browser Forum S/MIME BR \
                      §7.1.2.3 recommends it be critical"
                .to_string(),
        }],
        _ => Vec::new(),
    }
}

impl Lint for KeyUsageCritical {
    fn id(&self) -> &'static str {
        "cabf_smime_key_usage_critical"
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

    fn ku(critical: bool) -> KeyUsageView {
        KeyUsageView {
            digital_signature: true,
            key_encipherment: false,
            key_agreement: false,
            key_cert_sign: false,
            crl_sign: false,
            critical,
        }
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_when_critical() {
            assert!(evaluate(Some(ku(true))).is_empty());
        }

        #[test]
        fn passes_when_absent() {
            assert!(evaluate(None).is_empty());
        }

        #[test]
        fn warns_when_present_and_not_critical() {
            let findings = evaluate(Some(ku(false)));
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Warn);
        }
    }

    #[test]
    fn not_applicable_for_non_smime_leaf() {
        let cert = good_cert();
        assert_eq!(
            KeyUsageCritical::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = KeyUsageCritical::new();
        assert_eq!(lint.id(), "cabf_smime_key_usage_critical");
        assert_eq!(lint.source(), RuleSource::CabfSmime);
    }
}
