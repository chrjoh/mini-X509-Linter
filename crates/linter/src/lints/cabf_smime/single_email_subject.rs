//! The `cabf_smime_single_email_subject` lint
//! (CA/Browser Forum S/MIME BR §7.1.4.2.1).
//!
//! S/MIME BR §7.1.4.2.1: the subject DN MUST carry at most one `emailAddress`
//! (OID 1.2.840.113549.1.9.1) attribute. A subject with more than one
//! `emailAddress` RDN is flagged as a [`Severity::Error`].
//!
//! Zero or one `emailAddress` attributes pass (the attribute is optional).
//!
//! emailProtection-EKU-gated (see [`applies_to_smime_leaf`]).

use super::applies_to_smime_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires the subject DN to carry at most one `emailAddress` attribute.
#[derive(Debug, Clone, Default)]
pub struct SingleEmailSubject;

impl SingleEmailSubject {
    /// Creates the lint.
    pub fn new() -> Self {
        SingleEmailSubject
    }
}

/// Pure decision: turns the subject `emailAddress` list into zero or one
/// findings. Fires when more than one is present.
///
/// Kept separate so the logic can be unit-tested without constructing a
/// certificate.
fn evaluate(email_addresses: &[String]) -> Vec<Finding> {
    if email_addresses.len() > 1 {
        vec![Finding {
            severity: Severity::Error,
            message: format!(
                "the subject DN carries {} emailAddress attributes; CA/Browser Forum S/MIME BR \
                 §7.1.4.2.1 permits at most one",
                email_addresses.len()
            ),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for SingleEmailSubject {
    fn id(&self) -> &'static str {
        "cabf_smime_single_email_subject"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfSmime
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_smime_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable subject means we cannot evaluate; emit
        // nothing.
        match cert.subject_email_addresses() {
            Ok(emails) => evaluate(&emails),
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

    fn s(v: &str) -> String {
        v.to_string()
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_when_no_email() {
            assert!(evaluate(&[]).is_empty());
        }

        #[test]
        fn passes_when_single_email() {
            assert!(evaluate(&[s("user@example.com")]).is_empty());
        }

        #[test]
        fn fires_when_two_emails() {
            let findings = evaluate(&[s("a@example.com"), s("b@example.com")]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }
    }

    #[test]
    fn not_applicable_for_non_smime_leaf() {
        let cert = good_cert();
        assert_eq!(
            SingleEmailSubject::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SingleEmailSubject::new();
        assert_eq!(lint.id(), "cabf_smime_single_email_subject");
        assert_eq!(lint.source(), RuleSource::CabfSmime);
    }
}
