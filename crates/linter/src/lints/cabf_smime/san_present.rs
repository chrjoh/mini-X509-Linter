//! The `cabf_smime_san_present` lint (CA/Browser Forum S/MIME BR §7.1.2.3).
//!
//! S/MIME BR §7.1.2.3 (Subject Alternative Name): an S/MIME certificate MUST
//! carry a Subject Alternative Name extension containing at least one
//! `rfc822Name` (email address). A certificate with no SAN — or a SAN that
//! carries no `rfc822Name` — is flagged as a [`Severity::Error`].
//!
//! emailProtection-EKU-gated (see [`applies_to_smime_leaf`]).

use super::applies_to_smime_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires the SAN to carry at least one `rfc822Name` (email) entry.
#[derive(Debug, Clone, Default)]
pub struct SanPresent;

impl SanPresent {
    /// Creates the lint.
    pub fn new() -> Self {
        SanPresent
    }
}

/// Pure decision: turns the SAN `rfc822Name` count into zero or one findings.
///
/// Fires when no email address is present in the SAN (which also covers an
/// absent SAN, since `san_rfc822_names()` returns an empty list then). Kept
/// separate so the logic can be unit-tested without constructing a certificate.
fn evaluate(rfc822_names: &[String]) -> Vec<Finding> {
    if rfc822_names.is_empty() {
        vec![Finding {
            severity: Severity::Error,
            message: "the Subject Alternative Name extension must be present and contain at least \
                      one rfc822Name (email address) for an S/MIME certificate (CA/Browser Forum \
                      S/MIME BR §7.1.2.3)"
                .to_string(),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for SanPresent {
    fn id(&self) -> &'static str {
        "cabf_smime_san_present"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfSmime
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_smime_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable SAN means we cannot evaluate; emit nothing.
        match cert.san_rfc822_names() {
            Ok(names) => evaluate(&names),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    /// good.pem is a non-emailProtection TLS leaf — used only for scoping.
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
        fn passes_when_email_present() {
            assert!(evaluate(&[s("user@example.com")]).is_empty());
        }

        #[test]
        fn fires_when_no_email_present() {
            let findings = evaluate(&[]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }
    }

    #[test]
    fn not_applicable_for_non_smime_leaf() {
        let cert = good_cert();
        assert_eq!(
            SanPresent::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SanPresent::new();
        assert_eq!(lint.id(), "cabf_smime_san_present");
        assert_eq!(lint.source(), RuleSource::CabfSmime);
    }
}
