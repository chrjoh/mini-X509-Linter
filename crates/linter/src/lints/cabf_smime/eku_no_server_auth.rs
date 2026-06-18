//! The `cabf_smime_eku_no_server_auth` lint
//! (CA/Browser Forum S/MIME BR §7.1.2.3).
//!
//! S/MIME BR §7.1.2.3: an S/MIME certificate's EKU MUST NOT also assert the
//! `serverAuth` purpose (OID `1.3.6.1.5.5.7.3.1`). Combining the email-protection
//! and TLS-server purposes in one certificate is a forbidden multipurpose use. A
//! certificate that asserts both is flagged as a [`Severity::Error`].
//!
//! # serverAuth-precedence interaction
//!
//! The `CertPurpose::Auto` resolver gives `serverAuth` precedence over
//! `emailProtection`, so a both-purposes cert resolves to `TlsServer` and is not
//! linted under `CabfSmime` automatically. But under an explicit
//! `--source cabf_smime` / `--purpose smime` (where the gate still applies, since
//! the cert does carry `emailProtection`), this lint fires — that is the intended
//! TLS-server-multipurpose-abuse signal.
//!
//! emailProtection-EKU-gated (see [`applies_to_smime_leaf`]).

use super::applies_to_smime_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Forbids an S/MIME certificate from also asserting the `serverAuth` EKU.
#[derive(Debug, Clone, Default)]
pub struct EkuNoServerAuth;

impl EkuNoServerAuth {
    /// Creates the lint.
    pub fn new() -> Self {
        EkuNoServerAuth
    }
}

/// Pure decision: fires when the `serverAuth` purpose is also asserted.
///
/// Kept separate so the logic can be unit-tested without constructing a
/// certificate.
fn evaluate(has_server_auth: bool) -> Vec<Finding> {
    if has_server_auth {
        vec![Finding {
            severity: Severity::Error,
            message: "an S/MIME certificate must not also assert the serverAuth EKU (OID \
                      1.3.6.1.5.5.7.3.1); CA/Browser Forum S/MIME BR §7.1.2.3 forbids TLS-server \
                      multipurpose use"
                .to_string(),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for EkuNoServerAuth {
    fn id(&self) -> &'static str {
        "cabf_smime_eku_no_server_auth"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfSmime
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_smime_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable EKU means we cannot evaluate; emit nothing.
        match cert.has_server_auth() {
            Ok(present) => evaluate(present),
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

    mod evaluate {
        use super::*;

        #[test]
        fn passes_when_no_server_auth() {
            assert!(evaluate(false).is_empty());
        }

        #[test]
        fn fires_when_server_auth_present() {
            let findings = evaluate(true);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }
    }

    #[test]
    fn not_applicable_for_non_smime_leaf() {
        let cert = good_cert();
        assert_eq!(
            EkuNoServerAuth::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = EkuNoServerAuth::new();
        assert_eq!(lint.id(), "cabf_smime_eku_no_server_auth");
        assert_eq!(lint.source(), RuleSource::CabfSmime);
    }
}
