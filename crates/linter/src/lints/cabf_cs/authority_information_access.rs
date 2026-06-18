//! The `cabf_cs_authority_information_access` lint (CA/Browser Forum CS BR
//! §7.1.2.3).
//!
//! CS BR §7.1.2.3: a Code Signing Certificate is expected to carry an Authority
//! Information Access (AIA) extension (RFC 5280 §4.2.2.1) supplying CA Issuers
//! and OCSP pointers. A code-signing leaf with no AIA extension is flagged as a
//! [`Severity::Warn`].
//!
//! This lint is a *presence* check only: it does NOT enumerate the
//! `accessLocation` URI schemes (deferred to a follow-up lint).
//!
//! codeSigning-EKU-gated (see [`applies_to_code_signing`]).

use super::applies_to_code_signing;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Warns when a code-signing leaf has no Authority Information Access extension.
#[derive(Debug, Clone, Default)]
pub struct AuthorityInformationAccess;

impl AuthorityInformationAccess {
    /// Creates the lint.
    pub fn new() -> Self {
        AuthorityInformationAccess
    }
}

/// Pure decision: turns "is an AIA extension present?" into zero or one findings.
///
/// Kept separate so the logic can be unit-tested without constructing a
/// certificate.
fn evaluate(has_aia: bool) -> Vec<Finding> {
    if has_aia {
        Vec::new()
    } else {
        vec![Finding {
            severity: Severity::Warn,
            message: "no Authority Information Access extension; CA/Browser Forum CS BR §7.1.2.3 \
                      expects a code-signing certificate to carry AIA (CA Issuers / OCSP pointers)"
                .to_string(),
        }]
    }
}

impl Lint for AuthorityInformationAccess {
    fn id(&self) -> &'static str {
        "cabf_cs_authority_information_access"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfCs
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_code_signing(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: if AIA presence cannot be read we cannot evaluate; emit
        // nothing.
        match cert.has_authority_info_access() {
            Ok(present) => evaluate(present),
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

    mod evaluate {
        use super::*;

        #[test]
        fn passes_when_aia_present() {
            assert!(evaluate(true).is_empty());
        }

        #[test]
        fn warns_when_aia_absent() {
            let findings = evaluate(false);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Warn);
        }
    }

    #[test]
    fn not_applicable_for_non_code_signing_leaf() {
        let cert = good_cert();
        assert_eq!(
            AuthorityInformationAccess::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = AuthorityInformationAccess::new();
        assert_eq!(lint.id(), "cabf_cs_authority_information_access");
        assert_eq!(lint.source(), RuleSource::CabfCs);
    }
}
