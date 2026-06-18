//! The `cabf_cs_crl_distribution_points` lint (CA/Browser Forum CS BR §7.1.2.3).
//!
//! CS BR §7.1.2.3: a Code Signing Certificate is expected to carry a CRL
//! Distribution Points (CRL-DP) extension (RFC 5280 §4.2.1.13) supplying a
//! revocation pointer. A code-signing leaf with no CRL-DP extension is flagged
//! as a [`Severity::Warn`].
//!
//! This lint is a *presence* check only: it does NOT enumerate the
//! distribution-point URIs (deferred to a follow-up lint).
//!
//! codeSigning-EKU-gated (see [`applies_to_code_signing`]).

use super::applies_to_code_signing;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Warns when a code-signing leaf has no CRL Distribution Points extension.
#[derive(Debug, Clone, Default)]
pub struct CrlDistributionPoints;

impl CrlDistributionPoints {
    /// Creates the lint.
    pub fn new() -> Self {
        CrlDistributionPoints
    }
}

/// Pure decision: turns "is a CRL-DP extension present?" into zero or one
/// findings.
///
/// Kept separate so the logic can be unit-tested without constructing a
/// certificate.
fn evaluate(has_crl_dp: bool) -> Vec<Finding> {
    if has_crl_dp {
        Vec::new()
    } else {
        vec![Finding {
            severity: Severity::Warn,
            message: "no CRL Distribution Points extension; CA/Browser Forum CS BR §7.1.2.3 \
                      expects a code-signing certificate to carry a CRL revocation pointer"
                .to_string(),
        }]
    }
}

impl Lint for CrlDistributionPoints {
    fn id(&self) -> &'static str {
        "cabf_cs_crl_distribution_points"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfCs
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_code_signing(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: if CRL-DP presence cannot be read we cannot evaluate;
        // emit nothing.
        match cert.has_crl_distribution_points() {
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
        fn passes_when_crl_dp_present() {
            assert!(evaluate(true).is_empty());
        }

        #[test]
        fn warns_when_crl_dp_absent() {
            let findings = evaluate(false);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Warn);
        }
    }

    #[test]
    fn not_applicable_for_non_code_signing_leaf() {
        let cert = good_cert();
        assert_eq!(
            CrlDistributionPoints::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = CrlDistributionPoints::new();
        assert_eq!(lint.id(), "cabf_cs_crl_distribution_points");
        assert_eq!(lint.source(), RuleSource::CabfCs);
    }
}
