//! The `cabf_smime_crl_distribution_points_present` lint
//! (CA/Browser Forum S/MIME BR §7.1.2.3).
//!
//! S/MIME BR §7.1.2.3: a Subscriber S/MIME certificate MUST carry a CRL
//! Distribution Points extension (RFC 5280 §4.2.1.13) supplying a revocation
//! pointer. A certificate with no CRL-DP extension is flagged as a
//! [`Severity::Error`].
//!
//! This is a *presence* check only; the scheme of the distribution-point URIs is
//! the concern of
//! [`CrlDistributionPointsHttp`](super::CrlDistributionPointsHttp).
//!
//! emailProtection-EKU-gated (see [`applies_to_smime_leaf`]).

use super::applies_to_smime_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires an S/MIME certificate to carry a CRL Distribution Points extension.
#[derive(Debug, Clone, Default)]
pub struct CrlDistributionPointsPresent;

impl CrlDistributionPointsPresent {
    /// Creates the lint.
    pub fn new() -> Self {
        CrlDistributionPointsPresent
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
            severity: Severity::Error,
            message: "the CRL Distribution Points extension is required for an S/MIME certificate \
                      (CA/Browser Forum S/MIME BR §7.1.2.3)"
                .to_string(),
        }]
    }
}

impl Lint for CrlDistributionPointsPresent {
    fn id(&self) -> &'static str {
        "cabf_smime_crl_distribution_points_present"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfSmime
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_smime_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable CRL-DP presence means we cannot evaluate;
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
        fn fires_when_crl_dp_absent() {
            let findings = evaluate(false);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }
    }

    #[test]
    fn not_applicable_for_non_smime_leaf() {
        let cert = good_cert();
        assert_eq!(
            CrlDistributionPointsPresent::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = CrlDistributionPointsPresent::new();
        assert_eq!(lint.id(), "cabf_smime_crl_distribution_points_present");
        assert_eq!(lint.source(), RuleSource::CabfSmime);
    }
}
