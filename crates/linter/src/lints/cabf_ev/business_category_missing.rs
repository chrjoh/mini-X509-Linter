//! The `cabf_ev_business_category_missing` lint
//! (CA/Browser Forum EV Guidelines §9.2.4).
//!
//! EVG §9.2.4: an EV certificate's subject MUST include the `businessCategory`
//! (OID `2.5.4.15`) attribute identifying the Subject's entity type. An EV cert
//! with no `businessCategory` is mis-issued, so its absence is flagged as a
//! [`Severity::Error`].
//!
//! EV-scoped (see [`applies_to_ev`]).

use super::applies_to_ev;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires an EV subject to include a `businessCategory` attribute.
#[derive(Debug, Clone, Default)]
pub struct BusinessCategoryMissing;

impl BusinessCategoryMissing {
    /// Creates the lint.
    pub fn new() -> Self {
        BusinessCategoryMissing
    }
}

/// Pure decision: one [`Finding`] when no `businessCategory` value is present,
/// otherwise none.
fn evaluate(business_categories: &[String]) -> Vec<Finding> {
    if business_categories.is_empty() {
        vec![Finding {
            severity: Severity::Error,
            message: "EV subject is missing the businessCategory attribute; CA/Browser Forum EV \
                      Guidelines §9.2.4 requires it"
                .to_string(),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for BusinessCategoryMissing {
    fn id(&self) -> &'static str {
        "cabf_ev_business_category_missing"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfEv
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_ev(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable subject means we cannot evaluate; emit
        // nothing.
        match cert.subject_business_category() {
            Ok(values) => evaluate(&values),
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
        fn passes_when_business_category_present() {
            assert!(evaluate(&[s("Private Organization")]).is_empty());
        }

        #[test]
        fn fires_when_business_category_absent() {
            let findings = evaluate(&[]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("businessCategory"));
        }
    }

    #[test]
    fn not_applicable_for_non_ev_leaf() {
        let cert = good_cert();
        assert_eq!(
            BusinessCategoryMissing::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = BusinessCategoryMissing::new();
        assert_eq!(lint.id(), "cabf_ev_business_category_missing");
        assert_eq!(lint.source(), RuleSource::CabfEv);
    }
}
