//! The `cabf_ev_business_category_invalid` lint
//! (CA/Browser Forum EV Guidelines §9.2.4).
//!
//! EVG §9.2.4: when present, the `businessCategory` (OID `2.5.4.15`) attribute
//! MUST contain one of exactly three permitted values:
//!
//! - `Private Organization`
//! - `Government Entity`
//! - `Business Entity`
//!
//! Each `businessCategory` value outside this set is flagged as a
//! [`Severity::Error`], one finding per offending value, naming it. (The
//! *absence* of `businessCategory` is handled by
//! `cabf_ev_business_category_missing`, not here.)
//!
//! EV-scoped (see [`applies_to_ev`]).

use super::applies_to_ev;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// The three permitted `businessCategory` values (EVG §9.2.4).
const PERMITTED: &[&str] = &[
    "Private Organization",
    "Government Entity",
    "Business Entity",
];

/// Requires every present `businessCategory` value to be one of the three
/// permitted values.
#[derive(Debug, Clone, Default)]
pub struct BusinessCategoryInvalid;

impl BusinessCategoryInvalid {
    /// Creates the lint.
    pub fn new() -> Self {
        BusinessCategoryInvalid
    }
}

/// Pure decision: one [`Finding`] per `businessCategory` value not in the
/// permitted set; empty when there are no (or only permitted) values. Kept
/// separate so the permitted-set policy is unit-testable with plain strings.
fn evaluate(business_categories: &[String]) -> Vec<Finding> {
    business_categories
        .iter()
        .filter(|value| !PERMITTED.contains(&value.as_str()))
        .map(|value| Finding {
            severity: Severity::Error,
            message: format!(
                "businessCategory \"{value}\" is not a permitted EV value; CA/Browser Forum EV \
                 Guidelines §9.2.4 allows only \"Private Organization\", \"Government Entity\", or \
                 \"Business Entity\""
            ),
        })
        .collect()
}

impl Lint for BusinessCategoryInvalid {
    fn id(&self) -> &'static str {
        "cabf_ev_business_category_invalid"
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
        fn passes_for_each_permitted_value() {
            assert!(evaluate(&[s("Private Organization")]).is_empty());
            assert!(evaluate(&[s("Government Entity")]).is_empty());
            assert!(evaluate(&[s("Business Entity")]).is_empty());
        }

        #[test]
        fn passes_when_no_values() {
            // Absence is handled by business_category_missing, not here.
            assert!(evaluate(&[]).is_empty());
        }

        #[test]
        fn fires_for_disallowed_value() {
            let findings = evaluate(&[s("Sole Proprietor")]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("Sole Proprietor"));
        }

        #[test]
        fn is_case_sensitive() {
            // The permitted values are exact; lowercase is not permitted.
            assert_eq!(evaluate(&[s("private organization")]).len(), 1);
        }

        #[test]
        fn emits_one_finding_per_offending_value() {
            let findings = evaluate(&[s("Sole Proprietor"), s("Business Entity"), s("Other")]);
            assert_eq!(findings.len(), 2);
        }
    }

    #[test]
    fn not_applicable_for_non_ev_leaf() {
        let cert = good_cert();
        assert_eq!(
            BusinessCategoryInvalid::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = BusinessCategoryInvalid::new();
        assert_eq!(lint.id(), "cabf_ev_business_category_invalid");
        assert_eq!(lint.source(), RuleSource::CabfEv);
    }
}
