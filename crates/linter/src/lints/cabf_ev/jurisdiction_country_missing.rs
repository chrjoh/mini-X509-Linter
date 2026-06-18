//! The `cabf_ev_jurisdiction_country_missing` lint
//! (CA/Browser Forum EV Guidelines §9.2.4).
//!
//! EVG §9.2.4: an EV certificate's subject MUST include the
//! `jurisdictionOfIncorporationCountryName` (OID `1.3.6.1.4.1.311.60.2.1.3`)
//! attribute identifying the country of the Subject's jurisdiction of
//! incorporation or registration. An EV cert without it is mis-issued, so its
//! absence is flagged as a [`Severity::Error`].
//!
//! Note: this is the *jurisdiction* country, distinct from the ordinary subject
//! `countryName` (C) attribute.
//!
//! EV-scoped (see [`applies_to_ev`]).

use super::applies_to_ev;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires an EV subject to include a `jurisdictionOfIncorporationCountryName`
/// attribute.
#[derive(Debug, Clone, Default)]
pub struct JurisdictionCountryMissing;

impl JurisdictionCountryMissing {
    /// Creates the lint.
    pub fn new() -> Self {
        JurisdictionCountryMissing
    }
}

/// Pure decision: one [`Finding`] when no jurisdiction-country value is present,
/// otherwise none.
fn evaluate(jurisdiction_countries: &[String]) -> Vec<Finding> {
    if jurisdiction_countries.is_empty() {
        vec![Finding {
            severity: Severity::Error,
            message: "EV subject is missing the jurisdictionOfIncorporationCountryName attribute; \
                      CA/Browser Forum EV Guidelines §9.2.4 requires it"
                .to_string(),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for JurisdictionCountryMissing {
    fn id(&self) -> &'static str {
        "cabf_ev_jurisdiction_country_missing"
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
        match cert.subject_jurisdiction_country() {
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
        fn passes_when_jurisdiction_country_present() {
            assert!(evaluate(&[s("US")]).is_empty());
        }

        #[test]
        fn fires_when_jurisdiction_country_absent() {
            let findings = evaluate(&[]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(
                findings[0]
                    .message
                    .contains("jurisdictionOfIncorporationCountryName")
            );
        }
    }

    #[test]
    fn not_applicable_for_non_ev_leaf() {
        let cert = good_cert();
        assert_eq!(
            JurisdictionCountryMissing::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = JurisdictionCountryMissing::new();
        assert_eq!(lint.id(), "cabf_ev_jurisdiction_country_missing");
        assert_eq!(lint.source(), RuleSource::CabfEv);
    }
}
