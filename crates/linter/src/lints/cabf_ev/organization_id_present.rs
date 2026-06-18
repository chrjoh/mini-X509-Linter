//! The `cabf_ev_organization_id_present` lint
//! (CA/Browser Forum EV Guidelines §9.2.8).
//!
//! EVG §9.2.8: an EV certificate's subject carries an `organizationIdentifier`
//! (OID `2.5.4.97`) attribute encoding the Subject's registration scheme,
//! jurisdiction, and registration reference. This lint flags the **absence** of
//! that attribute as a [`Severity::Error`].
//!
//! (Despite the `_present` name, this lint fires when the attribute is *not*
//! present — it enforces that an `organizationIdentifier` is present.)
//!
//! EV-scoped (see [`applies_to_ev`]).

use super::applies_to_ev;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires an EV subject to include an `organizationIdentifier` attribute.
#[derive(Debug, Clone, Default)]
pub struct OrganizationIdPresent;

impl OrganizationIdPresent {
    /// Creates the lint.
    pub fn new() -> Self {
        OrganizationIdPresent
    }
}

/// Pure decision: one [`Finding`] when no `organizationIdentifier` value is
/// present, otherwise none.
fn evaluate(organization_identifiers: &[String]) -> Vec<Finding> {
    if organization_identifiers.is_empty() {
        vec![Finding {
            severity: Severity::Error,
            message: "EV subject is missing the organizationIdentifier attribute; CA/Browser \
                      Forum EV Guidelines §9.2.8 requires it"
                .to_string(),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for OrganizationIdPresent {
    fn id(&self) -> &'static str {
        "cabf_ev_organization_id_present"
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
        match cert.subject_organization_identifiers() {
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
        fn passes_when_organization_identifier_present() {
            assert!(evaluate(&[s("NTRUS-12345")]).is_empty());
        }

        #[test]
        fn fires_when_organization_identifier_absent() {
            let findings = evaluate(&[]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("organizationIdentifier"));
        }
    }

    #[test]
    fn not_applicable_for_non_ev_leaf() {
        let cert = good_cert();
        assert_eq!(
            OrganizationIdPresent::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = OrganizationIdPresent::new();
        assert_eq!(lint.id(), "cabf_ev_organization_id_present");
        assert_eq!(lint.source(), RuleSource::CabfEv);
    }
}
