//! The `cabf_ev_organization_name_missing` lint
//! (CA/Browser Forum EV Guidelines §9.2.1).
//!
//! EVG §9.2.1: an EV certificate's subject MUST include the `organizationName`
//! (O, OID `2.5.4.10`) attribute carrying the verified legal name of the
//! Subject. An EV cert with no `organizationName` is mis-issued, so its absence
//! is flagged as a [`Severity::Error`].
//!
//! EV-scoped (see [`applies_to_ev`]): only certificates in EV scope are checked.

use super::applies_to_ev;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires an EV subject to include an `organizationName` attribute.
#[derive(Debug, Clone, Default)]
pub struct OrganizationNameMissing;

impl OrganizationNameMissing {
    /// Creates the lint.
    pub fn new() -> Self {
        OrganizationNameMissing
    }
}

/// Pure decision: one [`Finding`] when no `organizationName` value is present,
/// otherwise none. Kept separate so the requirement is unit-testable without a
/// certificate.
fn evaluate(organization_names: &[String]) -> Vec<Finding> {
    if organization_names.is_empty() {
        vec![Finding {
            severity: Severity::Error,
            message: "EV subject is missing the organizationName (O) attribute; CA/Browser Forum \
                      EV Guidelines §9.2.1 requires it"
                .to_string(),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for OrganizationNameMissing {
    fn id(&self) -> &'static str {
        "cabf_ev_organization_name_missing"
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
        match cert.subject_organization_names() {
            Ok(names) => evaluate(&names),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    /// good.pem is a non-EV TLS leaf — used only for scoping.
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
        fn passes_when_organization_name_present() {
            assert!(evaluate(&[s("Example Inc")]).is_empty());
        }

        #[test]
        fn fires_when_organization_name_absent() {
            let findings = evaluate(&[]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("organizationName"));
        }
    }

    #[test]
    fn not_applicable_for_non_ev_leaf() {
        let cert = good_cert();
        assert_eq!(
            OrganizationNameMissing::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = OrganizationNameMissing::new();
        assert_eq!(lint.id(), "cabf_ev_organization_name_missing");
        assert_eq!(lint.source(), RuleSource::CabfEv);
    }
}
