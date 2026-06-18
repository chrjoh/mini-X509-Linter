//! The `cabf_ev_serial_number_missing` lint
//! (CA/Browser Forum EV Guidelines §9.2.6).
//!
//! EVG §9.2.6: an EV certificate's subject MUST include the `serialNumber`
//! (OID `2.5.4.5`) attribute carrying the Subject's registration or
//! incorporation number. An EV cert without it is mis-issued, so its absence is
//! flagged as a [`Severity::Error`].
//!
//! Note: this is the **subject-DN `serialNumber` attribute** (the
//! registration/incorporation number), which is entirely distinct from the
//! certificate's own serial number.
//!
//! EV-scoped (see [`applies_to_ev`]).

use super::applies_to_ev;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires an EV subject to include a `serialNumber` (registration-number)
/// attribute.
#[derive(Debug, Clone, Default)]
pub struct SerialNumberMissing;

impl SerialNumberMissing {
    /// Creates the lint.
    pub fn new() -> Self {
        SerialNumberMissing
    }
}

/// Pure decision: one [`Finding`] when no subject `serialNumber` value is
/// present, otherwise none.
fn evaluate(serial_numbers: &[String]) -> Vec<Finding> {
    if serial_numbers.is_empty() {
        vec![Finding {
            severity: Severity::Error,
            message: "EV subject is missing the serialNumber (registration number) attribute; \
                      CA/Browser Forum EV Guidelines §9.2.6 requires it (this is the subject-DN \
                      serialNumber, not the certificate serial)"
                .to_string(),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for SerialNumberMissing {
    fn id(&self) -> &'static str {
        "cabf_ev_serial_number_missing"
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
        match cert.subject_serial_numbers() {
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
        fn passes_when_serial_number_present() {
            assert!(evaluate(&[s("12345")]).is_empty());
        }

        #[test]
        fn fires_when_serial_number_absent() {
            let findings = evaluate(&[]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("serialNumber"));
        }
    }

    #[test]
    fn not_applicable_for_non_ev_leaf() {
        let cert = good_cert();
        assert_eq!(
            SerialNumberMissing::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SerialNumberMissing::new();
        assert_eq!(lint.id(), "cabf_ev_serial_number_missing");
        assert_eq!(lint.source(), RuleSource::CabfEv);
    }
}
