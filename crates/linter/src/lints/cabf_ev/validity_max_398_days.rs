//! The `cabf_ev_validity_max_398_days` lint
//! (CA/Browser Forum EV Guidelines §9.4).
//!
//! EVG §9.4: an EV certificate's validity window (`notAfter − notBefore`) MUST
//! NOT exceed 398 days. A longer window is flagged as a [`Severity::Error`],
//! naming the observed duration. Exactly 398 days passes; 399 fires.
//!
//! Note: the EV ceiling (398 days) coincides with the BR ceiling, so a too-long
//! EV leaf also fires `cabf_br_validity_max_398_days`. Both firing is expected.
//!
//! EV-scoped (see [`applies_to_ev`]).

use super::applies_to_ev;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Maximum EV validity window, in whole days (EVG §9.4).
const MAX_VALIDITY_DAYS: i64 = 398;

/// Flags an EV leaf whose validity window exceeds 398 days.
#[derive(Debug, Clone, Default)]
pub struct ValidityMax398Days;

impl ValidityMax398Days {
    /// Creates the lint.
    pub fn new() -> Self {
        ValidityMax398Days
    }
}

/// Pure decision: turns an observed validity-window length (in whole days) into
/// zero or one findings. Kept separate so the 398-day ceiling can be unit-tested
/// without constructing a certificate. Exactly 398 days passes; 399 fires.
fn evaluate(days: i64) -> Vec<Finding> {
    if days > MAX_VALIDITY_DAYS {
        vec![Finding {
            severity: Severity::Error,
            message: format!(
                "validity window is {days} days; CA/Browser Forum EV Guidelines §9.4 allows at \
                 most {MAX_VALIDITY_DAYS} days for an EV certificate"
            ),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for ValidityMax398Days {
    fn id(&self) -> &'static str {
        "cabf_ev_validity_max_398_days"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfEv
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_ev(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable validity window means we cannot evaluate;
        // emit nothing.
        match cert.validity_days() {
            Ok(days) => evaluate(days),
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
        fn passes_exactly_398_days() {
            assert!(evaluate(398).is_empty());
        }

        #[test]
        fn fires_at_399_days() {
            let findings = evaluate(399);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("399"));
        }

        #[test]
        fn fires_at_400_days() {
            let findings = evaluate(400);
            assert_eq!(findings.len(), 1);
            assert!(findings[0].message.contains("400"));
        }

        #[test]
        fn passes_zero_length_window() {
            assert!(evaluate(0).is_empty());
        }
    }

    #[test]
    fn not_applicable_for_non_ev_leaf() {
        let cert = good_cert();
        assert_eq!(
            ValidityMax398Days::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = ValidityMax398Days::new();
        assert_eq!(lint.id(), "cabf_ev_validity_max_398_days");
        assert_eq!(lint.source(), RuleSource::CabfEv);
    }
}
