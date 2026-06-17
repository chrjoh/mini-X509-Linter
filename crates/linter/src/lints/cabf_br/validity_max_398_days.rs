//! The `cabf_br_validity_max_398_days` lint (CA/Browser Forum BR §6.3.2).
//!
//! BR §6.3.2: for Subscriber Certificates, the validity period
//! (`notAfter − notBefore`) MUST NOT exceed 398 days. A leaf whose window is
//! longer than 398 days is flagged as a [`Severity::Error`].
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//! A zero-length or inverted window reports `0` days from the facade (≤ 398, so
//! it passes here); an inverted window is the separate concern of
//! `rfc5280_validity_not_after_after_not_before`.

use super::applies_to_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Maximum permitted Subscriber Certificate validity, in whole days (BR §6.3.2).
const MAX_VALIDITY_DAYS: i64 = 398;

/// Requires a non-CA leaf's validity window to be at most 398 days.
#[derive(Debug, Clone, Default)]
pub struct ValidityMax398Days;

impl ValidityMax398Days {
    /// Creates the lint.
    pub fn new() -> Self {
        ValidityMax398Days
    }
}

/// Pure decision: turns an observed validity-window length (in whole days) into
/// zero or one findings.
///
/// Kept separate so the 398-day ceiling can be unit-tested without constructing
/// a certificate. Exactly 398 days passes; 399 fires.
fn evaluate(days: i64) -> Vec<Finding> {
    if days > MAX_VALIDITY_DAYS {
        vec![Finding {
            severity: Severity::Error,
            message: format!(
                "validity window is {days} days; CA/Browser Forum BR §6.3.2 allows at most \
                 {MAX_VALIDITY_DAYS} days for a subscriber certificate"
            ),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for ValidityMax398Days {
    fn id(&self) -> &'static str {
        "cabf_br_validity_max_398_days"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable validity window means we cannot evaluate;
        // emit nothing (see module docs). Unreachable for a pre-validated `Cert`.
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

    /// Loads a single cert from a workspace `testdata` fixture by file name.
    fn load_fixture(name: &str) -> Cert {
        let path = format!(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/{}"),
            name
        );
        let bytes = std::fs::read(&path).unwrap();
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
        fn passes_zero_length_window() {
            assert!(evaluate(0).is_empty());
        }

        #[test]
        fn fires_for_far_future_window() {
            assert_eq!(evaluate(36500).len(), 1);
        }
    }

    #[test]
    fn not_applicable_for_ca_cert() {
        let cert = load_fixture("rfc5280_ca_bc_not_critical.pem");
        assert_eq!(
            ValidityMax398Days::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = ValidityMax398Days::new();
        assert_eq!(lint.id(), "cabf_br_validity_max_398_days");
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
