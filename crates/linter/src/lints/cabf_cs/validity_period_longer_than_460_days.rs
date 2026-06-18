//! The `cabf_cs_validity_period_longer_than_460_days` lint
//! (CA/Browser Forum CS BR §6.3.2).
//!
//! CS BR §6.3.2 recommends that a Code Signing Certificate's validity period
//! (`notAfter − notBefore`) not exceed 460 days. A window longer than 460 days
//! is flagged as a [`Severity::Warn`] (a recommendation, not the hard 39-month
//! ceiling enforced by `cabf_cs_validity_period_longer_than_39_months`).
//!
//! Note: any certificate exceeding 39 months necessarily also exceeds 460 days,
//! so both validity lints can co-fire on a very long window; that is expected.
//!
//! codeSigning-EKU-gated (see [`applies_to_code_signing`]). A zero-length or
//! inverted window reports `0` days (≤ 460, so it passes here).

use super::applies_to_code_signing;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Maximum recommended code-signing validity, in whole days (CS BR §6.3.2).
const MAX_VALIDITY_DAYS: i64 = 460;

/// Warns when a code-signing leaf's validity window exceeds 460 days.
#[derive(Debug, Clone, Default)]
pub struct ValidityPeriodLongerThan460Days;

impl ValidityPeriodLongerThan460Days {
    /// Creates the lint.
    pub fn new() -> Self {
        ValidityPeriodLongerThan460Days
    }
}

/// Pure decision: turns an observed validity-window length (in whole days) into
/// zero or one findings.
///
/// Kept separate so the 460-day ceiling can be unit-tested without constructing
/// a certificate. Exactly 460 days passes; 461 warns.
fn evaluate(days: i64) -> Vec<Finding> {
    if days > MAX_VALIDITY_DAYS {
        vec![Finding {
            severity: Severity::Warn,
            message: format!(
                "validity window is {days} days; CA/Browser Forum CS BR §6.3.2 recommends at \
                 most {MAX_VALIDITY_DAYS} days for a code-signing certificate"
            ),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for ValidityPeriodLongerThan460Days {
    fn id(&self) -> &'static str {
        "cabf_cs_validity_period_longer_than_460_days"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfCs
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_code_signing(cert)
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
        fn passes_exactly_460_days() {
            assert!(evaluate(460).is_empty());
        }

        #[test]
        fn warns_at_461_days() {
            let findings = evaluate(461);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Warn);
            assert!(findings[0].message.contains("461"));
        }

        #[test]
        fn warns_at_500_days() {
            let findings = evaluate(500);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Warn);
        }

        #[test]
        fn passes_zero_length_window() {
            assert!(evaluate(0).is_empty());
        }
    }

    #[test]
    fn not_applicable_for_non_code_signing_leaf() {
        let cert = good_cert();
        assert_eq!(
            ValidityPeriodLongerThan460Days::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = ValidityPeriodLongerThan460Days::new();
        assert_eq!(lint.id(), "cabf_cs_validity_period_longer_than_460_days");
        assert_eq!(lint.source(), RuleSource::CabfCs);
    }
}
