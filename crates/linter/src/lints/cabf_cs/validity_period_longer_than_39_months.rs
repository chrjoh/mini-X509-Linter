//! The `cabf_cs_validity_period_longer_than_39_months` lint
//! (CA/Browser Forum CS BR §6.3.2).
//!
//! CS BR §6.3.2: a Code Signing Certificate's validity period
//! (`notAfter − notBefore`) MUST NOT exceed 39 months. A leaf whose window is
//! longer than 39 months is flagged as a [`Severity::Error`].
//!
//! # Months → days basis
//!
//! Validity is measured in whole days by the facade
//! ([`Cert::validity_days`](crate::cert::Cert::validity_days)), so the 39-month
//! cap is expressed as a single fixed day count. We use **1188 days**
//! (39 × ~30.46 ≈ 1188), the conventional zlint translation. Exactly 1188 days
//! passes; 1189 fires.
//!
//! codeSigning-EKU-gated (see [`applies_to_code_signing`]). A zero-length or
//! inverted window reports `0` days (≤ 1188, so it passes here); an inverted
//! window is the separate concern of
//! `rfc5280_validity_not_after_after_not_before`.

use super::applies_to_code_signing;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Maximum permitted code-signing validity, in whole days (39 months ≈ 1188).
const MAX_VALIDITY_DAYS: i64 = 1188;

/// Requires a code-signing leaf's validity window to be at most 39 months.
#[derive(Debug, Clone, Default)]
pub struct ValidityPeriodLongerThan39Months;

impl ValidityPeriodLongerThan39Months {
    /// Creates the lint.
    pub fn new() -> Self {
        ValidityPeriodLongerThan39Months
    }
}

/// Pure decision: turns an observed validity-window length (in whole days) into
/// zero or one findings.
///
/// Kept separate so the 1188-day ceiling can be unit-tested without constructing
/// a certificate.
fn evaluate(days: i64) -> Vec<Finding> {
    if days > MAX_VALIDITY_DAYS {
        vec![Finding {
            severity: Severity::Error,
            message: format!(
                "validity window is {days} days; CA/Browser Forum CS BR §6.3.2 allows at most \
                 39 months ({MAX_VALIDITY_DAYS} days) for a code-signing certificate"
            ),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for ValidityPeriodLongerThan39Months {
    fn id(&self) -> &'static str {
        "cabf_cs_validity_period_longer_than_39_months"
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
        fn passes_exactly_1188_days() {
            assert!(evaluate(1188).is_empty());
        }

        #[test]
        fn fires_at_1189_days() {
            let findings = evaluate(1189);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("1189"));
        }

        #[test]
        fn passes_zero_length_window() {
            assert!(evaluate(0).is_empty());
        }

        #[test]
        fn passes_460_days() {
            assert!(evaluate(460).is_empty());
        }
    }

    #[test]
    fn not_applicable_for_non_code_signing_leaf() {
        let cert = good_cert();
        assert_eq!(
            ValidityPeriodLongerThan39Months::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = ValidityPeriodLongerThan39Months::new();
        assert_eq!(lint.id(), "cabf_cs_validity_period_longer_than_39_months");
        assert_eq!(lint.source(), RuleSource::CabfCs);
    }
}
