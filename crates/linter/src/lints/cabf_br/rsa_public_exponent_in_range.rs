//! The `cabf_br_rsa_public_exponent_in_range` lint
//! (CA/Browser Forum BR §6.1.6).
//!
//! BR §6.1.6 requires an RSA subscriber key's public exponent to be **odd** and
//! in the range `[2^16 + 1, 2^256 − 1]` (i.e. ≥ 65537 and ≤ 2^256 − 1). An RSA
//! leaf whose exponent fails any of these three predicates — most commonly a
//! small exponent such as 3 — is flagged [`Severity::Error`].
//!
//! The predicates are computed by the facade from the exponent's big-endian
//! octets (see [`RsaExponentView`](crate::cert::RsaExponentView)), so an
//! arbitrarily large exponent is handled without parsing into a fixed-width
//! integer.
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//! A non-RSA key yields no exponent view, so the rule produces no finding.
//!
//! # Fail policy
//!
//! An accessor `Err` in `check` means "cannot evaluate" → empty `Vec`; an
//! accessor `Err` in `applies` (`is_ca`) means "cannot scope" → `NotApplicable`.

use super::applies_to_leaf;
use crate::cert::{Cert, RsaExponentView};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires an RSA public exponent that is odd and in `[2^16 + 1, 2^256 − 1]`.
#[derive(Debug, Clone, Default)]
pub struct RsaPublicExponentInRange;

impl RsaPublicExponentInRange {
    /// Creates the lint.
    pub fn new() -> Self {
        RsaPublicExponentInRange
    }
}

/// Pure decision: one [`Finding`] when an RSA exponent fails any of the three
/// BR predicates. `view` is `None` for a non-RSA key ⇒ no finding.
fn evaluate(view: Option<&RsaExponentView>) -> Vec<Finding> {
    let Some(exp) = view else {
        return Vec::new();
    };
    if exp.is_odd && exp.at_least_65537 && exp.at_most_2_256_minus_1 {
        return Vec::new();
    }
    let mut reasons = Vec::new();
    if !exp.is_odd {
        reasons.push("it is not odd");
    }
    if !exp.at_least_65537 {
        reasons.push("it is less than 2^16 + 1 (65537)");
    }
    if !exp.at_most_2_256_minus_1 {
        reasons.push("it exceeds 2^256 − 1");
    }
    vec![Finding {
        severity: Severity::Error,
        message: format!(
            "RSA public exponent is out of range ({}); CA/Browser Forum BR §6.1.6 requires \
             it to be odd and in [2^16 + 1, 2^256 − 1]",
            reasons.join(" and ")
        ),
    }]
}

impl Lint for RsaPublicExponentInRange {
    fn id(&self) -> &'static str {
        "cabf_br_rsa_public_exponent_in_range"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.rsa_public_exponent() {
            Ok(view) => evaluate(view.as_ref()),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(is_odd: bool, at_least_65537: bool, at_most_2_256_minus_1: bool) -> RsaExponentView {
        RsaExponentView {
            is_odd,
            at_least_65537,
            at_most_2_256_minus_1,
        }
    }

    #[test]
    fn passes_for_non_rsa_key() {
        assert!(evaluate(None).is_empty());
    }

    #[test]
    fn passes_for_65537() {
        // 65537 = 0x010001: odd, >= 65537, <= 2^256 - 1.
        assert!(evaluate(Some(&view(true, true, true))).is_empty());
    }

    #[test]
    fn fires_for_small_exponent_3() {
        // 3: odd but below the floor.
        let findings = evaluate(Some(&view(true, false, true)));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains("65537"));
    }

    #[test]
    fn fires_for_even_exponent() {
        let findings = evaluate(Some(&view(false, true, true)));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("not odd"));
    }

    #[test]
    fn fires_for_too_large_exponent() {
        let findings = evaluate(Some(&view(true, true, false)));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("2^256"));
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = RsaPublicExponentInRange::new();
        assert_eq!(lint.id(), "cabf_br_rsa_public_exponent_in_range");
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
