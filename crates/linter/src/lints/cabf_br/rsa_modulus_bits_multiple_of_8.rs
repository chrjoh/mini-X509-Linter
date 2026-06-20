//! The `cabf_br_rsa_modulus_bits_multiple_of_8` lint
//! (CA/Browser Forum BR §6.1.6).
//!
//! BR §6.1.6 requires an RSA subscriber key's modulus length to be a whole
//! number of octets, i.e. its bit length MUST be a multiple of 8. An RSA leaf
//! whose modulus bit length is not octet-aligned (e.g. a 2047- or 2049-bit
//! modulus) is flagged [`Severity::Error`].
//!
//! This is distinct from `hygiene_rsa_key_min_2048`, which checks the minimum
//! key-size floor; this lint checks octet alignment regardless of the floor.
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//! A non-RSA key yields no modulus bit length, so the rule produces no finding.
//!
//! # Fail policy
//!
//! An accessor `Err` in `check` means "cannot evaluate" → empty `Vec`; an
//! accessor `Err` in `applies` (`is_ca`) means "cannot scope" → `NotApplicable`.

use super::applies_to_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires an RSA modulus bit length that is a multiple of 8.
#[derive(Debug, Clone, Default)]
pub struct RsaModulusBitsMultipleOf8;

impl RsaModulusBitsMultipleOf8 {
    /// Creates the lint.
    pub fn new() -> Self {
        RsaModulusBitsMultipleOf8
    }
}

/// Pure decision: one [`Finding`] when an RSA modulus bit length is not a
/// multiple of 8. `bits` is `None` for a non-RSA key ⇒ no finding.
fn evaluate(bits: Option<u32>) -> Vec<Finding> {
    match bits {
        Some(b) if b % 8 != 0 => vec![Finding {
            severity: Severity::Error,
            message: format!(
                "RSA modulus is {b} bits, which is not a multiple of 8 (not a whole \
                 number of octets); CA/Browser Forum BR §6.1.6 requires an octet-aligned \
                 RSA modulus"
            ),
        }],
        _ => Vec::new(),
    }
}

impl Lint for RsaModulusBitsMultipleOf8 {
    fn id(&self) -> &'static str {
        "cabf_br_rsa_modulus_bits_multiple_of_8"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.rsa_modulus_bits() {
            Ok(bits) => evaluate(bits),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_for_non_rsa_key() {
        assert!(evaluate(None).is_empty());
    }

    #[test]
    fn passes_for_aligned_modulus() {
        assert!(evaluate(Some(2048)).is_empty());
    }

    #[test]
    fn fires_for_unaligned_modulus() {
        let findings = evaluate(Some(2047));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains("2047"));
    }

    #[test]
    fn fires_for_modulus_just_above_octet_boundary() {
        assert_eq!(evaluate(Some(2049)).len(), 1);
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = RsaModulusBitsMultipleOf8::new();
        assert_eq!(lint.id(), "cabf_br_rsa_modulus_bits_multiple_of_8");
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
