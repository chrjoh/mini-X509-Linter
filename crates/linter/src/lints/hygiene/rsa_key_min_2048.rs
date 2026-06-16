//! The `hygiene_rsa_key_min_2048` lint.
//!
//! Requires RSA subject public keys to have a modulus of at least 2048 bits.
//! 1024-bit RSA has been considered factorable by well-resourced adversaries for
//! over a decade; NIST SP 800-57 and the CA/Browser Forum Baseline Requirements
//! both mandate a 2048-bit minimum for RSA. We surface an undersized modulus as a
//! [`Severity::Error`]: an under-strength key is a real cryptographic weakness.
//!
//! This lint only applies to RSA keys; for any other key algorithm it reports
//! [`Applicability::NotApplicable`].

use crate::cert::{Cert, PublicKeyAlg};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Minimum acceptable RSA modulus length in bits.
const MIN_RSA_BITS: u32 = 2048;

/// Requires RSA keys to use a modulus of at least 2048 bits.
#[derive(Debug, Clone, Default)]
pub struct RsaKeyMin2048;

impl RsaKeyMin2048 {
    /// Creates the lint.
    pub fn new() -> Self {
        RsaKeyMin2048
    }
}

/// Pure decision: turns an observed RSA modulus bit count into zero or one
/// findings.
///
/// `None` models an RSA key whose modulus could not be measured (e.g. an
/// unparsable SPKI). Following the fail-safe accessor policy we cannot confirm a
/// violation in that case, so we emit nothing. Kept separate so the threshold
/// logic can be unit-tested without constructing a certificate.
fn evaluate(bits: Option<u32>) -> Vec<Finding> {
    match bits {
        Some(bits) if bits < MIN_RSA_BITS => vec![Finding {
            severity: Severity::Error,
            message: format!(
                "RSA modulus is {bits} bits; a minimum of {MIN_RSA_BITS} bits is required"
            ),
        }],
        _ => Vec::new(),
    }
}

impl Lint for RsaKeyMin2048 {
    fn id(&self) -> &'static str {
        "hygiene_rsa_key_min_2048"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Hygiene
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        // Fail policy: if the key algorithm cannot be read, we cannot scope the
        // rule, so treat it as not applicable (see `lints::rfc5280` module docs).
        match cert.public_key_algorithm() {
            Ok(PublicKeyAlg::Rsa) => Applicability::Applies,
            _ => Applicability::NotApplicable,
        }
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable modulus means we cannot evaluate; emit
        // nothing rather than fabricate a result. Unreachable for a pre-validated
        // `Cert`.
        match cert.rsa_modulus_bits() {
            Ok(bits) => evaluate(bits),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    /// Loads the workspace `testdata/good.pem` fixture (RSA-2048 / SHA-256).
    fn good_cert() -> Cert {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
        let bytes = std::fs::read(path).unwrap();
        let mut certs = Cert::from_pem(&bytes).unwrap();
        certs.remove(0)
    }

    mod evaluate {
        use super::*;

        #[test]
        fn flags_1024_bit_modulus() {
            let findings = evaluate(Some(1024));
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }

        #[test]
        fn passes_exactly_2048_bits() {
            assert!(evaluate(Some(2048)).is_empty());
        }

        #[test]
        fn passes_4096_bits() {
            assert!(evaluate(Some(4096)).is_empty());
        }

        #[test]
        fn silent_when_bits_unknown() {
            assert!(evaluate(None).is_empty());
        }
    }

    mod check {
        use super::*;

        #[test]
        fn applies_to_rsa_good_cert() {
            let cert = good_cert();
            assert_eq!(RsaKeyMin2048::new().applies(&cert), Applicability::Applies);
        }

        #[test]
        fn passes_for_good_cert() {
            let cert = good_cert();
            assert!(RsaKeyMin2048::new().check(&cert).is_empty());
        }
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = RsaKeyMin2048::new();
        assert_eq!(lint.id(), "hygiene_rsa_key_min_2048");
        assert_eq!(lint.source(), RuleSource::Hygiene);
    }
}
