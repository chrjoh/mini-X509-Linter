//! The `cabf_cs_rsa_key_size` lint (CA/Browser Forum CS BR §6.1.5).
//!
//! CS BR §6.1.5: RSA keys in code-signing certificates MUST be at least 3072
//! bits — a stronger floor than the generic hygiene minimum of 2048 bits. An
//! RSA key below 3072 bits is flagged as a [`Severity::Error`].
//!
//! Doubly scoped: codeSigning-EKU-gated (see [`applies_to_code_signing`]) AND
//! RSA-only — non-RSA keys are filtered inside [`check`] and produce no finding.

use super::applies_to_code_signing;
use crate::cert::{Cert, PublicKeyAlg};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Minimum acceptable RSA modulus length for a code-signing key, in bits.
const MIN_RSA_BITS: u32 = 3072;

/// Requires RSA code-signing keys to use a modulus of at least 3072 bits.
#[derive(Debug, Clone, Default)]
pub struct RsaKeySize;

impl RsaKeySize {
    /// Creates the lint.
    pub fn new() -> Self {
        RsaKeySize
    }
}

/// Pure decision: turns an observed RSA modulus bit count into zero or one
/// findings.
///
/// `None` models a non-RSA key (or an RSA modulus that could not be measured);
/// in either case there is nothing for this lint to flag. Kept separate so the
/// threshold logic can be unit-tested without constructing a certificate.
fn evaluate(bits: Option<u32>) -> Vec<Finding> {
    match bits {
        Some(bits) if bits < MIN_RSA_BITS => vec![Finding {
            severity: Severity::Error,
            message: format!(
                "RSA modulus is {bits} bits; CA/Browser Forum CS BR §6.1.5 requires at least \
                 {MIN_RSA_BITS} bits for a code-signing certificate"
            ),
        }],
        _ => Vec::new(),
    }
}

impl Lint for RsaKeySize {
    fn id(&self) -> &'static str {
        "cabf_cs_rsa_key_size"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfCs
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_code_signing(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Further scope to RSA keys only: a non-RSA code-signing key is the
        // concern of `cabf_cs_ecdsa_curve_params`, not this lint.
        match cert.public_key_algorithm() {
            Ok(PublicKeyAlg::Rsa) => {}
            _ => return Vec::new(),
        }
        // Fail policy: an unreadable modulus means we cannot evaluate; emit
        // nothing.
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
        fn fires_below_3072_bits() {
            let findings = evaluate(Some(2048));
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("2048"));
        }

        #[test]
        fn passes_exactly_3072_bits() {
            assert!(evaluate(Some(3072)).is_empty());
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

    #[test]
    fn not_applicable_for_non_code_signing_leaf() {
        let cert = good_cert();
        assert_eq!(
            RsaKeySize::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = RsaKeySize::new();
        assert_eq!(lint.id(), "cabf_cs_rsa_key_size");
        assert_eq!(lint.source(), RuleSource::CabfCs);
    }
}
