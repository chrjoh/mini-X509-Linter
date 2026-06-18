//! The `pqc_signature_parameters_absent` lint.
//!
//! For a certificate whose key is ML-DSA / SLH-DSA, the outer
//! `signatureAlgorithm` `AlgorithmIdentifier.parameters` field MUST be **absent**
//! — not present, and not present-as-`NULL`. A present `parameters` field is
//! flagged as a [`Severity::Error`].
//!
//! The lint self-gates on the *SPKI* algorithm being PQC (the shared gate); for a
//! self-issued / leaf example the signature algorithm is the same PQC family, and
//! the LAMPS profile's absent-parameters requirement applies to that signature
//! `AlgorithmIdentifier` as well.
//!
//! Basis: the IETF LAMPS ML-DSA / SLH-DSA X.509 algorithm-identifier profiles
//! (FIPS 204 / FIPS 205, RFC number TBC).
//!
//! PQC-SPKI-gated (see [`applies_to_pqc`]).

use super::applies_to_pqc;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires the signature `AlgorithmIdentifier.parameters` to be absent for a
/// PQC certificate.
#[derive(Debug, Clone, Default)]
pub struct SignatureParametersAbsent;

impl SignatureParametersAbsent {
    /// Creates the lint.
    pub fn new() -> Self {
        SignatureParametersAbsent
    }
}

/// Pure decision: a present signature `parameters` field fires one finding.
///
/// Kept separate so the logic is unit-testable without constructing a
/// certificate.
fn evaluate(parameters_present: bool) -> Vec<Finding> {
    if parameters_present {
        vec![Finding {
            severity: Severity::Error,
            message: "the signature AlgorithmIdentifier.parameters field MUST be absent for an \
                      ML-DSA / SLH-DSA certificate, but a parameters field is present (IETF \
                      LAMPS ML-DSA / SLH-DSA X.509 profile, FIPS 204 / FIPS 205)"
                .to_string(),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for SignatureParametersAbsent {
    fn id(&self) -> &'static str {
        "pqc_signature_parameters_absent"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Pqc
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_pqc(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable signature algorithm means we cannot
        // evaluate; emit nothing.
        match cert.signature_algorithm_parameters_present() {
            Ok(present) => evaluate(present),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    /// good.pem is an RSA TLS leaf — used only for scoping.
    fn good_cert() -> Cert {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
        let bytes = std::fs::read(path).unwrap();
        let mut certs = Cert::from_pem(&bytes).unwrap();
        certs.remove(0)
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_when_parameters_absent() {
            assert!(evaluate(false).is_empty());
        }

        #[test]
        fn fires_when_parameters_present() {
            let findings = evaluate(true);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }
    }

    #[test]
    fn not_applicable_for_non_pqc_leaf() {
        let cert = good_cert();
        assert_eq!(
            SignatureParametersAbsent::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SignatureParametersAbsent::new();
        assert_eq!(lint.id(), "pqc_signature_parameters_absent");
        assert_eq!(lint.source(), RuleSource::Pqc);
    }
}
