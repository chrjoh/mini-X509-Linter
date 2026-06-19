//! The `pqc_mlkem_spki_parameters_absent` lint.
//!
//! For an ML-KEM SubjectPublicKeyInfo the `AlgorithmIdentifier.parameters` field
//! MUST be **absent** — not present, and not present-as-`NULL`. A present
//! `parameters` field is flagged as a [`Severity::Error`]: it is a malformed /
//! non-interoperable encoding under the profile.
//!
//! Basis: the IETF LAMPS ML-KEM X.509 algorithm-identifier profile (NIST FIPS
//! 203, RFC/draft number TBC), which mandates absent parameters for ML-KEM.
//!
//! ML-KEM-SPKI-gated (see [`applies_to_mlkem`](super::applies_to_mlkem)). Mirror
//! of `pqc_spki_parameters_absent`.

use super::applies_to_mlkem;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires the SPKI `AlgorithmIdentifier.parameters` to be absent for an ML-KEM
/// key.
#[derive(Debug, Clone, Default)]
pub struct MlKemSpkiParametersAbsent;

impl MlKemSpkiParametersAbsent {
    /// Creates the lint.
    pub fn new() -> Self {
        MlKemSpkiParametersAbsent
    }
}

/// Pure decision: a present SPKI `parameters` field fires one finding.
///
/// Kept separate so the logic is unit-testable without constructing a
/// certificate.
fn evaluate(parameters_present: bool) -> Vec<Finding> {
    if parameters_present {
        vec![Finding {
            severity: Severity::Error,
            message: "the SPKI AlgorithmIdentifier.parameters field MUST be absent for an \
                      ML-KEM public key, but a parameters field is present (IETF LAMPS ML-KEM \
                      X.509 profile, NIST FIPS 203)"
                .to_string(),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for MlKemSpkiParametersAbsent {
    fn id(&self) -> &'static str {
        "pqc_mlkem_spki_parameters_absent"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Pqc
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_mlkem(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable SPKI algorithm means we cannot evaluate;
        // emit nothing.
        match cert.spki_algorithm_parameters_present() {
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
    fn not_applicable_for_non_mlkem_leaf() {
        let cert = good_cert();
        assert_eq!(
            MlKemSpkiParametersAbsent::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = MlKemSpkiParametersAbsent::new();
        assert_eq!(lint.id(), "pqc_mlkem_spki_parameters_absent");
        assert_eq!(lint.source(), RuleSource::Pqc);
    }
}
