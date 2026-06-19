//! The `pqc_mlkem_algorithm_known` lint.
//!
//! The certificate's SPKI algorithm OID lies in the ML-KEM "kems" arc
//! (`2.16.840.1.101.3.4.4.{1,2,3}`, NIST FIPS 203) — that is what admits this
//! lint via the shared [`applies_to_mlkem`](super::applies_to_mlkem) gate — but it
//! MUST also name a *published*, recognised parameter set. An arc member that maps
//! to no assigned parameter set (any unmapped slot, e.g. `.4`) is flagged as a
//! [`Severity::Error`]: it is not an interoperable algorithm.
//!
//! Basis: NIST FIPS 203 parameter-set table + the IETF LAMPS ML-KEM X.509
//! algorithm-identifier profile (RFC/draft number TBC).
//!
//! This is the one `mlkem` lint that *distinguishes* a known set from an
//! arc-but-unknown OID: the gate engages on any arc member (so this lint can fire
//! through the registry), and the length / key-usage lints treat the unknown case
//! as "no finding", so an unknown-arc fixture isolates exactly this lint. Mirror
//! of `pqc_algorithm_known`.

use super::applies_to_mlkem;
use crate::cert::{Cert, PqcParamSet, PublicKeyAlg};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires an ML-KEM SPKI OID to name a published FIPS 203 parameter set.
#[derive(Debug, Clone, Default)]
pub struct MlKemAlgorithmKnown;

impl MlKemAlgorithmKnown {
    /// Creates the lint.
    pub fn new() -> Self {
        MlKemAlgorithmKnown
    }
}

/// Pure decision: turns the resolved SPKI algorithm into zero or one findings.
///
/// Fires only on an ML-KEM variant carrying [`PqcParamSet::Unknown`]. A recognised
/// parameter set, or any non-ML-KEM algorithm (which the gate never admits, but is
/// handled defensively here), yields no finding. Kept separate so the logic is
/// unit-testable without constructing a certificate.
fn evaluate(alg: &PublicKeyAlg) -> Vec<Finding> {
    let unknown_oid = match alg {
        PublicKeyAlg::MlKem(PqcParamSet::Unknown(oid)) => oid,
        _ => return Vec::new(),
    };

    vec![Finding {
        severity: Severity::Error,
        message: format!(
            "the SPKI algorithm OID {unknown_oid} lies in the ML-KEM \"kems\" arc but does not \
             name a published FIPS 203 parameter set (NIST FIPS 203 + the IETF LAMPS ML-KEM \
             X.509 profile)"
        ),
    }]
}

impl Lint for MlKemAlgorithmKnown {
    fn id(&self) -> &'static str {
        "pqc_mlkem_algorithm_known"
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
        match cert.public_key_algorithm() {
            Ok(alg) => evaluate(&alg),
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
        fn passes_for_known_ml_kem_set() {
            let alg = PublicKeyAlg::MlKem(PqcParamSet::Known("ML-KEM-768"));
            assert!(evaluate(&alg).is_empty());
        }

        #[test]
        fn fires_for_unknown_ml_kem_arc_member() {
            let alg = PublicKeyAlg::MlKem(PqcParamSet::Unknown("2.16.840.1.101.3.4.4.4".into()));
            let findings = evaluate(&alg);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }

        #[test]
        fn passes_for_signature_pqc_algorithm() {
            // An ML-DSA key is not in scope for this KEM lint.
            let alg = PublicKeyAlg::MlDsa(PqcParamSet::Known("ML-DSA-65"));
            assert!(evaluate(&alg).is_empty());
        }

        #[test]
        fn passes_for_non_pqc_algorithm() {
            assert!(evaluate(&PublicKeyAlg::Rsa).is_empty());
        }
    }

    #[test]
    fn not_applicable_for_non_mlkem_leaf() {
        let cert = good_cert();
        assert_eq!(
            MlKemAlgorithmKnown::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = MlKemAlgorithmKnown::new();
        assert_eq!(lint.id(), "pqc_mlkem_algorithm_known");
        assert_eq!(lint.source(), RuleSource::Pqc);
    }
}
