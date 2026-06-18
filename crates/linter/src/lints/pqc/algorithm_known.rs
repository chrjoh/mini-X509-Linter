//! The `pqc_algorithm_known` lint.
//!
//! The certificate's SPKI algorithm OID lies in the ML-DSA
//! (`2.16.840.1.101.3.4.3.{17,18,19}`, NIST FIPS 204) or SLH-DSA
//! (`2.16.840.1.101.3.4.3.{20..35}`, NIST FIPS 205) arc — that is what admits
//! this lint via the shared gate — but it MUST also name a *published*,
//! recognised parameter set. An arc member that maps to no assigned parameter
//! set (a reserved-but-unassigned SLH-DSA slot such as `.32`–`.35`, or any other
//! unmapped arc member) is flagged as a [`Severity::Error`]: it is not an
//! interoperable algorithm.
//!
//! Basis: NIST FIPS 204 §4 / FIPS 205 parameter-set tables + the IETF LAMPS
//! ML-DSA / SLH-DSA X.509 algorithm-identifier profiles (RFC number TBC).
//!
//! This is the one `pqc` lint that *distinguishes* a known set from an
//! arc-but-unknown OID: the gate engages on any arc member (so this lint can fire
//! through the registry), and the length / key-usage lints treat the unknown case
//! as "no finding", so an unknown-arc fixture isolates exactly this lint.

use super::applies_to_pqc;
use crate::cert::{Cert, PqcParamSet, PublicKeyAlg};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires a PQC SPKI OID to name a published ML-DSA / SLH-DSA parameter set.
#[derive(Debug, Clone, Default)]
pub struct AlgorithmKnown;

impl AlgorithmKnown {
    /// Creates the lint.
    pub fn new() -> Self {
        AlgorithmKnown
    }
}

/// Pure decision: turns the resolved SPKI algorithm into zero or one findings.
///
/// Fires only on a PQC variant carrying [`PqcParamSet::Unknown`]. A recognised
/// parameter set, or any non-PQC algorithm (which the gate never admits, but is
/// handled defensively here), yields no finding. Kept separate so the logic is
/// unit-testable without constructing a certificate.
fn evaluate(alg: &PublicKeyAlg) -> Vec<Finding> {
    let unknown_oid = match alg {
        PublicKeyAlg::MlDsa(PqcParamSet::Unknown(oid))
        | PublicKeyAlg::SlhDsa(PqcParamSet::Unknown(oid)) => oid,
        _ => return Vec::new(),
    };

    vec![Finding {
        severity: Severity::Error,
        message: format!(
            "the SPKI algorithm OID {unknown_oid} lies in an ML-DSA / SLH-DSA arc but does \
             not name a published FIPS 204 / FIPS 205 parameter set (NIST FIPS 204 §4 / \
             FIPS 205 parameter-set tables)"
        ),
    }]
}

impl Lint for AlgorithmKnown {
    fn id(&self) -> &'static str {
        "pqc_algorithm_known"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Pqc
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_pqc(cert)
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
        fn passes_for_known_ml_dsa_set() {
            let alg = PublicKeyAlg::MlDsa(PqcParamSet::Known("ML-DSA-65"));
            assert!(evaluate(&alg).is_empty());
        }

        #[test]
        fn passes_for_known_slh_dsa_set() {
            let alg = PublicKeyAlg::SlhDsa(PqcParamSet::Known("SLH-DSA-SHA2-128s"));
            assert!(evaluate(&alg).is_empty());
        }

        #[test]
        fn fires_for_unknown_ml_dsa_arc_member() {
            let alg = PublicKeyAlg::MlDsa(PqcParamSet::Unknown("2.16.840.1.101.3.4.3.16".into()));
            let findings = evaluate(&alg);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }

        #[test]
        fn fires_for_unknown_slh_dsa_arc_member() {
            let alg = PublicKeyAlg::SlhDsa(PqcParamSet::Unknown("2.16.840.1.101.3.4.3.32".into()));
            let findings = evaluate(&alg);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }

        #[test]
        fn passes_for_non_pqc_algorithm() {
            assert!(evaluate(&PublicKeyAlg::Rsa).is_empty());
        }
    }

    #[test]
    fn not_applicable_for_non_pqc_leaf() {
        let cert = good_cert();
        assert_eq!(
            AlgorithmKnown::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = AlgorithmKnown::new();
        assert_eq!(lint.id(), "pqc_algorithm_known");
        assert_eq!(lint.source(), RuleSource::Pqc);
    }
}
