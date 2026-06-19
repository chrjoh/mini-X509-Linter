//! The `pqc_mlkem_public_key_length` lint.
//!
//! The raw subject-public-key (encapsulation-key) byte length MUST equal the
//! length mandated for the named ML-KEM parameter set (NIST FIPS 203 §8,
//! tabulated in [`kem_params`](super::kem_params)). A mismatch is flagged as a
//! [`Severity::Error`]; the message names the parameter set, the expected length,
//! and the actual length.
//!
//! On the "unknown arc member" case ([`PqcParamSet::Unknown`]) there is no known
//! length to validate, so this lint emits **no** finding —
//! `pqc_mlkem_algorithm_known` owns that case, and the unknown-arc fixture is left
//! isolating exactly that lint.
//!
//! Basis: NIST FIPS 203 §8 encapsulation-key sizes + the IETF LAMPS ML-KEM X.509
//! algorithm-identifier profile (RFC/draft number TBC), which defines the SPKI
//! public key as the raw encapsulation key — the BIT STRING value octets measured
//! by [`Cert::public_key_raw_len`](crate::cert::Cert::public_key_raw_len).
//!
//! ML-KEM-SPKI-gated (see [`applies_to_mlkem`](super::applies_to_mlkem)). Mirror
//! of `pqc_public_key_length`.

use super::applies_to_mlkem;
use super::kem_params::expected_mlkem_public_key_len;
use crate::cert::{Cert, PqcParamSet, PublicKeyAlg};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires an ML-KEM public key's byte length to match its named parameter set.
#[derive(Debug, Clone, Default)]
pub struct MlKemPublicKeyLength;

impl MlKemPublicKeyLength {
    /// Creates the lint.
    pub fn new() -> Self {
        MlKemPublicKeyLength
    }
}

/// Pure decision: compares the actual public-key length against the mandated one
/// for the resolved ML-KEM parameter set.
///
/// A known set with a mismatched length fires one finding. An unknown arc member
/// (no known length), or any non-ML-KEM algorithm (which the gate never admits),
/// yields no finding. Kept separate so the logic is unit-testable without
/// constructing a certificate.
fn evaluate(alg: &PublicKeyAlg, actual_len: usize) -> Vec<Finding> {
    let param_set = match alg {
        PublicKeyAlg::MlKem(PqcParamSet::Known(name)) => name,
        // Unknown arc member: pqc_mlkem_algorithm_known owns it; nothing to
        // validate. Non-ML-KEM: not admitted by the gate.
        _ => return Vec::new(),
    };

    let Some(expected_len) = expected_mlkem_public_key_len(param_set) else {
        // A Known name with no table entry would be an internal inconsistency;
        // fail closed to no finding rather than fabricate one.
        return Vec::new();
    };

    if actual_len == expected_len {
        Vec::new()
    } else {
        vec![Finding {
            severity: Severity::Error,
            message: format!(
                "{param_set} mandates a {expected_len}-byte encapsulation key, but the SPKI \
                 carries a {actual_len}-byte public key (NIST FIPS 203 §8)"
            ),
        }]
    }
}

impl Lint for MlKemPublicKeyLength {
    fn id(&self) -> &'static str {
        "pqc_mlkem_public_key_length"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Pqc
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_mlkem(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable SPKI algorithm or public-key length means we
        // cannot evaluate; emit nothing.
        match (cert.public_key_algorithm(), cert.public_key_raw_len()) {
            (Ok(alg), Ok(actual_len)) => evaluate(&alg, actual_len),
            _ => Vec::new(),
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
        fn passes_when_ml_kem_768_length_matches() {
            let alg = PublicKeyAlg::MlKem(PqcParamSet::Known("ML-KEM-768"));
            assert!(evaluate(&alg, 1184).is_empty());
        }

        #[test]
        fn passes_when_ml_kem_512_length_matches() {
            let alg = PublicKeyAlg::MlKem(PqcParamSet::Known("ML-KEM-512"));
            assert!(evaluate(&alg, 800).is_empty());
        }

        #[test]
        fn fires_when_length_mismatches() {
            let alg = PublicKeyAlg::MlKem(PqcParamSet::Known("ML-KEM-768"));
            let findings = evaluate(&alg, 800);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }

        #[test]
        fn no_finding_for_unknown_arc_member() {
            let alg = PublicKeyAlg::MlKem(PqcParamSet::Unknown("2.16.840.1.101.3.4.4.4".into()));
            assert!(evaluate(&alg, 9999).is_empty());
        }

        #[test]
        fn no_finding_for_non_mlkem_algorithm() {
            assert!(evaluate(&PublicKeyAlg::Rsa, 256).is_empty());
        }
    }

    #[test]
    fn not_applicable_for_non_mlkem_leaf() {
        let cert = good_cert();
        assert_eq!(
            MlKemPublicKeyLength::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = MlKemPublicKeyLength::new();
        assert_eq!(lint.id(), "pqc_mlkem_public_key_length");
        assert_eq!(lint.source(), RuleSource::Pqc);
    }
}
