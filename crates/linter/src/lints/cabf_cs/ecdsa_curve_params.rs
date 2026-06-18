//! The `cabf_cs_ecdsa_curve_params` lint (CA/Browser Forum CS BR §6.1.5).
//!
//! CS BR §6.1.5: EC keys in code-signing certificates MUST use one of the
//! permitted NIST prime curves, identified by a *named-curve* OID (RFC 5480
//! §2.1.1): P-256 (`1.2.840.10045.3.1.7`), P-384 (`1.3.132.0.34`), or P-521
//! (`1.3.132.0.35`). An EC key that uses any other named curve, explicit/unnamed
//! curve parameters, or absent parameters is flagged as a [`Severity::Error`].
//!
//! Doubly scoped: codeSigning-EKU-gated (see [`applies_to_code_signing`]) AND
//! EC-only — non-EC keys are filtered inside [`check`] and produce no finding.
//!
//! # `None` curve policy (fail closed)
//!
//! [`Cert::ec_named_curve`](crate::cert::Cert::ec_named_curve) returns `None`
//! for an EC key with no recognised *named* curve OID (explicit parameters, or
//! an OID we could not extract). We **fail closed**: we cannot confirm a
//! permitted named curve, so we emit an `Error` rather than silently passing an
//! unknown EC parameter set (OWASP A04/A10 fail-securely stance). This is
//! distinct from the accessor `Err` case, which means "could not read at all"
//! and yields no findings per the shared fail-safe policy.

use super::applies_to_code_signing;
use crate::cert::{Cert, NamedCurve, PublicKeyAlg};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// P-256 / prime256v1 (RFC 5480 §2.1.1.1).
const OID_P256: &str = "1.2.840.10045.3.1.7";
/// P-384 / secp384r1 (RFC 5480 §2.1.1.1).
const OID_P384: &str = "1.3.132.0.34";
/// P-521 / secp521r1 (RFC 5480 §2.1.1.1).
const OID_P521: &str = "1.3.132.0.35";

/// Requires EC code-signing keys to use a permitted named curve.
#[derive(Debug, Clone, Default)]
pub struct EcdsaCurveParams;

impl EcdsaCurveParams {
    /// Creates the lint.
    pub fn new() -> Self {
        EcdsaCurveParams
    }
}

/// Returns `true` if the given curve OID is on the permitted set.
fn is_permitted_oid(oid: &str) -> bool {
    matches!(oid, OID_P256 | OID_P384 | OID_P521)
}

/// Pure decision: turns an observed EC named curve into zero or one findings.
///
/// `None` models an EC key with no recognised named curve (explicit parameters
/// or an unextractable OID); per the module's fail-closed policy this is flagged.
/// Kept separate so the logic can be unit-tested without constructing a
/// certificate.
fn evaluate(curve: Option<NamedCurve>) -> Vec<Finding> {
    match curve {
        Some(curve) if is_permitted_oid(&curve.oid) => Vec::new(),
        Some(curve) => {
            let label = match &curve.name {
                Some(name) => format!("{name} ({})", curve.oid),
                None => curve.oid.clone(),
            };
            vec![Finding {
                severity: Severity::Error,
                message: format!(
                    "EC curve {label} is not permitted for a code-signing certificate; \
                     CA/Browser Forum CS BR §6.1.5 allows only the named curves P-256, P-384, \
                     and P-521"
                ),
            }]
        }
        None => vec![Finding {
            severity: Severity::Error,
            message: "EC key uses unrecognised or explicit curve parameters; CA/Browser Forum \
                      CS BR §6.1.5 requires a named curve (P-256, P-384, or P-521)"
                .to_string(),
        }],
    }
}

impl Lint for EcdsaCurveParams {
    fn id(&self) -> &'static str {
        "cabf_cs_ecdsa_curve_params"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfCs
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_code_signing(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Further scope to EC keys only: an RSA code-signing key is the concern
        // of `cabf_cs_rsa_key_size`, not this lint.
        match cert.public_key_algorithm() {
            Ok(PublicKeyAlg::Ec) => {}
            _ => return Vec::new(),
        }
        // Fail policy: if the curve cannot be read at all we cannot evaluate;
        // emit nothing. (A successfully read `None` curve is the fail-closed
        // Error handled by `evaluate`.)
        match cert.ec_named_curve() {
            Ok(curve) => evaluate(curve),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    /// good.pem is a non-codeSigning RSA TLS leaf — used only for scoping.
    fn good_cert() -> Cert {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
        let bytes = std::fs::read(path).unwrap();
        let mut certs = Cert::from_pem(&bytes).unwrap();
        certs.remove(0)
    }

    fn curve(oid: &str, name: Option<&str>) -> NamedCurve {
        NamedCurve {
            oid: oid.to_string(),
            name: name.map(str::to_string),
        }
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_p256() {
            assert!(evaluate(Some(curve(OID_P256, Some("prime256v1")))).is_empty());
        }

        #[test]
        fn passes_p384() {
            assert!(evaluate(Some(curve(OID_P384, Some("secp384r1")))).is_empty());
        }

        #[test]
        fn passes_p521() {
            assert!(evaluate(Some(curve(OID_P521, Some("secp521r1")))).is_empty());
        }

        #[test]
        fn fires_for_non_permitted_curve() {
            // secp256k1 — a real curve that is not on the permitted set.
            let findings = evaluate(Some(curve("1.3.132.0.10", Some("secp256k1"))));
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }

        #[test]
        fn fires_for_none_curve_fail_closed() {
            let findings = evaluate(None);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }
    }

    #[test]
    fn not_applicable_for_non_code_signing_leaf() {
        let cert = good_cert();
        assert_eq!(
            EcdsaCurveParams::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = EcdsaCurveParams::new();
        assert_eq!(lint.id(), "cabf_cs_ecdsa_curve_params");
        assert_eq!(lint.source(), RuleSource::CabfCs);
    }
}
