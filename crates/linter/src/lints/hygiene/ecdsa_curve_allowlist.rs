//! The `hygiene_ecdsa_curve_allowlist` lint.
//!
//! Restricts elliptic-curve subject public keys to a small allowlist of
//! well-vetted NIST prime curves: P-256, P-384, and P-521 (RFC 5480 §2.1.1).
//! These are the curves required by the CA/Browser Forum Baseline Requirements
//! and supported across all major TLS stacks. Other named curves (e.g. legacy or
//! low-strength curves) and explicit/unnamed curve parameters fall outside what
//! we are willing to vouch for, so they are flagged as a [`Severity::Error`].
//!
//! This lint only applies to EC keys; for any other key algorithm it reports
//! [`Applicability::NotApplicable`].
//!
//! # `None` curve policy
//!
//! [`Cert::ec_named_curve`](crate::cert::Cert::ec_named_curve) returns `None`
//! when the key is EC but no recognised *named* curve OID is present (e.g.
//! explicit curve parameters, or an OID we could not extract). We deliberately
//! **fail closed** here: we cannot confirm the key uses an allowlisted named
//! curve, so we emit an `Error` rather than silently passing an unknown EC
//! parameter set. This matches the project's fail-securely stance (OWASP A04/A10)
//! for cryptographic decisions. This is distinct from the *accessor `Err`* case,
//! which means "could not read at all" and yields no findings per the shared
//! fail-safe policy.

use crate::cert::{Cert, NamedCurve, PublicKeyAlg};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// P-256 / prime256v1 (RFC 5480 §2.1.1.1).
const OID_P256: &str = "1.2.840.10045.3.1.7";
/// P-384 / secp384r1 (RFC 5480 §2.1.1.1).
const OID_P384: &str = "1.3.132.0.34";
/// P-521 / secp521r1 (RFC 5480 §2.1.1.1).
const OID_P521: &str = "1.3.132.0.35";

/// Restricts EC keys to the P-256 / P-384 / P-521 named curves.
#[derive(Debug, Clone, Default)]
pub struct EcdsaCurveAllowlist;

impl EcdsaCurveAllowlist {
    /// Creates the lint.
    pub fn new() -> Self {
        EcdsaCurveAllowlist
    }
}

/// Returns `true` if the given curve OID is on the allowlist.
fn is_allowlisted_oid(oid: &str) -> bool {
    matches!(oid, OID_P256 | OID_P384 | OID_P521)
}

/// Pure decision: turns an observed EC named curve into zero or one findings.
///
/// `None` models an EC key with no recognised named curve (explicit parameters
/// or an unextractable OID); per the module's fail-closed policy this is flagged.
/// Kept separate so the allowlist logic can be unit-tested without constructing a
/// certificate.
fn evaluate(curve: Option<NamedCurve>) -> Vec<Finding> {
    match curve {
        Some(curve) if is_allowlisted_oid(&curve.oid) => Vec::new(),
        Some(curve) => {
            let label = match &curve.name {
                Some(name) => format!("{name} ({})", curve.oid),
                None => curve.oid.clone(),
            };
            vec![Finding {
                severity: Severity::Error,
                message: format!("EC curve {label} is not on the allowlist (P-256, P-384, P-521)"),
            }]
        }
        None => vec![Finding {
            severity: Severity::Error,
            message: "EC key uses an unrecognised or explicit curve; only the named curves \
                      P-256, P-384, and P-521 are allowed"
                .to_string(),
        }],
    }
}

impl Lint for EcdsaCurveAllowlist {
    fn id(&self) -> &'static str {
        "hygiene_ecdsa_curve_allowlist"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Hygiene
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        // Fail policy: if the key algorithm cannot be read, we cannot scope the
        // rule, so treat it as not applicable (see `lints::rfc5280` module docs).
        match cert.public_key_algorithm() {
            Ok(PublicKeyAlg::Ec) => Applicability::Applies,
            _ => Applicability::NotApplicable,
        }
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: if the curve cannot be read at all, we cannot evaluate;
        // emit nothing. (A *successfully read* `None` curve is handled by
        // `evaluate` as a fail-closed Error — see module docs.) Unreachable for a
        // pre-validated `Cert`.
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

    /// Loads the workspace `testdata/good.pem` fixture (an RSA key; EC lints must
    /// be `NotApplicable` here).
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

    mod is_allowlisted_oid {
        use super::*;

        #[test]
        fn accepts_p256_p384_p521() {
            assert!(is_allowlisted_oid(OID_P256));
            assert!(is_allowlisted_oid(OID_P384));
            assert!(is_allowlisted_oid(OID_P521));
        }

        #[test]
        fn rejects_secp256k1() {
            // secp256k1 — not on the allowlist.
            assert!(!is_allowlisted_oid("1.3.132.0.10"));
        }
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_p256() {
            assert!(evaluate(Some(curve(OID_P256, Some("prime256v1")))).is_empty());
        }

        #[test]
        fn flags_non_allowlisted_curve() {
            let findings = evaluate(Some(curve("1.3.132.0.10", Some("secp256k1"))));
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }

        #[test]
        fn flags_unnamed_curve_fail_closed() {
            let findings = evaluate(None);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }
    }

    mod check {
        use super::*;

        #[test]
        fn not_applicable_for_rsa_good_cert() {
            let cert = good_cert();
            assert_eq!(
                EcdsaCurveAllowlist::new().applies(&cert),
                Applicability::NotApplicable
            );
        }
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = EcdsaCurveAllowlist::new();
        assert_eq!(lint.id(), "hygiene_ecdsa_curve_allowlist");
        assert_eq!(lint.source(), RuleSource::Hygiene);
    }
}
