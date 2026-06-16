//! The `hygiene_no_sha1_signature` lint.
//!
//! Flags certificates whose signature algorithm is based on SHA-1. SHA-1 is a
//! broken hash: practical chosen-prefix collisions exist (SHAttered, 2017; and
//! the 2020 "SHA-1 is a Shambles" chosen-prefix attack), which directly
//! undermines the integrity guarantee of a certificate signature. The CA/Browser
//! Forum Baseline Requirements and all major root programs have prohibited
//! SHA-1 signatures in publicly trusted certificates for years. We surface this
//! as a [`Severity::Error`]: a SHA-1 signature is a serious cryptographic defect,
//! not a stylistic nit.
//!
//! Detection is keyed on the signature algorithm OID (authoritative); the
//! registry short name is only used to enrich the message.

use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// `sha1WithRSAEncryption` (RFC 8017 / PKCS#1).
const OID_SHA1_WITH_RSA: &str = "1.2.840.113549.1.1.5";
/// `id-dsa-with-sha1` (RFC 5758 / FIPS 186).
const OID_DSA_WITH_SHA1: &str = "1.2.840.10040.4.3";
/// `ecdsa-with-SHA1` (RFC 5758).
const OID_ECDSA_WITH_SHA1: &str = "1.2.840.10045.4.1";

/// Flags SHA-1-based certificate signature algorithms.
#[derive(Debug, Clone, Default)]
pub struct NoSha1Signature;

impl NoSha1Signature {
    /// Creates the lint.
    pub fn new() -> Self {
        NoSha1Signature
    }
}

/// Pure decision: returns `true` if the given signature algorithm OID denotes a
/// SHA-1-based algorithm.
///
/// Kept separate so the OID logic can be unit-tested without constructing a
/// certificate.
fn is_sha1_signature_oid(oid: &str) -> bool {
    matches!(
        oid,
        OID_SHA1_WITH_RSA | OID_DSA_WITH_SHA1 | OID_ECDSA_WITH_SHA1
    )
}

/// Builds the human-readable algorithm label for a finding message, preferring
/// the registry short name and falling back to the dotted OID.
fn algorithm_label(oid: &str, name: Option<&str>) -> String {
    match name {
        Some(n) => format!("{n} ({oid})"),
        None => oid.to_string(),
    }
}

impl Lint for NoSha1Signature {
    fn id(&self) -> &'static str {
        "hygiene_no_sha1_signature"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Hygiene
    }

    fn applies(&self, _cert: &Cert) -> Applicability {
        // Every certificate has a signature algorithm, so this rule always
        // applies.
        Applicability::Applies
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy (see `lints::rfc5280` module docs and the `not_expired`
        // precedent): if the signature algorithm OID cannot be read, we cannot
        // evaluate the rule, so we emit nothing rather than fabricating a result.
        // Unreachable for a pre-validated `Cert`.
        let oid = match cert.signature_algorithm_oid() {
            Ok(oid) => oid,
            Err(_) => return Vec::new(),
        };

        if !is_sha1_signature_oid(&oid) {
            return Vec::new();
        }

        // The name is purely cosmetic; a read error there must not suppress the
        // finding we already decided to emit from the (authoritative) OID.
        let name = cert.signature_algorithm_name().ok().flatten();
        let label = algorithm_label(&oid, name.as_deref());

        vec![Finding {
            severity: Severity::Error,
            message: format!(
                "signature algorithm {label} is SHA-1-based; SHA-1 is cryptographically broken and prohibited for certificate signatures"
            ),
        }]
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

    mod is_sha1_signature_oid {
        use super::*;

        #[test]
        fn flags_sha1_with_rsa() {
            assert!(is_sha1_signature_oid(OID_SHA1_WITH_RSA));
        }

        #[test]
        fn flags_dsa_with_sha1() {
            assert!(is_sha1_signature_oid(OID_DSA_WITH_SHA1));
        }

        #[test]
        fn flags_ecdsa_with_sha1() {
            assert!(is_sha1_signature_oid(OID_ECDSA_WITH_SHA1));
        }

        #[test]
        fn passes_sha256_with_rsa() {
            // sha256WithRSAEncryption
            assert!(!is_sha1_signature_oid("1.2.840.113549.1.1.11"));
        }
    }

    mod algorithm_label {
        use super::*;

        #[test]
        fn prefers_name_when_present() {
            let label = algorithm_label("1.2.3", Some("sha1WithRSAEncryption"));
            assert_eq!(label, "sha1WithRSAEncryption (1.2.3)");
        }

        #[test]
        fn falls_back_to_oid_when_name_absent() {
            assert_eq!(algorithm_label("1.2.3", None), "1.2.3");
        }
    }

    mod check {
        use super::*;

        #[test]
        fn passes_for_good_cert() {
            let cert = good_cert();
            assert!(NoSha1Signature::new().check(&cert).is_empty());
        }

        #[test]
        fn applies_always() {
            let cert = good_cert();
            assert_eq!(
                NoSha1Signature::new().applies(&cert),
                Applicability::Applies
            );
        }
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = NoSha1Signature::new();
        assert_eq!(lint.id(), "hygiene_no_sha1_signature");
        assert_eq!(lint.source(), RuleSource::Hygiene);
    }
}
