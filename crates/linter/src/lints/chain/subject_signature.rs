//! The `chain_signature_valid` chain lint (RFC 5280 §4.1.1.3), behind the
//! `verify` feature.
//!
//! Verifies the subject certificate's signature over its `tbsCertificate` DER
//! against the public key of the certificate presented as its issuer. This is
//! **signature verification ONLY** — it does NOT perform trust-anchor / path
//! validation, does NOT check revocation, and does NOT build or reorder the
//! chain. It answers exactly: "does this cert's signature verify against the
//! public key of the cert presented as its issuer?"
//!
//! # Policy
//!
//! - Verify SUCCEEDS → pass (empty findings).
//! - Verify FAILS → **Error** ("signature does not verify against the issuer's
//!   public key") — a forged / mismatched / corrupted link.
//! - Algorithm not in the supported matrix → **Notice** ("signature not verified:
//!   unsupported algorithm `<oid>`"). This is **fail-open**: never a false Error
//!   for an algorithm the backends cannot check.
//! - Any accessor `Err` (missing TBS / signature / SPKI bytes) → no finding
//!   (graceful degradation, like the structural lints).
//!
//! All crypto lives in the sibling [`verify`](super::verify) module; this lint is
//! a thin translator.
//!
//! # Maturity caveat
//!
//! PQC verification uses the pre-1.0, generally-unaudited `fips204` / `fips205`
//! crates — acceptable for a verifier over PUBLIC certificate data, not for
//! protecting secrets.
//!
//! # Self-signed roots
//!
//! A synthetic `(root, root)` self-link is NOT created in v1: the engine walks
//! only the N−1 adjacent links, so a self-signed root's signature is verified
//! only when the root appears as the issuer of the link below it. A standalone
//! self-signed root's self-signature check is reserved (see plan Open
//! Decision 8).
//! TODO(open-decision-8): optionally verify a self-signed root's own signature
//! by treating it as its own issuer for the top link.

use super::verify::{self, VerifyOutcome};
use crate::cert::Cert;
use crate::{ChainLint, Finding, RuleSource, Severity};

/// Verifies each link's signature against the issuer's public key.
#[derive(Debug, Clone, Default)]
pub struct SignatureValid;

impl SignatureValid {
    /// Creates the lint.
    pub fn new() -> Self {
        SignatureValid
    }
}

impl ChainLint for SignatureValid {
    fn id(&self) -> &'static str {
        "chain_signature_valid"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Chain
    }

    fn check(&self, subject: &Cert, issuer: &Cert) -> Vec<Finding> {
        // Any accessor Err → cannot evaluate → no finding (graceful degradation).
        let (Ok(oid), Ok(tbs), Ok(sig), Ok(spki)) = (
            subject.signature_algorithm_oid(),
            subject.tbs_der(),
            subject.signature_value_bytes(),
            issuer.issuer_spki_bytes(),
        ) else {
            return Vec::new();
        };

        match verify::verify_signature(&oid, &tbs, &sig, &spki) {
            VerifyOutcome::Verified => Vec::new(),
            VerifyOutcome::Failed => vec![Finding {
                severity: Severity::Error,
                message: format!(
                    "signature does not verify against the issuer's public key (algorithm OID {oid}); \
                     RFC 5280 §4.1.1.3"
                ),
            }],
            VerifyOutcome::Unsupported => vec![Finding {
                severity: Severity::Notice,
                message: format!("signature not verified: unsupported algorithm {oid}"),
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_one(pem: &[u8]) -> Cert {
        let mut certs = Cert::from_pem(pem).expect("fixture must parse");
        certs.pop().expect("fixture must contain one cert")
    }

    const LEAF_PEM: &[u8] = include_bytes!("../../chain_testdata/link_leaf.pem");
    const INTER_PEM: &[u8] = include_bytes!("../../chain_testdata/link_inter.pem");
    const ROOT_PEM: &[u8] = include_bytes!("../../chain_testdata/link_root.pem");

    #[test]
    fn valid_classical_link_passes() {
        let leaf = load_one(LEAF_PEM);
        let inter = load_one(INTER_PEM);
        assert!(SignatureValid::new().check(&leaf, &inter).is_empty());
    }

    #[test]
    fn wrong_issuer_is_error() {
        // leaf's signature checked against the root (not its real issuer).
        let leaf = load_one(LEAF_PEM);
        let root = load_one(ROOT_PEM);
        let findings = SignatureValid::new().check(&leaf, &root);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SignatureValid::new();
        assert_eq!(lint.id(), "chain_signature_valid");
        assert_eq!(lint.source(), RuleSource::Chain);
    }
}
