//! The `chain_issuer_is_ca` chain lint (RFC 5280 §4.2.1.9 / §4.2.1.3).
//!
//! The cert presented as an issuer MUST be a CA: its Basic Constraints must
//! assert `cA = TRUE` (RFC 5280 §4.2.1.9) AND its Key Usage must assert
//! `keyCertSign` (RFC 5280 §4.2.1.3). An end-entity certificate cannot legally
//! issue another certificate, so an issuer that fails either check is a broken
//! chain → **Error**.
//!
//! # Degradation
//!
//! Every issuer is checked. Any accessor `Err` (Basic Constraints or Key Usage
//! unreadable) yields no finding — the link cannot be evaluated, so it is not
//! penalized (never a panic).

use crate::cert::Cert;
use crate::{ChainLint, Finding, RuleSource, Severity};

/// Requires the issuer cert to be a `keyCertSign`-capable CA.
#[derive(Debug, Clone, Default)]
pub struct IssuerIsCa;

impl IssuerIsCa {
    /// Creates the lint.
    pub fn new() -> Self {
        IssuerIsCa
    }
}

impl ChainLint for IssuerIsCa {
    fn id(&self) -> &'static str {
        "chain_issuer_is_ca"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Chain
    }

    fn check(&self, _subject: &Cert, issuer: &Cert) -> Vec<Finding> {
        // Accessor Err → cannot evaluate → no finding.
        let (Ok(bc), Ok(ku)) = (issuer.basic_constraints(), issuer.key_usage()) else {
            return Vec::new();
        };

        let is_ca = bc.is_some_and(|b| b.is_ca);
        let key_cert_sign = ku.is_some_and(|k| k.key_cert_sign);

        if is_ca && key_cert_sign {
            return Vec::new();
        }

        let mut reasons = Vec::new();
        if !is_ca {
            reasons.push("Basic Constraints does not assert cA=TRUE");
        }
        if !key_cert_sign {
            reasons.push("Key Usage does not assert keyCertSign");
        }

        vec![Finding {
            severity: Severity::Error,
            message: format!(
                "issuer certificate \"{}\" is not a certificate-signing CA: {}; \
                 RFC 5280 §4.2.1.9/§4.2.1.3 require cA=TRUE and keyCertSign on an issuer",
                issuer_dn(issuer),
                reasons.join(" and "),
            ),
        }]
    }
}

/// A short DN summary of the issuer for messages, degrading to a placeholder.
fn issuer_dn(issuer: &Cert) -> String {
    match issuer.subject_rfc4514() {
        Ok(dn) if !dn.is_empty() => dn,
        _ => "subject unavailable".to_string(),
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

    #[test]
    fn passes_when_issuer_is_ca_with_key_cert_sign() {
        let leaf = load_one(LEAF_PEM);
        let inter = load_one(INTER_PEM);
        assert!(IssuerIsCa::new().check(&leaf, &inter).is_empty());
    }

    #[test]
    fn flags_non_ca_issuer() {
        // The leaf is an end-entity (cA=FALSE, no keyCertSign). Presenting it as
        // an issuer must be flagged.
        let leaf = load_one(LEAF_PEM);
        let findings = IssuerIsCa::new().check(&load_one(INTER_PEM), &leaf);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = IssuerIsCa::new();
        assert_eq!(lint.id(), "chain_issuer_is_ca");
        assert_eq!(lint.source(), RuleSource::Chain);
    }
}
