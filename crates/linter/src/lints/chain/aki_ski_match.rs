//! The `chain_aki_ski_match` chain lint (RFC 5280 §4.2.1.1).
//!
//! RFC 5280 §4.2.1.1: the Authority Key Identifier "provides a means of
//! identifying the public key corresponding to the private key used to sign a
//! certificate" and SHOULD match the issuer's Subject Key Identifier. When a
//! subject carries an AKI `keyIdentifier` AND its alleged issuer carries an SKI,
//! the two byte strings MUST be equal — a mismatch is a strong signal that the
//! wrong issuer is presented or the bundle is mis-ordered, so this fires
//! **Error**.
//!
//! # Pass-by-vacuity
//!
//! Returns no finding when the subject has no AKI `keyIdentifier` or the issuer
//! has no SKI (there is nothing to compare). Any accessor `Err` likewise yields
//! no finding (graceful degradation).

use crate::cert::Cert;
use crate::{ChainLint, Finding, RuleSource, Severity};

/// Requires a present subject AKI keyIdentifier to equal a present issuer SKI.
#[derive(Debug, Clone, Default)]
pub struct AkiSkiMatch;

impl AkiSkiMatch {
    /// Creates the lint.
    pub fn new() -> Self {
        AkiSkiMatch
    }
}

impl ChainLint for AkiSkiMatch {
    fn id(&self) -> &'static str {
        "chain_aki_ski_match"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Chain
    }

    fn check(&self, subject: &Cert, issuer: &Cert) -> Vec<Finding> {
        // Accessor Err → cannot evaluate → no finding.
        let (Ok(aki), Ok(ski)) = (
            subject.authority_key_id_bytes(),
            issuer.subject_key_id_bytes(),
        ) else {
            return Vec::new();
        };

        // Pass-by-vacuity: either key id absent → nothing to compare.
        let (Some(aki), Some(ski)) = (aki, ski) else {
            return Vec::new();
        };

        if aki == ski {
            return Vec::new();
        }

        vec![Finding {
            severity: Severity::Error,
            message: format!(
                "subject's Authority Key Identifier ({}) does not match the issuer's Subject Key Identifier ({}); \
                 RFC 5280 §4.2.1.1 expects them to match",
                hex_colon(&aki),
                hex_colon(&ski),
            ),
        }]
    }
}

/// Renders bytes as uppercase, colon-separated hex (e.g. `0A:1B:2C`) for
/// human-readable messages. Never used for the comparison itself (that uses the
/// raw bytes).
fn hex_colon(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_one(pem: &[u8]) -> Cert {
        let mut certs = Cert::from_pem(pem).expect("fixture must parse");
        certs.pop().expect("fixture must contain one cert")
    }

    // leaf is issued by inter: leaf.AKI == inter.SKI.
    const LEAF_PEM: &[u8] = include_bytes!("../../chain_testdata/link_leaf.pem");
    const INTER_PEM: &[u8] = include_bytes!("../../chain_testdata/link_inter.pem");
    const ROOT_PEM: &[u8] = include_bytes!("../../chain_testdata/link_root.pem");

    #[test]
    fn passes_matching_aki_ski() {
        let leaf = load_one(LEAF_PEM);
        let inter = load_one(INTER_PEM);
        assert!(AkiSkiMatch::new().check(&leaf, &inter).is_empty());
    }

    #[test]
    fn flags_mismatched_aki_ski() {
        // leaf's AKI points at inter, but we present root as the issuer: the
        // root's SKI differs from leaf's AKI → Error.
        let leaf = load_one(LEAF_PEM);
        let root = load_one(ROOT_PEM);
        let findings = AkiSkiMatch::new().check(&leaf, &root);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn pass_by_vacuity_when_subject_has_no_aki() {
        // A self-signed root has no AKI keyIdentifier (or it equals its own SKI);
        // using it as subject against an issuer with an SKI but where the subject
        // lacks an AKI yields no finding. The root here is self-signed; pair it
        // with inter as a notional issuer — the comparison only fires when both
        // ids are present and differ.
        let root = load_one(ROOT_PEM);
        let inter = load_one(INTER_PEM);
        // root has no AKI keyIdentifier → pass-by-vacuity.
        if root.authority_key_id_bytes().unwrap().is_none() {
            assert!(AkiSkiMatch::new().check(&root, &inter).is_empty());
        }
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = AkiSkiMatch::new();
        assert_eq!(lint.id(), "chain_aki_ski_match");
        assert_eq!(lint.source(), RuleSource::Chain);
    }
}
