//! The `chain_path_len_respected` chain lint (RFC 5280 §4.2.1.9).
//!
//! RFC 5280 §4.2.1.9: `pathLenConstraint` "gives the maximum number of
//! non-self-issued intermediate certificates that may follow this certificate in
//! a valid certification path." It is meaningful only when `cA = TRUE` and
//! `keyCertSign` is asserted. When the cert presented as an issuer is a CA with a
//! `pathLenConstraint = k`, the number of intermediate CAs that appear *below* it
//! in the built chain (between this issuer and the leaf, the leaf itself not
//! counted) MUST NOT exceed `k`. Exceeding it is a broken issuance path →
//! **Error**.
//!
//! # Engine-supplied depth
//!
//! This is the only v1 chain lint that needs whole-chain context: the issuer's
//! position in the built leaf→top order. The engine supplies it via
//! [`check_with_depth`](crate::ChainLint::check_with_depth) (`issuer_index = 0`
//! is the leaf). The number of intermediate CAs below the issuer is therefore
//! `issuer_index − 1` (the leaf at order index 0 is excluded from the count).
//!
//! # Pass-by-vacuity
//!
//! Returns no finding when the issuer is not a CA or has no `pathLenConstraint`
//! (unconstrained). Any accessor `Err` likewise yields no finding.

use crate::cert::Cert;
use crate::{ChainLint, Finding, RuleSource, Severity};

/// Requires the issuer CA's `pathLenConstraint` to bound the intermediates below
/// it.
#[derive(Debug, Clone, Default)]
pub struct PathLenRespected;

impl PathLenRespected {
    /// Creates the lint.
    pub fn new() -> Self {
        PathLenRespected
    }
}

impl ChainLint for PathLenRespected {
    fn id(&self) -> &'static str {
        "chain_path_len_respected"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Chain
    }

    /// Without depth context the lint cannot compute the path position, so the
    /// bare `check` is a pass-by-vacuity. The engine always calls
    /// [`check_with_depth`](ChainLint::check_with_depth).
    fn check(&self, _subject: &Cert, _issuer: &Cert) -> Vec<Finding> {
        Vec::new()
    }

    fn check_with_depth(
        &self,
        _subject: &Cert,
        issuer: &Cert,
        issuer_index: usize,
    ) -> Vec<Finding> {
        // Accessor Err → cannot evaluate → no finding.
        let Ok(bc) = issuer.basic_constraints() else {
            return Vec::new();
        };

        // Pass-by-vacuity: not a CA, or no pathLenConstraint (unconstrained).
        let Some(bc) = bc else {
            return Vec::new();
        };
        if !bc.is_ca {
            return Vec::new();
        }
        let Some(path_len) = bc.path_len else {
            return Vec::new();
        };

        // Intermediate CAs strictly below this issuer (between it and the leaf),
        // not counting the leaf at order index 0.
        let intermediates_below = issuer_index.saturating_sub(1);

        if (intermediates_below as u64) <= u64::from(path_len) {
            return Vec::new();
        }

        vec![Finding {
            severity: Severity::Error,
            message: format!(
                "issuer CA \"{}\" has pathLenConstraint={} but {} intermediate CA(s) appear below it in the chain; \
                 RFC 5280 §4.2.1.9 forbids exceeding the path-length constraint",
                issuer_dn(issuer),
                path_len,
                intermediates_below,
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
    fn passes_when_intermediates_within_path_len() {
        // inter has pathlen:0 and sits at order index 1 (issuer of the leaf at 0).
        // intermediates below = 0 <= 0 → pass.
        let leaf = load_one(LEAF_PEM);
        let inter = load_one(INTER_PEM);
        assert!(
            PathLenRespected::new()
                .check_with_depth(&leaf, &inter, 1)
                .is_empty()
        );
    }

    #[test]
    fn flags_when_intermediates_exceed_path_len() {
        // Pretend inter (pathlen:0) sits deep in the chain (issuer_index 3 ⇒ 2
        // intermediate CAs below it), exceeding its pathLenConstraint of 0.
        let leaf = load_one(LEAF_PEM);
        let inter = load_one(INTER_PEM);
        let findings = PathLenRespected::new().check_with_depth(&leaf, &inter, 3);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn pass_by_vacuity_when_issuer_not_ca() {
        // The leaf is not a CA → unconstrained → no finding.
        let leaf = load_one(LEAF_PEM);
        assert!(
            PathLenRespected::new()
                .check_with_depth(&load_one(INTER_PEM), &leaf, 5)
                .is_empty()
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = PathLenRespected::new();
        assert_eq!(lint.id(), "chain_path_len_respected");
        assert_eq!(lint.source(), RuleSource::Chain);
    }
}
