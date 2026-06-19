//! The `chain_subject_issuer_dn_match` chain lint (RFC 5280 §4.1.2.4/§4.1.2.6).
//!
//! **Redefined for the chain pass.** Its OLD per-cert meaning ("adjacent file
//! pairs have matching subject/issuer DNs") no longer fits once the chain is
//! BUILT by Name-DER linkage — comparing arbitrary file-adjacent pairs is exactly
//! the false-Error source the construction step removes. It is now the chain's
//! **structural-integrity verdict** produced by
//! [`build_chain`](crate::chain::build_chain): *"every cert links to exactly one
//! issuer in the set and the certs form a single linear chain."*
//!
//! It fires **Error** on a missing middle link / unlinkable-extra cert / cycle,
//! **Warn** on a fork (ambiguous, after the deterministic lowest-index
//! tie-break), and passes (empty) when the set forms one clean chain — whether or
//! not it was in order (mere disorder is the separate `chain_not_in_order`
//! Notice, and a merely-absent root is the separate `chain_issuer_not_in_chain`
//! Notice).
//!
//! This is a **construction-driven** lint: its findings are injected by the chain
//! engine from the construction diagnostics, not from a pairwise `check`. The
//! `check` here is a no-op and is never called (see
//! [`ChainLint::is_construction_driven`](crate::ChainLint::is_construction_driven)).

use crate::cert::Cert;
use crate::{ChainLint, Finding, RuleSource};

/// The chain structural-integrity verdict (construction-driven).
#[derive(Debug, Clone, Default)]
pub struct SubjectIssuerDnMatch;

impl SubjectIssuerDnMatch {
    /// Creates the lint.
    pub fn new() -> Self {
        SubjectIssuerDnMatch
    }
}

impl ChainLint for SubjectIssuerDnMatch {
    fn id(&self) -> &'static str {
        "chain_subject_issuer_dn_match"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Chain
    }

    /// No-op: findings are injected by the engine from the construction
    /// diagnostics. Never called (the engine skips construction-driven lints).
    fn check(&self, _subject: &Cert, _issuer: &Cert) -> Vec<Finding> {
        Vec::new()
    }

    fn is_construction_driven(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_correct_id_and_source() {
        let lint = SubjectIssuerDnMatch::new();
        assert_eq!(lint.id(), "chain_subject_issuer_dn_match");
        assert_eq!(lint.source(), RuleSource::Chain);
    }

    #[test]
    fn is_construction_driven() {
        assert!(SubjectIssuerDnMatch::new().is_construction_driven());
    }
}
