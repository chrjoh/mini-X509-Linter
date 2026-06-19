//! The `chain_issuer_not_in_chain` chain lint (RFC 5280 §4.2.1.1 / §6.1).
//!
//! A Notice emitted on the top cert when its issuer (e.g. the root) is simply not
//! present in the presented set. This is NOT an error: servers usually present
//! leaf + intermediates but omit the root (the client holds it in its trust
//! store), and for `--from-host` trust to a root is established by the connection
//! verdict, not by the lints. A self-signed top (its own anchor) or a top whose
//! issuer IS present does not trigger this Notice.
//!
//! This is a **construction-driven** lint: its finding is injected by the chain
//! engine from the
//! [`MissingTopIssuer`](crate::chain::ConstructionDiagnostic::MissingTopIssuer)
//! diagnostic, not from a pairwise `check` (which is a no-op and never called).

use crate::cert::Cert;
use crate::{ChainLint, Finding, RuleSource};

/// Notices that the top cert's issuer (the root) is absent from the presented
/// set (construction-driven).
#[derive(Debug, Clone, Default)]
pub struct IssuerNotInChain;

impl IssuerNotInChain {
    /// Creates the lint.
    pub fn new() -> Self {
        IssuerNotInChain
    }
}

impl ChainLint for IssuerNotInChain {
    fn id(&self) -> &'static str {
        "chain_issuer_not_in_chain"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Chain
    }

    /// No-op: the finding is injected by the engine from the `MissingTopIssuer`
    /// diagnostic. Never called (the engine skips construction-driven lints).
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
        let lint = IssuerNotInChain::new();
        assert_eq!(lint.id(), "chain_issuer_not_in_chain");
        assert_eq!(lint.source(), RuleSource::Chain);
    }

    #[test]
    fn is_construction_driven() {
        assert!(IssuerNotInChain::new().is_construction_driven());
    }
}
