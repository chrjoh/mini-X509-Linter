//! The `chain_not_in_order` chain lint (RFC 5280 §6.1 chain ordering).
//!
//! A Notice emitted when the presented certificates DO form one linear chain but
//! the input order differed from leaf→root, so they were reordered for analysis.
//! This is informational — NOT an error: a complete, correctly-linked chain that
//! merely arrived in the wrong file/presentation order is still a valid chain.
//! The reorder is recorded so the link labels follow the BUILT order.
//!
//! This is a **construction-driven** lint: its finding is injected by the chain
//! engine from the [`Disorder`](crate::chain::ConstructionDiagnostic::Disorder)
//! diagnostic, not from a pairwise `check` (which is a no-op and never called).

use crate::cert::Cert;
use crate::{ChainLint, Finding, RuleSource};

/// Notices that a complete chain was presented out of leaf-to-root order
/// (construction-driven).
#[derive(Debug, Clone, Default)]
pub struct NotInOrder;

impl NotInOrder {
    /// Creates the lint.
    pub fn new() -> Self {
        NotInOrder
    }
}

impl ChainLint for NotInOrder {
    fn id(&self) -> &'static str {
        "chain_not_in_order"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Chain
    }

    /// No-op: the finding is injected by the engine from the `Disorder`
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
        let lint = NotInOrder::new();
        assert_eq!(lint.id(), "chain_not_in_order");
        assert_eq!(lint.source(), RuleSource::Chain);
    }

    #[test]
    fn is_construction_driven() {
        assert!(NotInOrder::new().is_construction_driven());
    }
}
