//! The `cabf_br_basic_constraints_present` lint (CA/Browser Forum BR §7.1.2.7.8).
//!
//! BR §7.1.2.7.8 requires a subscriber TLS certificate to include a
//! BasicConstraints extension (with `cA = FALSE`). A non-CA leaf with no
//! BasicConstraints extension is flagged.
//!
//! # Severity (load-bearing): `Warn`, not `Error`
//!
//! This rule is deliberately [`Severity::Warn`] (defence-in-depth) so that, under
//! the BR family's broad scoping, it never adds a second *Error* to any existing
//! leaf fixture that happens to omit BasicConstraints — preserving the
//! single-Error isolation tests (see the feature-17 Cascade-Management strategy).
//! The canonical `good.pem` carries BasicConstraints (`CA:FALSE`) and PASSES.
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//!
//! # Fail policy
//!
//! An accessor `Err` in `check` means "cannot evaluate" → empty `Vec`; an
//! accessor `Err` in `applies` (`is_ca`) means "cannot scope" → `NotApplicable`.

use super::applies_to_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires a BasicConstraints extension on a subscriber certificate.
#[derive(Debug, Clone, Default)]
pub struct BasicConstraintsPresent;

impl BasicConstraintsPresent {
    /// Creates the lint.
    pub fn new() -> Self {
        BasicConstraintsPresent
    }
}

/// Pure decision: one [`Severity::Warn`] [`Finding`] when no BasicConstraints
/// extension is present, none otherwise.
fn evaluate(has_basic_constraints: bool) -> Vec<Finding> {
    if has_basic_constraints {
        Vec::new()
    } else {
        vec![Finding {
            severity: Severity::Warn,
            message: "certificate has no BasicConstraints extension; \
                      CA/Browser Forum BR §7.1.2.7.8 requires it (with cA=FALSE) in a \
                      subscriber TLS certificate"
                .to_string(),
        }]
    }
}

impl Lint for BasicConstraintsPresent {
    fn id(&self) -> &'static str {
        "cabf_br_basic_constraints_present"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.basic_constraints() {
            Ok(view) => evaluate(view.is_some()),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_when_basic_constraints_present() {
        assert!(evaluate(true).is_empty());
    }

    #[test]
    fn warns_when_basic_constraints_absent() {
        let findings = evaluate(false);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0].message.contains("BasicConstraints"));
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = BasicConstraintsPresent::new();
        assert_eq!(lint.id(), "cabf_br_basic_constraints_present");
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
