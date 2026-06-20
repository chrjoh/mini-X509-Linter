//! The `cabf_br_subscriber_basic_constraints_path_len_prohibited` lint
//! (CA/Browser Forum BR §7.1.2.7 / RFC 5280 §4.2.1.9).
//!
//! A `pathLenConstraint` in BasicConstraints is meaningful only for a CA
//! certificate (RFC 5280 §4.2.1.9 permits it only when `cA = TRUE` and the
//! `keyCertSign` bit is asserted). A subscriber (non-CA leaf) certificate MUST
//! NOT include a `pathLenConstraint`; any such leaf is flagged
//! [`Severity::Error`].
//!
//! This is the **BR-scoped** sibling of feature-12's RFC-sourced
//! `rfc5280_path_len_constraint_improperly_included`. The two intentionally
//! co-fire on the same path-len-on-leaf fixture by construction (distinct
//! sources / ids / clauses); reconciling that co-fire is the tester's concern.
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//! When no BasicConstraints extension is present there is no `pathLenConstraint`
//! to flag, so the rule produces no finding.
//!
//! # Fail policy
//!
//! An accessor `Err` in `check` means "cannot evaluate" → empty `Vec`; an
//! accessor `Err` in `applies` (`is_ca`) means "cannot scope" → `NotApplicable`.

use super::applies_to_leaf;
use crate::cert::{BasicConstraintsView, Cert};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Forbids a `pathLenConstraint` on a subscriber (non-CA) certificate.
#[derive(Debug, Clone, Default)]
pub struct SubscriberBasicConstraintsPathLenProhibited;

impl SubscriberBasicConstraintsPathLenProhibited {
    /// Creates the lint.
    pub fn new() -> Self {
        SubscriberBasicConstraintsPathLenProhibited
    }
}

/// Pure decision: one [`Finding`] when BasicConstraints carries a
/// `pathLenConstraint`, none otherwise. `view` is `None` when the extension is
/// absent.
fn evaluate(view: Option<&BasicConstraintsView>) -> Vec<Finding> {
    match view.and_then(|bc| bc.path_len) {
        Some(path_len) => vec![Finding {
            severity: Severity::Error,
            message: format!(
                "BasicConstraints includes pathLenConstraint:{path_len} on a subscriber \
                 (non-CA) certificate; CA/Browser Forum BR §7.1.2.7 / RFC 5280 §4.2.1.9 \
                 permit pathLenConstraint only for a CA (cA=TRUE with keyCertSign)"
            ),
        }],
        None => Vec::new(),
    }
}

impl Lint for SubscriberBasicConstraintsPathLenProhibited {
    fn id(&self) -> &'static str {
        "cabf_br_subscriber_basic_constraints_path_len_prohibited"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.basic_constraints() {
            Ok(view) => evaluate(view.as_ref()),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bc(path_len: Option<u32>) -> BasicConstraintsView {
        BasicConstraintsView {
            is_ca: false,
            path_len,
            critical: false,
        }
    }

    #[test]
    fn passes_when_no_basic_constraints() {
        assert!(evaluate(None).is_empty());
    }

    #[test]
    fn passes_when_no_path_len() {
        assert!(evaluate(Some(&bc(None))).is_empty());
    }

    #[test]
    fn fires_when_path_len_present() {
        let findings = evaluate(Some(&bc(Some(0))));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains("pathLenConstraint"));
    }

    #[test]
    fn names_the_path_len_value() {
        let findings = evaluate(Some(&bc(Some(3))));
        assert!(findings[0].message.contains('3'));
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SubscriberBasicConstraintsPathLenProhibited::new();
        assert_eq!(
            lint.id(),
            "cabf_br_subscriber_basic_constraints_path_len_prohibited"
        );
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
