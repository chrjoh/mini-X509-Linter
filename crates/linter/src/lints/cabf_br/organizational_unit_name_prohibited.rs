//! The `cabf_br_organizational_unit_name_prohibited` lint
//! (CA/Browser Forum BR §7.1.4.2.2).
//!
//! Since 2022-09-01 the Baseline Requirements prohibit the
//! `organizationalUnitName` (OU) attribute in the subject of a publicly-trusted
//! certificate. Any subject containing one or more OU attributes is flagged as a
//! [`Severity::Error`].
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

/// Forbids the `organizationalUnitName` (OU) subject attribute.
#[derive(Debug, Clone, Default)]
pub struct OrganizationalUnitNameProhibited;

impl OrganizationalUnitNameProhibited {
    /// Creates the lint.
    pub fn new() -> Self {
        OrganizationalUnitNameProhibited
    }
}

/// Pure decision: a single [`Finding`] when one or more OU attributes are
/// present, naming the count; empty otherwise.
fn evaluate(ou_count: usize) -> Vec<Finding> {
    if ou_count == 0 {
        return Vec::new();
    }
    vec![Finding {
        severity: Severity::Error,
        message: format!(
            "subject contains {ou_count} organizationalUnitName (OU) attribute(s); \
             CA/Browser Forum BR §7.1.4.2.2 prohibits the OU attribute (since 2022-09-01)"
        ),
    }]
}

impl Lint for OrganizationalUnitNameProhibited {
    fn id(&self) -> &'static str {
        "cabf_br_organizational_unit_name_prohibited"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.subject_organizational_unit_count() {
            Ok(count) => evaluate(count),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_when_no_ou() {
        assert!(evaluate(0).is_empty());
    }

    #[test]
    fn flags_single_ou() {
        let findings = evaluate(1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains('1'));
    }

    #[test]
    fn flags_multiple_ou_with_count() {
        let findings = evaluate(3);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains('3'));
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = OrganizationalUnitNameProhibited::new();
        assert_eq!(lint.id(), "cabf_br_organizational_unit_name_prohibited");
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
