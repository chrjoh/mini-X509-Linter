//! The `cabf_br_extra_subject_common_names` lint
//! (CA/Browser Forum BR §7.1.4.2.2).
//!
//! BR §7.1.4.2.2: the subject `commonName` field, if present, MUST contain a
//! single value. A subject carrying more than one `commonName` attribute is
//! flagged as a [`Severity::Error`] (the message names the count).
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//! A subject with zero or exactly one CN passes.
//!
//! # Fail policy
//!
//! An accessor `Err` in `check` means "cannot evaluate" → empty `Vec`; an
//! accessor `Err` in `applies` (`is_ca`) means "cannot scope" → `NotApplicable`.

use super::applies_to_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Forbids more than one `commonName` attribute in the subject.
#[derive(Debug, Clone, Default)]
pub struct ExtraSubjectCommonNames;

impl ExtraSubjectCommonNames {
    /// Creates the lint.
    pub fn new() -> Self {
        ExtraSubjectCommonNames
    }
}

/// Pure decision: a single [`Finding`] when more than one CN is present,
/// naming the count; empty for zero or one.
fn evaluate(cn_count: usize) -> Vec<Finding> {
    if cn_count <= 1 {
        return Vec::new();
    }
    vec![Finding {
        severity: Severity::Error,
        message: format!(
            "subject contains {cn_count} commonName attributes; \
             CA/Browser Forum BR §7.1.4.2.2 permits at most one commonName"
        ),
    }]
}

impl Lint for ExtraSubjectCommonNames {
    fn id(&self) -> &'static str {
        "cabf_br_extra_subject_common_names"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.subject_common_names() {
            Ok(cns) => evaluate(cns.len()),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_with_no_cn() {
        assert!(evaluate(0).is_empty());
    }

    #[test]
    fn passes_with_single_cn() {
        assert!(evaluate(1).is_empty());
    }

    #[test]
    fn flags_two_cns_with_count() {
        let findings = evaluate(2);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains('2'));
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = ExtraSubjectCommonNames::new();
        assert_eq!(lint.id(), "cabf_br_extra_subject_common_names");
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
