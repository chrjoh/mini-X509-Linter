//! The `cabf_br_san_present` lint (CA/Browser Forum BR §7.1.2.7.12).
//!
//! BR §7.1.2.7.12 requires a subscriber TLS certificate to include a Subject
//! Alternative Name extension (the modern source of identity, superseding the
//! subject commonName). A non-CA leaf with no SAN extension is flagged.
//!
//! # Severity (load-bearing): `Warn`, not `Error`
//!
//! This rule is deliberately [`Severity::Warn`]. Under the BR family's broad
//! scoping it runs on every existing non-CA leaf fixture, including a deliberate
//! no-SAN deviation fixture whose single-Error isolation test must be preserved.
//! Shipping this as a `Warn` keeps it from adding a second *Error* to any such
//! fixture (see the feature-17 Cascade-Management strategy).
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

/// Requires a Subject Alternative Name extension on a subscriber certificate.
#[derive(Debug, Clone, Default)]
pub struct SanPresent;

impl SanPresent {
    /// Creates the lint.
    pub fn new() -> Self {
        SanPresent
    }
}

/// Pure decision: one [`Severity::Warn`] [`Finding`] when no SAN extension is
/// present, none otherwise.
fn evaluate(has_san: bool) -> Vec<Finding> {
    if has_san {
        Vec::new()
    } else {
        vec![Finding {
            severity: Severity::Warn,
            message: "certificate has no Subject Alternative Name extension; \
                      CA/Browser Forum BR §7.1.2.7.12 requires SAN in a subscriber \
                      TLS certificate"
                .to_string(),
        }]
    }
}

impl Lint for SanPresent {
    fn id(&self) -> &'static str {
        "cabf_br_san_present"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.subject_alt_name() {
            Ok(view) => evaluate(view.is_some()),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_when_san_present() {
        assert!(evaluate(true).is_empty());
    }

    #[test]
    fn warns_when_san_absent() {
        let findings = evaluate(false);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0].message.contains("Subject Alternative Name"));
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SanPresent::new();
        assert_eq!(lint.id(), "cabf_br_san_present");
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
