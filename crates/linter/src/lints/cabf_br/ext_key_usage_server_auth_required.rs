//! The `cabf_br_ext_key_usage_server_auth_required` lint
//! (CA/Browser Forum BR §7.1.2.7.6).
//!
//! BR §7.1.2.7.6 requires that, **when** a subscriber TLS certificate carries an
//! Extended Key Usage extension, that EKU MUST include `id-kp-serverAuth`
//! (OID `1.3.6.1.5.5.7.3.1`). An EKU that is present but lists only other
//! purposes (e.g. `clientAuth` alone) is flagged [`Severity::Error`].
//!
//! # Distinct surface from `cabf_br_ext_key_usage_server_auth_present`
//!
//! This rule deliberately differs from the existing
//! [`ExtKeyUsageServerAuthPresent`](super::ExtKeyUsageServerAuthPresent), which
//! flags the **EKU-absent** case (a leaf with no EKU at all). THIS rule flags the
//! **EKU-present-but-no-serverAuth** case and is silent when the EKU extension is
//! absent. The two share intent but cover different surfaces; on an
//! EKU-present-without-serverAuth fixture they co-fire by construction, which the
//! tester reconciles as a documented two-rule assertion.
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//!
//! # Fail policy
//!
//! An accessor `Err` in `check` means "cannot evaluate" → empty `Vec`; an
//! accessor `Err` in `applies` (`is_ca`) means "cannot scope" → `NotApplicable`.

use super::applies_to_leaf;
use crate::cert::{Cert, EkuView};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires `serverAuth` in a present subscriber EKU extension.
#[derive(Debug, Clone, Default)]
pub struct ExtKeyUsageServerAuthRequired;

impl ExtKeyUsageServerAuthRequired {
    /// Creates the lint.
    pub fn new() -> Self {
        ExtKeyUsageServerAuthRequired
    }
}

/// Pure decision: one [`Finding`] when the EKU extension is present but does not
/// assert `serverAuth`. Silent when the EKU is absent (`view` is `None`) — that
/// case is owned by [`ExtKeyUsageServerAuthPresent`](super::ExtKeyUsageServerAuthPresent).
fn evaluate(view: Option<&EkuView>) -> Vec<Finding> {
    match view {
        Some(eku) if !eku.server_auth => vec![Finding {
            severity: Severity::Error,
            message: "Extended Key Usage is present but does not assert serverAuth \
                      (OID 1.3.6.1.5.5.7.3.1); CA/Browser Forum BR §7.1.2.7.6 requires \
                      a subscriber TLS certificate's EKU to include serverAuth"
                .to_string(),
        }],
        _ => Vec::new(),
    }
}

impl Lint for ExtKeyUsageServerAuthRequired {
    fn id(&self) -> &'static str {
        "cabf_br_ext_key_usage_server_auth_required"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.extended_key_usage() {
            Ok(view) => evaluate(view.as_ref()),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eku(server_auth: bool, oids: &[&str]) -> EkuView {
        EkuView {
            present: true,
            critical: false,
            server_auth,
            client_auth: oids.contains(&"1.3.6.1.5.5.7.3.2"),
            code_signing: false,
            email_protection: false,
            is_empty: oids.is_empty(),
            oids: oids.iter().map(|o| o.to_string()).collect(),
        }
    }

    #[test]
    fn passes_when_eku_absent() {
        // The EKU-absent case is owned by the sibling lint, not this one.
        assert!(evaluate(None).is_empty());
    }

    #[test]
    fn passes_when_server_auth_present() {
        assert!(evaluate(Some(&eku(true, &["1.3.6.1.5.5.7.3.1"]))).is_empty());
    }

    #[test]
    fn fires_when_eku_present_without_server_auth() {
        let findings = evaluate(Some(&eku(false, &["1.3.6.1.5.5.7.3.2"])));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains("serverAuth"));
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = ExtKeyUsageServerAuthRequired::new();
        assert_eq!(lint.id(), "cabf_br_ext_key_usage_server_auth_required");
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
