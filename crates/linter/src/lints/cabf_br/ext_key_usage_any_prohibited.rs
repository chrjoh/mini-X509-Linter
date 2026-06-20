//! The `cabf_br_ext_key_usage_any_prohibited` lint
//! (CA/Browser Forum BR §7.1.2.7.6).
//!
//! BR §7.1.2.7.6 specifies that a subscriber TLS certificate's Extended Key
//! Usage MUST contain `id-kp-serverAuth` and MAY contain `id-kp-clientAuth`; the
//! over-broad `anyExtendedKeyUsage` purpose (OID `2.5.29.37.0`) is prohibited
//! because it grants every key purpose. A subscriber EKU asserting `anyEKU` is
//! flagged [`Severity::Error`].
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//! When no EKU extension is present there is nothing to constrain, so the rule
//! produces no finding.
//!
//! # Fail policy
//!
//! An accessor `Err` in `check` means "cannot evaluate" → empty `Vec`; an
//! accessor `Err` in `applies` (`is_ca`) means "cannot scope" → `NotApplicable`.

use super::applies_to_leaf;
use crate::cert::{Cert, EkuView};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// The `anyExtendedKeyUsage` key-purpose OID (RFC 5280 §4.2.1.12).
const ANY_EXTENDED_KEY_USAGE_OID: &str = "2.5.29.37.0";

/// Forbids the `anyExtendedKeyUsage` purpose in a subscriber EKU.
#[derive(Debug, Clone, Default)]
pub struct ExtKeyUsageAnyProhibited;

impl ExtKeyUsageAnyProhibited {
    /// Creates the lint.
    pub fn new() -> Self {
        ExtKeyUsageAnyProhibited
    }
}

/// Pure decision: one [`Finding`] when the EKU lists `anyExtendedKeyUsage`, none
/// otherwise. `view` is `None` when no EKU extension exists.
fn evaluate(view: Option<&EkuView>) -> Vec<Finding> {
    let asserts_any =
        view.is_some_and(|eku| eku.oids.iter().any(|oid| oid == ANY_EXTENDED_KEY_USAGE_OID));
    if asserts_any {
        vec![Finding {
            severity: Severity::Error,
            message: format!(
                "Extended Key Usage asserts anyExtendedKeyUsage (OID \
                 {ANY_EXTENDED_KEY_USAGE_OID}); CA/Browser Forum BR §7.1.2.7.6 \
                 prohibits it in a subscriber TLS certificate"
            ),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for ExtKeyUsageAnyProhibited {
    fn id(&self) -> &'static str {
        "cabf_br_ext_key_usage_any_prohibited"
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

    fn eku(oids: &[&str]) -> EkuView {
        EkuView {
            present: true,
            critical: false,
            server_auth: oids.contains(&"1.3.6.1.5.5.7.3.1"),
            client_auth: false,
            code_signing: false,
            email_protection: false,
            is_empty: oids.is_empty(),
            oids: oids.iter().map(|o| o.to_string()).collect(),
        }
    }

    #[test]
    fn passes_when_no_eku_extension() {
        assert!(evaluate(None).is_empty());
    }

    #[test]
    fn passes_when_server_auth_only() {
        assert!(evaluate(Some(&eku(&["1.3.6.1.5.5.7.3.1"]))).is_empty());
    }

    #[test]
    fn fires_when_any_eku_present() {
        let findings = evaluate(Some(&eku(&[
            "1.3.6.1.5.5.7.3.1",
            ANY_EXTENDED_KEY_USAGE_OID,
        ])));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains(ANY_EXTENDED_KEY_USAGE_OID));
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = ExtKeyUsageAnyProhibited::new();
        assert_eq!(lint.id(), "cabf_br_ext_key_usage_any_prohibited");
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
