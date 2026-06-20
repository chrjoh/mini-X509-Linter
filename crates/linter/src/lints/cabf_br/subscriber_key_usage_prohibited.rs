//! The `cabf_br_subscriber_key_usage_cert_sign_prohibited` and
//! `cabf_br_subscriber_key_usage_crl_sign_prohibited` lints
//! (CA/Browser Forum BR §7.1.2.7).
//!
//! BR §7.1.2.7 (subscriber-certificate KeyUsage) constrains which KeyUsage bits
//! a subscriber (non-CA leaf) certificate may assert. Two bits are CA-only and
//! MUST NOT appear in a subscriber certificate:
//!
//! - `keyCertSign` (bit 5) — meaningful only for a certificate-signing CA
//!   (RFC 5280 §4.2.1.3); a subscriber asserting it is flagged
//!   [`Severity::Error`] by [`SubscriberKeyUsageCertSignProhibited`].
//! - `cRLSign` (bit 6) — meaningful only for a CRL-signing CA; a subscriber
//!   asserting it is flagged [`Severity::Error`] by
//!   [`SubscriberKeyUsageCrlSignProhibited`].
//!
//! These two sibling rules live in the same file because they share one clause,
//! one accessor, and one shape.
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//! When no KeyUsage extension is present there is nothing to constrain, so each
//! rule produces no finding.
//!
//! # Fail policy
//!
//! An accessor `Err` in `check` means "cannot evaluate" → empty `Vec`; an
//! accessor `Err` in `applies` (`is_ca`) means "cannot scope" → `NotApplicable`.

use super::applies_to_leaf;
use crate::cert::{Cert, KeyUsageView};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Forbids the `keyCertSign` KeyUsage bit on a subscriber certificate.
#[derive(Debug, Clone, Default)]
pub struct SubscriberKeyUsageCertSignProhibited;

impl SubscriberKeyUsageCertSignProhibited {
    /// Creates the lint.
    pub fn new() -> Self {
        SubscriberKeyUsageCertSignProhibited
    }
}

/// Forbids the `cRLSign` KeyUsage bit on a subscriber certificate.
#[derive(Debug, Clone, Default)]
pub struct SubscriberKeyUsageCrlSignProhibited;

impl SubscriberKeyUsageCrlSignProhibited {
    /// Creates the lint.
    pub fn new() -> Self {
        SubscriberKeyUsageCrlSignProhibited
    }
}

/// Pure decision for the `keyCertSign` rule: one [`Finding`] when the bit is
/// asserted, none otherwise. `view` is `None` when no KeyUsage extension exists.
fn evaluate_cert_sign(view: Option<&KeyUsageView>) -> Vec<Finding> {
    match view {
        Some(ku) if ku.key_cert_sign => vec![Finding {
            severity: Severity::Error,
            message: "certificate asserts the keyCertSign KeyUsage bit; \
                      CA/Browser Forum BR §7.1.2.7 prohibits it on a subscriber \
                      (non-CA) certificate (keyCertSign is a CA-only bit)"
                .to_string(),
        }],
        _ => Vec::new(),
    }
}

/// Pure decision for the `cRLSign` rule: one [`Finding`] when the bit is
/// asserted, none otherwise. `view` is `None` when no KeyUsage extension exists.
fn evaluate_crl_sign(view: Option<&KeyUsageView>) -> Vec<Finding> {
    match view {
        Some(ku) if ku.crl_sign => vec![Finding {
            severity: Severity::Error,
            message: "certificate asserts the cRLSign KeyUsage bit; \
                      CA/Browser Forum BR §7.1.2.7 prohibits it on a subscriber \
                      (non-CA) certificate (cRLSign is a CA-only bit)"
                .to_string(),
        }],
        _ => Vec::new(),
    }
}

impl Lint for SubscriberKeyUsageCertSignProhibited {
    fn id(&self) -> &'static str {
        "cabf_br_subscriber_key_usage_cert_sign_prohibited"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.key_usage() {
            Ok(view) => evaluate_cert_sign(view.as_ref()),
            Err(_) => Vec::new(),
        }
    }
}

impl Lint for SubscriberKeyUsageCrlSignProhibited {
    fn id(&self) -> &'static str {
        "cabf_br_subscriber_key_usage_crl_sign_prohibited"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.key_usage() {
            Ok(view) => evaluate_crl_sign(view.as_ref()),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a `KeyUsageView` with all bits clear except those set explicitly.
    fn ku(key_cert_sign: bool, crl_sign: bool) -> KeyUsageView {
        KeyUsageView {
            digital_signature: true,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            key_cert_sign,
            crl_sign,
            encipher_only: false,
            decipher_only: false,
            critical: true,
        }
    }

    mod cert_sign {
        use super::*;

        #[test]
        fn passes_when_no_key_usage_extension() {
            assert!(evaluate_cert_sign(None).is_empty());
        }

        #[test]
        fn passes_when_cert_sign_clear() {
            assert!(evaluate_cert_sign(Some(&ku(false, false))).is_empty());
        }

        #[test]
        fn fires_when_cert_sign_set() {
            let findings = evaluate_cert_sign(Some(&ku(true, false)));
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("keyCertSign"));
        }

        #[test]
        fn ignores_crl_sign_bit() {
            assert!(evaluate_cert_sign(Some(&ku(false, true))).is_empty());
        }

        #[test]
        fn has_correct_id_and_source() {
            let lint = SubscriberKeyUsageCertSignProhibited::new();
            assert_eq!(
                lint.id(),
                "cabf_br_subscriber_key_usage_cert_sign_prohibited"
            );
            assert_eq!(lint.source(), RuleSource::CabfBr);
        }
    }

    mod crl_sign {
        use super::*;

        #[test]
        fn passes_when_no_key_usage_extension() {
            assert!(evaluate_crl_sign(None).is_empty());
        }

        #[test]
        fn passes_when_crl_sign_clear() {
            assert!(evaluate_crl_sign(Some(&ku(false, false))).is_empty());
        }

        #[test]
        fn fires_when_crl_sign_set() {
            let findings = evaluate_crl_sign(Some(&ku(false, true)));
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("cRLSign"));
        }

        #[test]
        fn ignores_cert_sign_bit() {
            assert!(evaluate_crl_sign(Some(&ku(true, false))).is_empty());
        }

        #[test]
        fn has_correct_id_and_source() {
            let lint = SubscriberKeyUsageCrlSignProhibited::new();
            assert_eq!(
                lint.id(),
                "cabf_br_subscriber_key_usage_crl_sign_prohibited"
            );
            assert_eq!(lint.source(), RuleSource::CabfBr);
        }
    }
}
