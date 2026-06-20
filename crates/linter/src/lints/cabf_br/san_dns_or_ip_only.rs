//! The `cabf_br_san_dns_or_ip_only` lint (CA/Browser Forum BR §7.1.2.7.12).
//!
//! BR §7.1.2.7.12 constrains the contents of a subscriber TLS certificate's
//! Subject Alternative Name extension: every entry MUST be a `dNSName` or an
//! `iPAddress` GeneralName. Other GeneralName types (`rfc822Name`/email, `URI`,
//! `directoryName`, `otherName`, etc.) are prohibited. One [`Severity::Error`]
//! is emitted per offending entry, naming the entry's kind and value.
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//! When no SAN extension is present there are no entries to check, so the rule
//! produces no finding.
//!
//! # Fail policy
//!
//! An accessor `Err` in `check` means "cannot evaluate" → empty `Vec`; an
//! accessor `Err` in `applies` (`is_ca`) means "cannot scope" → `NotApplicable`.

use super::applies_to_leaf;
use crate::cert::{Cert, GeneralNameView};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// The two permitted SAN entry kinds (the [`GeneralNameView::kind`] short
/// labels used by the facade).
const ALLOWED_KINDS: [&str; 2] = ["DNS", "IP"];

/// Forbids SAN entries that are not `dNSName` or `iPAddress`.
#[derive(Debug, Clone, Default)]
pub struct SanDnsOrIpOnly;

impl SanDnsOrIpOnly {
    /// Creates the lint.
    pub fn new() -> Self {
        SanDnsOrIpOnly
    }
}

/// Pure decision: one [`Finding`] per SAN entry whose kind is not `DNS` or `IP`.
fn evaluate(entries: &[GeneralNameView]) -> Vec<Finding> {
    entries
        .iter()
        .filter(|e| !ALLOWED_KINDS.contains(&e.kind.as_str()))
        .map(|e| Finding {
            severity: Severity::Error,
            message: format!(
                "Subject Alternative Name contains a prohibited entry kind \"{}\" \
                 (value \"{}\"); CA/Browser Forum BR §7.1.2.7.12 permits only \
                 dNSName and iPAddress entries in a subscriber TLS certificate",
                e.kind, e.value
            ),
        })
        .collect()
}

impl Lint for SanDnsOrIpOnly {
    fn id(&self) -> &'static str {
        "cabf_br_san_dns_or_ip_only"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.san_entries() {
            Ok(Some(san)) => evaluate(&san.entries),
            Ok(None) | Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gn(kind: &str, value: &str) -> GeneralNameView {
        GeneralNameView {
            kind: kind.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn passes_for_dns_and_ip_entries() {
        let entries = [gn("DNS", "good.example.com"), gn("IP", "192.0.2.1")];
        assert!(evaluate(&entries).is_empty());
    }

    #[test]
    fn passes_for_empty_entries() {
        assert!(evaluate(&[]).is_empty());
    }

    #[test]
    fn fires_for_email_entry() {
        let entries = [gn("DNS", "good.example.com"), gn("email", "a@example.com")];
        let findings = evaluate(&entries);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains("email"));
        assert!(findings[0].message.contains("a@example.com"));
    }

    #[test]
    fn emits_one_finding_per_offending_entry() {
        let entries = [
            gn("DNS", "good.example.com"),
            gn("URI", "https://example.com/"),
            gn("DirName", "CN=Example"),
        ];
        assert_eq!(evaluate(&entries).len(), 2);
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SanDnsOrIpOnly::new();
        assert_eq!(lint.id(), "cabf_br_san_dns_or_ip_only");
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
