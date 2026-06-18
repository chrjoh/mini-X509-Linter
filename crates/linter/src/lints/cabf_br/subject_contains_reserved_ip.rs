//! The `cabf_br_subject_contains_reserved_ip` lint (CA/Browser Forum BR §4.2.2).
//!
//! The Baseline Requirements forbid publicly-trusted certificates for Reserved
//! IP Addresses (BR §1.6.1 definitions, enforced under BR §4.2.2). This lint
//! checks the subject **commonName**: each CN value that parses as an
//! [`IpAddr`](std::net::IpAddr) and is classified reserved by
//! [`super::reserved::is_reserved_ip`] is flagged as a [`Severity::Error`].
//!
//! This complements the existing `cabf_br_no_internal_names_or_reserved_ip`,
//! which checks **SAN** entries; this lint covers the distinct **CN** surface.
//! A CN that is a DNS name (not an IP literal) is ignored here.
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//! One finding is emitted per offending CN.
//!
//! # Fail policy
//!
//! An accessor `Err` in `check` means "cannot evaluate" → empty `Vec`; an
//! accessor `Err` in `applies` (`is_ca`) means "cannot scope" → `NotApplicable`.

use std::net::IpAddr;

use super::applies_to_leaf;
use super::reserved::is_reserved_ip;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Forbids a subject CN that is a reserved/internal IP address.
#[derive(Debug, Clone, Default)]
pub struct SubjectContainsReservedIp;

impl SubjectContainsReservedIp {
    /// Creates the lint.
    pub fn new() -> Self {
        SubjectContainsReservedIp
    }
}

/// Pure decision: one [`Finding`] per CN value that parses as an IP and is
/// reserved. CN values that are not IP literals are ignored.
fn evaluate(common_names: &[String]) -> Vec<Finding> {
    common_names
        .iter()
        .filter_map(|cn| {
            let ip: IpAddr = cn.trim().parse().ok()?;
            is_reserved_ip(&ip).then(|| Finding {
                severity: Severity::Error,
                message: format!(
                    "subject commonName \"{cn}\" is a reserved/internal IP address; \
                     CA/Browser Forum BR §4.2.2 forbids reserved IP addresses in \
                     publicly-trusted certificates"
                ),
            })
        })
        .collect()
}

impl Lint for SubjectContainsReservedIp {
    fn id(&self) -> &'static str {
        "cabf_br_subject_contains_reserved_ip"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.subject_common_names() {
            Ok(cns) => evaluate(&cns),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_string()
    }

    #[test]
    fn passes_for_dns_name_cn() {
        assert!(evaluate(&[s("good.example.com")]).is_empty());
    }

    #[test]
    fn passes_for_public_ip_cn() {
        assert!(evaluate(&[s("8.8.8.8")]).is_empty());
    }

    #[test]
    fn flags_reserved_ipv4_cn() {
        let findings = evaluate(&[s("10.0.0.1")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains("10.0.0.1"));
    }

    #[test]
    fn emits_one_finding_per_offending_cn() {
        let findings = evaluate(&[s("10.0.0.1"), s("192.168.0.1"), s("good.example.com")]);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SubjectContainsReservedIp::new();
        assert_eq!(lint.id(), "cabf_br_subject_contains_reserved_ip");
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
