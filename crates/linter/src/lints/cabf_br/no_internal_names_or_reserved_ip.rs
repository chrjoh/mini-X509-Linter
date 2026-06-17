//! The `cabf_br_no_internal_names_or_reserved_ip` lint
//! (CA/Browser Forum BR §7.1.4.2 / §4.2.2).
//!
//! The Baseline Requirements forbid issuing publicly-trusted certificates for
//! **Internal Names** or **Reserved IP Addresses** (BR §1.6.1 definitions,
//! enforced under BR §4.2.2 / §7.1.4.2). Each SAN `dNSName` that is an internal
//! name, and each SAN `iPAddress` that is a reserved address, is flagged as a
//! [`Severity::Error`]. The classification lives in [`super::reserved`].
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//! One finding is emitted per offending entry (a SAN may contain several).

use super::applies_to_leaf;
use super::reserved::{is_internal_name, is_reserved_ip};
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Forbids internal/reserved DNS names and reserved IPs in the SAN.
#[derive(Debug, Clone, Default)]
pub struct NoInternalNamesOrReservedIp;

impl NoInternalNamesOrReservedIp {
    /// Creates the lint.
    pub fn new() -> Self {
        NoInternalNamesOrReservedIp
    }
}

/// Pure decision: returns one [`Finding`] per offending SAN entry — internal
/// dNSNames first (in encounter order), then reserved iPAddresses.
///
/// Kept separate from the facade so the policy can be unit-tested with plain
/// string/IP inputs.
fn evaluate(san_dns: &[String], san_ips: &[std::net::IpAddr]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for name in san_dns {
        if is_internal_name(name) {
            findings.push(Finding {
                severity: Severity::Error,
                message: format!(
                    "Subject Alternative Name contains internal/reserved dNSName \"{name}\"; \
                     CA/Browser Forum BR §7.1.4.2 forbids internal names in publicly-trusted \
                     certificates"
                ),
            });
        }
    }

    for ip in san_ips {
        if is_reserved_ip(ip) {
            findings.push(Finding {
                severity: Severity::Error,
                message: format!(
                    "Subject Alternative Name contains reserved iPAddress \"{ip}\"; \
                     CA/Browser Forum BR §4.2.2 forbids reserved IP addresses in \
                     publicly-trusted certificates"
                ),
            });
        }
    }

    findings
}

impl Lint for NoInternalNamesOrReservedIp {
    fn id(&self) -> &'static str {
        "cabf_br_no_internal_names_or_reserved_ip"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: any unreadable accessor means we cannot evaluate; emit
        // nothing (see module docs). Unreachable for a pre-validated `Cert`.
        let san_dns = match cert.san_dns_names() {
            Ok(dns) => dns,
            Err(_) => return Vec::new(),
        };
        let san_ips = match cert.san_ip_addresses() {
            Ok(ips) => ips,
            Err(_) => return Vec::new(),
        };

        evaluate(&san_dns, &san_ips)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;
    use std::net::IpAddr;

    /// Loads a single cert from a workspace `testdata` fixture by file name.
    fn load_fixture(name: &str) -> Cert {
        let path = format!(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/{}"),
            name
        );
        let bytes = std::fs::read(&path).unwrap();
        let mut certs = Cert::from_pem(&bytes).unwrap();
        certs.remove(0)
    }

    fn s(v: &str) -> String {
        v.to_string()
    }

    fn ip(v: &str) -> IpAddr {
        v.parse().unwrap()
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_for_public_names_and_ips() {
            assert!(evaluate(&[s("www.example.com")], &[ip("8.8.8.8")]).is_empty());
        }

        #[test]
        fn flags_internal_name() {
            let findings = evaluate(&[s("db.internal")], &[]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("db.internal"));
        }

        #[test]
        fn flags_reserved_ip() {
            let findings = evaluate(&[], &[ip("10.0.0.1")]);
            assert_eq!(findings.len(), 1);
            assert!(findings[0].message.contains("10.0.0.1"));
        }

        #[test]
        fn emits_one_finding_per_offending_entry() {
            let findings = evaluate(
                &[s("internal.local"), s("public.example.com")],
                &[ip("10.0.0.1"), ip("1.1.1.1")],
            );
            assert_eq!(findings.len(), 2);
        }
    }

    #[test]
    fn not_applicable_for_ca_cert() {
        let cert = load_fixture("rfc5280_ca_bc_not_critical.pem");
        assert_eq!(
            NoInternalNamesOrReservedIp::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = NoInternalNamesOrReservedIp::new();
        assert_eq!(lint.id(), "cabf_br_no_internal_names_or_reserved_ip");
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
