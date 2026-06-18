//! The `cabf_ev_san_no_ip_address` lint (CA/Browser Forum EV Guidelines §9.2.2).
//!
//! EVG §9.2.2: an EV certificate MUST NOT contain an `iPAddress` in its Subject
//! Alternative Name extension (EV identity is asserted for legal entities and
//! domain names, not bare IP addresses). Each SAN `iPAddress` entry is flagged
//! as a [`Severity::Error`], one finding per offending address, naming it.
//!
//! EV-scoped (see [`applies_to_ev`]).

use std::net::IpAddr;

use super::applies_to_ev;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Forbids `iPAddress` entries in an EV certificate's SAN.
#[derive(Debug, Clone, Default)]
pub struct SanNoIpAddress;

impl SanNoIpAddress {
    /// Creates the lint.
    pub fn new() -> Self {
        SanNoIpAddress
    }
}

/// Pure decision: one [`Finding`] per SAN `iPAddress` entry; empty when none are
/// present.
fn evaluate(san_ips: &[IpAddr]) -> Vec<Finding> {
    san_ips
        .iter()
        .map(|ip| Finding {
            severity: Severity::Error,
            message: format!(
                "SAN contains iPAddress {ip}; CA/Browser Forum EV Guidelines §9.2.2 forbids an IP \
                 address in an EV certificate"
            ),
        })
        .collect()
}

impl Lint for SanNoIpAddress {
    fn id(&self) -> &'static str {
        "cabf_ev_san_no_ip_address"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfEv
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_ev(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable SAN means we cannot evaluate; emit nothing.
        match cert.san_ip_addresses() {
            Ok(ips) => evaluate(&ips),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    fn good_cert() -> Cert {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
        let bytes = std::fs::read(path).unwrap();
        let mut certs = Cert::from_pem(&bytes).unwrap();
        certs.remove(0)
    }

    fn ip(v: &str) -> IpAddr {
        v.parse().unwrap()
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_when_no_ip_entries() {
            assert!(evaluate(&[]).is_empty());
        }

        #[test]
        fn fires_for_ip_entry() {
            let findings = evaluate(&[ip("192.0.2.10")]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("192.0.2.10"));
        }

        #[test]
        fn emits_one_finding_per_ip_entry() {
            let findings = evaluate(&[ip("192.0.2.10"), ip("2001:db8::1")]);
            assert_eq!(findings.len(), 2);
        }
    }

    #[test]
    fn not_applicable_for_non_ev_leaf() {
        let cert = good_cert();
        assert_eq!(
            SanNoIpAddress::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SanNoIpAddress::new();
        assert_eq!(lint.id(), "cabf_ev_san_no_ip_address");
        assert_eq!(lint.source(), RuleSource::CabfEv);
    }
}
