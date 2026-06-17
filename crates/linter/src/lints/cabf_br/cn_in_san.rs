//! The `cabf_br_cn_in_san` lint (CA/Browser Forum BR §7.1.4.2.2).
//!
//! BR §7.1.4.2.2: the subject `commonName` field, if present, MUST contain a
//! single value that is also one of the values in the Subject Alternative Name
//! extension. (A CN value that does not appear in the SAN is a long-standing
//! source of name-validation confusion, hence the requirement.) Each subject CN
//! value that is not present in the SAN is flagged as a [`Severity::Error`].
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//! If the subject has no CN there is nothing to require, so no finding is
//! emitted. Multiple offending CN values yield one finding each.
//!
//! # Matching policy
//!
//! A CN is satisfied if it matches a SAN entry by either of:
//!
//! - **dNSName**: ASCII case-insensitive equality (DNS names are
//!   case-insensitive; we compare lowercased, after trimming a single trailing
//!   root dot). This is the primary case.
//! - **iPAddress**: when the CN parses as an [`IpAddr`], it is satisfied by a
//!   SAN `iPAddress` entry that is the same address.

use std::net::IpAddr;

use super::applies_to_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires every subject CN value to also appear in the SAN.
#[derive(Debug, Clone, Default)]
pub struct CnInSan;

impl CnInSan {
    /// Creates the lint.
    pub fn new() -> Self {
        CnInSan
    }
}

/// Normalises a dNSName for case-insensitive comparison: trims surrounding
/// whitespace, lowercases ASCII, and drops a single trailing root dot.
fn normalize_dns(name: &str) -> String {
    let trimmed = name.trim().to_ascii_lowercase();
    trimmed.strip_suffix('.').unwrap_or(&trimmed).to_string()
}

/// Pure decision: returns one [`Finding`] per subject CN value that is not
/// present among the SAN dNSName or iPAddress entries.
///
/// Kept separate from the facade so the matching policy can be unit-tested with
/// plain string/IP inputs.
fn evaluate(common_names: &[String], san_dns: &[String], san_ips: &[IpAddr]) -> Vec<Finding> {
    let normalized_dns: Vec<String> = san_dns.iter().map(|n| normalize_dns(n)).collect();

    common_names
        .iter()
        .filter(|cn| !cn_is_in_san(cn, &normalized_dns, san_ips))
        .map(|cn| Finding {
            severity: Severity::Error,
            message: format!(
                "subject commonName \"{cn}\" is not present in the Subject Alternative Name; \
                 CA/Browser Forum BR §7.1.4.2.2 requires every CN value to also appear in the SAN"
            ),
        })
        .collect()
}

/// Whether a single CN value is satisfied by some SAN entry, per the matching
/// policy documented at module level.
fn cn_is_in_san(cn: &str, normalized_san_dns: &[String], san_ips: &[IpAddr]) -> bool {
    // IP-literal CN: satisfied by a matching SAN iPAddress entry.
    if let Ok(cn_ip) = cn.trim().parse::<IpAddr>()
        && san_ips.contains(&cn_ip)
    {
        return true;
    }
    // dNSName CN: ASCII case-insensitive match against a SAN dNSName entry.
    let normalized_cn = normalize_dns(cn);
    normalized_san_dns.contains(&normalized_cn)
}

impl Lint for CnInSan {
    fn id(&self) -> &'static str {
        "cabf_br_cn_in_san"
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
        let common_names = match cert.subject_common_names() {
            Ok(cns) => cns,
            Err(_) => return Vec::new(),
        };
        let san_dns = match cert.san_dns_names() {
            Ok(dns) => dns,
            Err(_) => return Vec::new(),
        };
        let san_ips = match cert.san_ip_addresses() {
            Ok(ips) => ips,
            Err(_) => return Vec::new(),
        };

        evaluate(&common_names, &san_dns, &san_ips)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

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
        fn passes_when_no_common_name() {
            assert!(evaluate(&[], &[s("example.com")], &[]).is_empty());
        }

        #[test]
        fn passes_when_cn_matches_dns_san() {
            assert!(evaluate(&[s("good.example")], &[s("good.example")], &[]).is_empty());
        }

        #[test]
        fn matching_is_case_insensitive_and_root_dot_tolerant() {
            assert!(evaluate(&[s("Good.Example")], &[s("good.example.")], &[]).is_empty());
        }

        #[test]
        fn fires_when_cn_absent_from_san() {
            let findings = evaluate(&[s("cn-missing.example")], &[s("other.example")], &[]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("cn-missing.example"));
        }

        #[test]
        fn emits_one_finding_per_offending_cn() {
            let findings = evaluate(&[s("a.example"), s("b.example")], &[s("c.example")], &[]);
            assert_eq!(findings.len(), 2);
        }

        #[test]
        fn ip_literal_cn_matches_san_ip() {
            assert!(evaluate(&[s("192.0.2.10")], &[], &[ip("192.0.2.10")]).is_empty());
        }

        #[test]
        fn ip_literal_cn_without_matching_san_ip_fires() {
            let findings = evaluate(&[s("192.0.2.10")], &[], &[ip("198.51.100.1")]);
            assert_eq!(findings.len(), 1);
        }
    }

    #[test]
    fn not_applicable_for_ca_cert() {
        let cert = load_fixture("rfc5280_ca_bc_not_critical.pem");
        assert_eq!(CnInSan::new().applies(&cert), Applicability::NotApplicable);
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = CnInSan::new();
        assert_eq!(lint.id(), "cabf_br_cn_in_san");
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
