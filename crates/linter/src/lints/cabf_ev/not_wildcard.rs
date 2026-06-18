//! The `cabf_ev_not_wildcard` lint (CA/Browser Forum EV Guidelines §9.2.2).
//!
//! EVG §9.2.2: an EV certificate MUST NOT contain a wildcard (`*.`) name in its
//! Subject Alternative Name dNSName entries. Each wildcard dNSName is flagged as
//! a [`Severity::Error`], one finding per offending entry, naming it.
//!
//! EV-scoped (see [`applies_to_ev`]).

use super::applies_to_ev;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Forbids wildcard dNSName entries in an EV certificate's SAN.
#[derive(Debug, Clone, Default)]
pub struct NotWildcard;

impl NotWildcard {
    /// Creates the lint.
    pub fn new() -> Self {
        NotWildcard
    }
}

/// Pure decision: one [`Finding`] per wildcard SAN dNSName entry; empty when
/// none are present. The caller passes only the wildcard entries (the facade's
/// `san_wildcard_dns_names()` already filters), so each input is an offender.
fn evaluate(wildcard_dns_names: &[String]) -> Vec<Finding> {
    wildcard_dns_names
        .iter()
        .map(|name| Finding {
            severity: Severity::Error,
            message: format!(
                "SAN dNSName \"{name}\" is a wildcard; CA/Browser Forum EV Guidelines §9.2.2 \
                 forbids wildcard names in an EV certificate"
            ),
        })
        .collect()
}

impl Lint for NotWildcard {
    fn id(&self) -> &'static str {
        "cabf_ev_not_wildcard"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfEv
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_ev(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable SAN means we cannot evaluate; emit nothing.
        match cert.san_wildcard_dns_names() {
            Ok(names) => evaluate(&names),
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

    fn s(v: &str) -> String {
        v.to_string()
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_when_no_wildcard_entries() {
            assert!(evaluate(&[]).is_empty());
        }

        #[test]
        fn fires_for_wildcard_entry() {
            let findings = evaluate(&[s("*.ev.example.com")]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("*.ev.example.com"));
        }

        #[test]
        fn emits_one_finding_per_wildcard_entry() {
            let findings = evaluate(&[s("*.a.example"), s("*.b.example")]);
            assert_eq!(findings.len(), 2);
        }
    }

    #[test]
    fn not_applicable_for_non_ev_leaf() {
        let cert = good_cert();
        assert_eq!(
            NotWildcard::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = NotWildcard::new();
        assert_eq!(lint.id(), "cabf_ev_not_wildcard");
        assert_eq!(lint.source(), RuleSource::CabfEv);
    }
}
