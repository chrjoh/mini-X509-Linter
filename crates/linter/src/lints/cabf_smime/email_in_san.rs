//! The `cabf_smime_email_in_san` lint (CA/Browser Forum S/MIME BR §7.1.4.2.1).
//!
//! S/MIME BR §7.1.4.2.1: every subject `commonName` that is an email address
//! MUST also appear as an `rfc822Name` in the Subject Alternative Name
//! extension. Each email-shaped CN that is absent from the SAN's `rfc822Name`
//! set is flagged as a [`Severity::Error`] (one finding per offending CN).
//!
//! Non-email CNs (those without an `@`) are ignored: this lint only governs the
//! email-in-CN-must-also-be-in-SAN requirement, not general CN-in-SAN.
//!
//! # Matching policy
//!
//! An email address is split at the last `@` into a local part and a domain
//! part. The **local part** is compared case-sensitively (per RFC 5321 the local
//! part is, in general, case-sensitive) and the **domain part** is compared
//! ASCII case-insensitively (DNS domains are case-insensitive). A CN is
//! satisfied when some SAN `rfc822Name` matches under that policy.
//!
//! emailProtection-EKU-gated (see [`applies_to_smime_leaf`]).

use super::applies_to_smime_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires every email-shaped subject CN to appear as a SAN `rfc822Name`.
#[derive(Debug, Clone, Default)]
pub struct EmailInSan;

impl EmailInSan {
    /// Creates the lint.
    pub fn new() -> Self {
        EmailInSan
    }
}

/// Normalises an email address for comparison: trims surrounding whitespace,
/// leaves the local part as-is, and lowercases the domain part (after the last
/// `@`). An address with no `@` is returned trimmed unchanged.
fn normalize_email(addr: &str) -> String {
    let trimmed = addr.trim();
    match trimmed.rsplit_once('@') {
        Some((local, domain)) => format!("{local}@{}", domain.to_ascii_lowercase()),
        None => trimmed.to_string(),
    }
}

/// Pure decision: one [`Finding`] per email-shaped CN not present among the SAN
/// `rfc822Name` entries (under the documented matching policy).
///
/// Kept separate so the matching policy can be unit-tested with plain strings.
fn evaluate(common_names: &[String], san_emails: &[String]) -> Vec<Finding> {
    let normalized_san: Vec<String> = san_emails.iter().map(|e| normalize_email(e)).collect();

    common_names
        .iter()
        .filter(|cn| cn.contains('@'))
        .filter(|cn| !normalized_san.contains(&normalize_email(cn)))
        .map(|cn| Finding {
            severity: Severity::Error,
            message: format!(
                "subject commonName \"{cn}\" is an email address not present as an rfc822Name in \
                 the Subject Alternative Name; CA/Browser Forum S/MIME BR §7.1.4.2.1 requires it \
                 to also appear in the SAN"
            ),
        })
        .collect()
}

impl Lint for EmailInSan {
    fn id(&self) -> &'static str {
        "cabf_smime_email_in_san"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfSmime
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_smime_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: any unreadable accessor means we cannot evaluate; emit
        // nothing.
        let common_names = match cert.subject_common_names() {
            Ok(cns) => cns,
            Err(_) => return Vec::new(),
        };
        let san_emails = match cert.san_rfc822_names() {
            Ok(emails) => emails,
            Err(_) => return Vec::new(),
        };
        evaluate(&common_names, &san_emails)
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
        fn passes_when_no_common_name() {
            assert!(evaluate(&[], &[s("user@example.com")]).is_empty());
        }

        #[test]
        fn passes_when_cn_is_not_email() {
            assert!(evaluate(&[s("Acme Inc")], &[]).is_empty());
        }

        #[test]
        fn passes_when_email_cn_in_san() {
            assert!(evaluate(&[s("user@example.com")], &[s("user@example.com")]).is_empty());
        }

        #[test]
        fn domain_match_is_case_insensitive() {
            assert!(evaluate(&[s("user@Example.COM")], &[s("user@example.com")]).is_empty());
        }

        #[test]
        fn local_part_match_is_case_sensitive() {
            let findings = evaluate(&[s("User@example.com")], &[s("user@example.com")]);
            assert_eq!(findings.len(), 1);
        }

        #[test]
        fn fires_when_email_cn_absent_from_san() {
            let findings = evaluate(&[s("user@example.com")], &[s("other@example.com")]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("user@example.com"));
        }

        #[test]
        fn emits_one_finding_per_offending_cn() {
            let findings = evaluate(&[s("a@example.com"), s("b@example.com")], &[]);
            assert_eq!(findings.len(), 2);
        }
    }

    #[test]
    fn not_applicable_for_non_smime_leaf() {
        let cert = good_cert();
        assert_eq!(
            EmailInSan::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = EmailInSan::new();
        assert_eq!(lint.id(), "cabf_smime_email_in_san");
        assert_eq!(lint.source(), RuleSource::CabfSmime);
    }
}
