//! SAN `dNSName` syntax lints (CA/Browser Forum BR §7.1.4.2, §3.2.2.4,
//! §3.2.2.6 / RFC 1035 §2.3.4).
//!
//! This module houses **four** [`Lint`](crate::Lint) impls, all
//! [`RuleSource::CabfBr`](crate::RuleSource) and all operating on the SAN
//! `dNSName` strings exposed by [`Cert::san_dns_names`]. Each is broad-scoped:
//! it applies to every non-CA leaf and is
//! [`NotApplicable`](crate::Applicability::NotApplicable) for CA certificates.
//! Each lint emits **one finding per offending name** (the message names it).
//!
//! - [`DnsnameUnderscoreInSld`] — `cabf_br_dnsname_underscore_in_sld`: a label
//!   contains an underscore. (BR §7.1.4.2 / §3.2.2.4)
//! - [`DnsnameBadCharacterInLabel`] — `cabf_br_dnsname_bad_character_in_label`:
//!   a label contains a non-LDH character (anything other than ASCII letters,
//!   digits, or hyphen), allowing `*` only as a whole leftmost wildcard label.
//!   (BR §7.1.4.2)
//! - [`DnsnameLabelTooLong`] — `cabf_br_dnsname_label_too_long`: a DNS label
//!   exceeds 63 octets. (BR §7.1.4.2 / RFC 1035 §2.3.4)
//! - [`DnsnameWildcardLeftOfPublicSuffix`] —
//!   `cabf_br_dnsname_wildcard_left_of_public_suffix`: a bare wildcard of the
//!   form `*.<single-label>` (e.g. `*.com`). (BR §3.2.2.6)
//!
//! # Fail policy
//!
//! As with the rest of the BR family, an accessor `Err` in `check` means
//! "cannot evaluate" → empty `Vec`; an accessor `Err` in `applies` (`is_ca`)
//! means "cannot scope" → `NotApplicable`. No `unwrap`/`expect`/`panic!` on
//! cert data paths.

use super::applies_to_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Maximum length, in octets, of a single DNS label (RFC 1035 §2.3.4).
const MAX_LABEL_OCTETS: usize = 63;

/// Whether `label` is a legal wildcard label: exactly the single character `*`.
fn is_wildcard_label(label: &str) -> bool {
    label == "*"
}

// ---------------------------------------------------------------------------
// 1. Underscore in label
// ---------------------------------------------------------------------------

/// Forbids underscores in any SAN `dNSName` label.
#[derive(Debug, Clone, Default)]
pub struct DnsnameUnderscoreInSld;

impl DnsnameUnderscoreInSld {
    /// Creates the lint.
    pub fn new() -> Self {
        DnsnameUnderscoreInSld
    }
}

/// Pure decision: one [`Finding`] per name containing an underscore in any
/// label.
fn evaluate_underscore(san_dns: &[String]) -> Vec<Finding> {
    san_dns
        .iter()
        .filter(|name| name.split('.').any(|label| label.contains('_')))
        .map(|name| Finding {
            severity: Severity::Error,
            message: format!(
                "Subject Alternative Name dNSName \"{name}\" contains an underscore; \
                 CA/Browser Forum BR §7.1.4.2 / §3.2.2.4 forbids underscores in dNSName labels"
            ),
        })
        .collect()
}

impl Lint for DnsnameUnderscoreInSld {
    fn id(&self) -> &'static str {
        "cabf_br_dnsname_underscore_in_sld"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.san_dns_names() {
            Ok(dns) => evaluate_underscore(&dns),
            Err(_) => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Bad character in label
// ---------------------------------------------------------------------------

/// Forbids non-LDH characters in SAN `dNSName` labels (allowing `*` only as a
/// whole leftmost wildcard label).
#[derive(Debug, Clone, Default)]
pub struct DnsnameBadCharacterInLabel;

impl DnsnameBadCharacterInLabel {
    /// Creates the lint.
    pub fn new() -> Self {
        DnsnameBadCharacterInLabel
    }
}

/// Whether every character in `label` is LDH (ASCII letter, digit, or hyphen).
fn label_is_ldh(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Whether a single SAN `dNSName` is composed only of LDH labels, permitting a
/// single leading `*` wildcard label.
fn name_has_only_ldh_labels(name: &str) -> bool {
    name.split('.').enumerate().all(|(idx, label)| {
        // A whole `*` label is permitted only as the leftmost label.
        if idx == 0 && is_wildcard_label(label) {
            return true;
        }
        label_is_ldh(label)
    })
}

/// Pure decision: one [`Finding`] per name with a non-LDH character in any
/// label.
fn evaluate_bad_character(san_dns: &[String]) -> Vec<Finding> {
    san_dns
        .iter()
        .filter(|name| !name_has_only_ldh_labels(name))
        .map(|name| Finding {
            severity: Severity::Error,
            message: format!(
                "Subject Alternative Name dNSName \"{name}\" contains a non-LDH character; \
                 CA/Browser Forum BR §7.1.4.2 permits only letters, digits, and hyphens in \
                 dNSName labels (with `*` allowed only as a leftmost wildcard label)"
            ),
        })
        .collect()
}

impl Lint for DnsnameBadCharacterInLabel {
    fn id(&self) -> &'static str {
        "cabf_br_dnsname_bad_character_in_label"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.san_dns_names() {
            Ok(dns) => evaluate_bad_character(&dns),
            Err(_) => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Label too long
// ---------------------------------------------------------------------------

/// Forbids SAN `dNSName` labels longer than 63 octets.
#[derive(Debug, Clone, Default)]
pub struct DnsnameLabelTooLong;

impl DnsnameLabelTooLong {
    /// Creates the lint.
    pub fn new() -> Self {
        DnsnameLabelTooLong
    }
}

/// Pure decision: one [`Finding`] per name with any label exceeding 63 octets.
fn evaluate_label_too_long(san_dns: &[String]) -> Vec<Finding> {
    san_dns
        .iter()
        .filter(|name| name.split('.').any(|label| label.len() > MAX_LABEL_OCTETS))
        .map(|name| Finding {
            severity: Severity::Error,
            message: format!(
                "Subject Alternative Name dNSName \"{name}\" has a label longer than \
                 {MAX_LABEL_OCTETS} octets; CA/Browser Forum BR §7.1.4.2 / RFC 1035 §2.3.4 \
                 limit DNS labels to {MAX_LABEL_OCTETS} octets"
            ),
        })
        .collect()
}

impl Lint for DnsnameLabelTooLong {
    fn id(&self) -> &'static str {
        "cabf_br_dnsname_label_too_long"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.san_dns_names() {
            Ok(dns) => evaluate_label_too_long(&dns),
            Err(_) => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Bare wildcard left of public suffix
// ---------------------------------------------------------------------------

/// Forbids a bare wildcard `dNSName` of the form `*.<single-label>` (e.g.
/// `*.com`).
///
/// # Limitation (conservative, dependency-free)
///
/// This lint does **not** consult a Public Suffix List. It flags only the
/// unambiguous bare-wildcard case: a name of exactly **two** labels whose first
/// label is `*` (so the wildcard sits immediately left of a single-label
/// suffix, e.g. `*.com`, `*.local`, `*.xyz`). Multi-label wildcards such as
/// `*.example.com` are intentionally **not** flagged — distinguishing those
/// would require a PSL. This keeps the lint false-positive-safe.
#[derive(Debug, Clone, Default)]
pub struct DnsnameWildcardLeftOfPublicSuffix;

impl DnsnameWildcardLeftOfPublicSuffix {
    /// Creates the lint.
    pub fn new() -> Self {
        DnsnameWildcardLeftOfPublicSuffix
    }
}

/// Whether `name` is a bare wildcard of exactly two labels with `*` first.
fn is_bare_wildcard(name: &str) -> bool {
    let labels: Vec<&str> = name.split('.').collect();
    labels.len() == 2 && is_wildcard_label(labels[0])
}

/// Pure decision: one [`Finding`] per bare-wildcard name.
fn evaluate_bare_wildcard(san_dns: &[String]) -> Vec<Finding> {
    san_dns
        .iter()
        .filter(|name| is_bare_wildcard(name))
        .map(|name| Finding {
            severity: Severity::Error,
            message: format!(
                "Subject Alternative Name dNSName \"{name}\" is a bare wildcard immediately left \
                 of a public suffix; CA/Browser Forum BR §3.2.2.6 forbids wildcards over an \
                 entire top-level/public-suffix label"
            ),
        })
        .collect()
}

impl Lint for DnsnameWildcardLeftOfPublicSuffix {
    fn id(&self) -> &'static str {
        "cabf_br_dnsname_wildcard_left_of_public_suffix"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.san_dns_names() {
            Ok(dns) => evaluate_bare_wildcard(&dns),
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

    mod underscore {
        use super::*;

        #[test]
        fn passes_for_ldh_name() {
            assert!(evaluate_underscore(&[s("good.example.com")]).is_empty());
        }

        #[test]
        fn flags_underscore_in_label() {
            let findings = evaluate_underscore(&[s("foo_bar.example.com")]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("foo_bar.example.com"));
        }

        #[test]
        fn emits_one_finding_per_offending_name() {
            let findings = evaluate_underscore(&[s("a_b.example"), s("c_d.example")]);
            assert_eq!(findings.len(), 2);
        }

        #[test]
        fn has_correct_id_and_source() {
            let lint = DnsnameUnderscoreInSld::new();
            assert_eq!(lint.id(), "cabf_br_dnsname_underscore_in_sld");
            assert_eq!(lint.source(), RuleSource::CabfBr);
        }
    }

    mod bad_character {
        use super::*;

        #[test]
        fn passes_for_ldh_name() {
            assert!(evaluate_bad_character(&[s("good.example.com")]).is_empty());
        }

        #[test]
        fn passes_for_leftmost_wildcard() {
            assert!(evaluate_bad_character(&[s("*.example.com")]).is_empty());
        }

        #[test]
        fn flags_illegal_character() {
            let findings = evaluate_bad_character(&[s("foo!bar.example.com")]);
            assert_eq!(findings.len(), 1);
            assert!(findings[0].message.contains("foo!bar.example.com"));
        }

        #[test]
        fn flags_wildcard_not_at_left() {
            // `*` mid-name is not a legal wildcard label.
            let findings = evaluate_bad_character(&[s("foo.*.example.com")]);
            assert_eq!(findings.len(), 1);
        }

        #[test]
        fn has_correct_id_and_source() {
            let lint = DnsnameBadCharacterInLabel::new();
            assert_eq!(lint.id(), "cabf_br_dnsname_bad_character_in_label");
            assert_eq!(lint.source(), RuleSource::CabfBr);
        }
    }

    mod label_too_long {
        use super::*;

        #[test]
        fn passes_for_short_labels() {
            assert!(evaluate_label_too_long(&[s("good.example.com")]).is_empty());
        }

        #[test]
        fn flags_over_63_octet_label() {
            let long_label = "a".repeat(64);
            let name = format!("{long_label}.example.com");
            let findings = evaluate_label_too_long(std::slice::from_ref(&name));
            assert_eq!(findings.len(), 1);
            assert!(findings[0].message.contains(&name));
        }

        #[test]
        fn passes_for_exactly_63_octet_label() {
            let label = "a".repeat(63);
            let name = format!("{label}.example.com");
            assert!(evaluate_label_too_long(&[name]).is_empty());
        }

        #[test]
        fn has_correct_id_and_source() {
            let lint = DnsnameLabelTooLong::new();
            assert_eq!(lint.id(), "cabf_br_dnsname_label_too_long");
            assert_eq!(lint.source(), RuleSource::CabfBr);
        }
    }

    mod bare_wildcard {
        use super::*;

        #[test]
        fn flags_bare_wildcard() {
            let findings = evaluate_bare_wildcard(&[s("*.com")]);
            assert_eq!(findings.len(), 1);
            assert!(findings[0].message.contains("*.com"));
        }

        #[test]
        fn does_not_flag_multi_label_wildcard() {
            assert!(evaluate_bare_wildcard(&[s("*.example.com")]).is_empty());
        }

        #[test]
        fn does_not_flag_non_wildcard() {
            assert!(evaluate_bare_wildcard(&[s("example.com")]).is_empty());
        }

        #[test]
        fn has_correct_id_and_source() {
            let lint = DnsnameWildcardLeftOfPublicSuffix::new();
            assert_eq!(lint.id(), "cabf_br_dnsname_wildcard_left_of_public_suffix");
            assert_eq!(lint.source(), RuleSource::CabfBr);
        }
    }
}
