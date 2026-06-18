//! CA/Browser Forum Baseline Requirements (BR) lints.
//!
//! Each submodule holds one [`Lint`](crate::Lint) impl enforcing a single
//! web-PKI requirement from the CA/Browser Forum Baseline Requirements, tagged
//! [`RuleSource::CabfBr`](crate::RuleSource). All four are
//! [`Severity::Error`](crate::Severity::Error) checks.
//!
//! The [`reserved`] submodule is the single, well-cited classifier for
//! internal/reserved DNS names and reserved IP addresses; the
//! `no_internal_names_or_reserved_ip` lint delegates to it.
//!
//! # Scoping policy (BROAD — load-bearing)
//!
//! Every BR lint here uses identical, **broad** scoping: it applies to **every
//! non-CA leaf certificate**, regardless of EKU, and is
//! [`NotApplicable`](crate::Applicability::NotApplicable) for CA certificates.
//! Concretely each [`applies`](crate::Lint::applies) is:
//!
//! ```text
//! if cert.is_ca() { NotApplicable } else { Applies }
//! ```
//!
//! The lints are deliberately **NOT** EKU-gated: a TLS-intended leaf that forgot
//! `serverAuth` is still in scope (and is flagged by
//! [`ExtKeyUsageServerAuthPresent`], not skipped). This makes the missing-EKU
//! lint meaningful and keeps `applies()` trivial and uniform.
//!
//! # Fail policy
//!
//! Every facade accessor returns `Result<_, CertError>`, but a [`Cert`](crate::Cert)
//! can only be constructed from already-parsed, structurally valid DER, so a
//! re-parse error in an accessor is effectively unreachable. Following the same
//! fail-safe stance as the `rfc5280` and `hygiene` families:
//!
//! - An accessor `Err` in [`check`](crate::Lint::check) means "cannot evaluate
//!   this rule" → return an empty `Vec` (never fabricate a pass or a spurious
//!   failure).
//! - An accessor `Err` in [`applies`](crate::Lint::applies) (here, `is_ca()`)
//!   means "cannot scope the rule" → return
//!   [`NotApplicable`](crate::Applicability::NotApplicable).
//!
//! Each accessor `Err` is handled explicitly (no `unwrap`/`expect`) at the call
//! site.

pub mod reserved;

mod cn_in_san;
mod ext_key_usage_server_auth_present;
mod no_internal_names_or_reserved_ip;
mod validity_max_398_days;

// Feature 12: BR depth-expansion lints (all broad-scoped, RuleSource::CabfBr).
mod dnsname_syntax;
mod extra_subject_common_names;
mod organizational_unit_name_prohibited;
mod subject_contains_reserved_ip;
mod subject_country_not_iso;

pub use cn_in_san::CnInSan;
pub use ext_key_usage_server_auth_present::ExtKeyUsageServerAuthPresent;
pub use no_internal_names_or_reserved_ip::NoInternalNamesOrReservedIp;
pub use validity_max_398_days::ValidityMax398Days;

pub use dnsname_syntax::{
    DnsnameBadCharacterInLabel, DnsnameLabelTooLong, DnsnameUnderscoreInSld,
    DnsnameWildcardLeftOfPublicSuffix,
};
pub use extra_subject_common_names::ExtraSubjectCommonNames;
pub use organizational_unit_name_prohibited::OrganizationalUnitNameProhibited;
pub use subject_contains_reserved_ip::SubjectContainsReservedIp;
pub use subject_country_not_iso::SubjectCountryNotIso;

use crate::Applicability;
use crate::cert::Cert;

/// Shared broad-scoping decision for every BR lint: a CA certificate is
/// [`NotApplicable`](Applicability::NotApplicable); every non-CA leaf
/// [`Applies`](Applicability::Applies).
///
/// Fail policy: if `is_ca()` cannot be read we cannot scope the rule, so we
/// treat it as not applicable (see the module-level fail policy).
fn applies_to_leaf(cert: &Cert) -> Applicability {
    match cert.is_ca() {
        Ok(false) => Applicability::Applies,
        Ok(true) | Err(_) => Applicability::NotApplicable,
    }
}
