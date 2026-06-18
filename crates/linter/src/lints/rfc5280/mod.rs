//! RFC 5280 structural lints.
//!
//! Each submodule holds one [`Lint`](crate::Lint) impl enforcing a single
//! requirement from RFC 5280, tagged [`RuleSource::Rfc5280`](crate::RuleSource).
//! These are hard-failure structural checks (mostly [`Severity::Error`]) as
//! opposed to the informational checks in the `hygiene` family.
//!
//! # Fail policy
//!
//! Every facade accessor returns `Result<_, CertError>`, but a [`Cert`](crate::Cert)
//! can only be constructed from already-parsed, structurally valid DER, so a
//! re-parse error in an accessor is effectively unreachable. Following the
//! project's fail-safe stance (A10: do not silently mask problems) **and** the
//! `hygiene_not_expired` precedent, these lints treat an accessor `Err` as
//! "cannot evaluate this rule" and return no findings — they never fabricate a
//! pass nor a spurious failure from data they could not read. Each accessor
//! `Err` is handled explicitly (no `unwrap`/`expect`) at the call site.

mod basic_constraints_critical_on_ca;
mod key_usage_present_when_ca;
mod san_present_if_subject_empty;
mod serial_number_positive;
mod validity_window;
mod version_is_v3;

// Feature 12: RFC 5280 depth-expansion lints (appended after the original six).
mod ca_subject_field_empty;
mod ext_authority_key_identifier_no_key_identifier;
mod ext_key_usage_without_bits;
mod ext_name_constraints_not_critical;
mod ext_san_no_entries;
mod path_len_constraint_improperly_included;
mod subject_dn_country_not_printable_string;
mod subject_key_identifier_presence;
mod utc_time_not_in_zulu;

pub use basic_constraints_critical_on_ca::BasicConstraintsCriticalOnCa;
pub use key_usage_present_when_ca::KeyUsagePresentWhenCa;
pub use san_present_if_subject_empty::SanPresentIfSubjectEmpty;
pub use serial_number_positive::SerialNumberPositive;
pub use validity_window::ValidityNotAfterAfterNotBefore;
pub use version_is_v3::VersionIsV3;

// Feature 12 re-exports.
pub use ca_subject_field_empty::CaSubjectFieldEmpty;
pub use ext_authority_key_identifier_no_key_identifier::ExtAuthorityKeyIdentifierNoKeyIdentifier;
pub use ext_key_usage_without_bits::ExtKeyUsageWithoutBits;
pub use ext_name_constraints_not_critical::ExtNameConstraintsNotCritical;
pub use ext_san_no_entries::ExtSanNoEntries;
pub use path_len_constraint_improperly_included::PathLenConstraintImproperlyIncluded;
pub use subject_dn_country_not_printable_string::SubjectDnCountryNotPrintableString;
pub use subject_key_identifier_presence::{
    ExtSubjectKeyIdentifierMissingCa, ExtSubjectKeyIdentifierMissingSubCert,
};
pub use utc_time_not_in_zulu::UtcTimeNotInZulu;
