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

pub use basic_constraints_critical_on_ca::BasicConstraintsCriticalOnCa;
pub use key_usage_present_when_ca::KeyUsagePresentWhenCa;
pub use san_present_if_subject_empty::SanPresentIfSubjectEmpty;
pub use serial_number_positive::SerialNumberPositive;
pub use validity_window::ValidityNotAfterAfterNotBefore;
pub use version_is_v3::VersionIsV3;
