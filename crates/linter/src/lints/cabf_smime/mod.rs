//! CA/Browser Forum S/MIME Baseline Requirements (S/MIME BR) lints.
//!
//! Each submodule holds one [`Lint`](crate::Lint) impl enforcing a single,
//! structurally-checkable requirement from the CA/Browser Forum S/MIME Baseline
//! Requirements, tagged [`RuleSource::CabfSmime`](crate::RuleSource). A curated,
//! high-signal subset (12 lints) modeled on zlint's ~36-lint S/MIME menu: we
//! reimplement, from the S/MIME BR spec, only the rules that are decidable from
//! the encoded certificate via the [`Cert`] facade. The validation-tier
//! (Mailbox / Organization / Sponsor / Individual)
//! and legacy/multipurpose/strict *generation* distinctions turn on out-of-band
//! CA validation state the certificate does not encode, and are out of scope.
//!
//! # Scoping policy (emailProtection-EKU-gated — LOAD-BEARING)
//!
//! Unlike the `cabf_br` family (which scopes broadly to every non-CA leaf),
//! every S/MIME lint here uses an identical, **narrow** gate: it applies only to
//! a certificate that asserts the `emailProtection` EKU (OID
//! `1.3.6.1.5.5.7.3.4`) and is **not** a CA. Concretely each
//! [`applies`](crate::Lint::applies) delegates to [`applies_to_smime_leaf`]:
//!
//! ```text
//! if cert.has_email_protection()? && !cert.is_ca()? { Applies } else { NotApplicable }
//! ```
//!
//! This narrow gate is deliberate (see the feature plan's "Cascade-Avoidance
//! Decision"): it makes every S/MIME lint
//! [`NotApplicable`](crate::Applicability::NotApplicable) on **every existing
//! fixture** — none of the TLS / generic / code-signing / CA fixtures from
//! features 03/04/05/09 assert `emailProtection` — so this feature adds **no**
//! pressure to regenerate any pre-existing fixture.
//!
//! # serverAuth interaction (multipurpose-abuse signal)
//!
//! The `CertPurpose::Auto` resolver gives `serverAuth` precedence over
//! `emailProtection`, so a cert asserting both resolves to `TlsServer`. But when
//! such a cert is linted under the `CabfSmime` source explicitly (e.g.
//! `--source cabf_smime` or `--purpose smime`), [`EkuNoServerAuth`] still fires:
//! an S/MIME EKU MUST NOT also assert `serverAuth`. That is the intended
//! TLS-server-multipurpose-abuse signal.
//!
//! # Fail policy
//!
//! Mirrors the `cabf_br` / `cabf_cs` / `rfc5280` / `hygiene` families:
//!
//! - An accessor `Err` in [`applies`](crate::Lint::applies) (reading the EKU or
//!   `is_ca`) means "cannot scope the rule" → **fail closed** to
//!   [`NotApplicable`](crate::Applicability::NotApplicable) (never manufacture a
//!   false positive).
//! - An accessor `Err` in [`check`](crate::Lint::check) means "cannot evaluate
//!   this rule" → return an empty `Vec` (never fabricate a pass or failure).
//!
//! Each accessor `Err` is handled explicitly (no `unwrap`/`expect`/`panic!`) at
//! the call site.

mod authority_key_identifier_present;
mod crl_distribution_points_http;
mod crl_distribution_points_present;
mod eku_email_protection_present;
mod eku_no_server_auth;
mod email_in_san;
mod key_usage_critical;
mod key_usage_present;
mod san_not_critical;
mod san_present;
mod single_email_subject;
mod subject_country_valid;

pub use authority_key_identifier_present::AuthorityKeyIdentifierPresent;
pub use crl_distribution_points_http::CrlDistributionPointsHttp;
pub use crl_distribution_points_present::CrlDistributionPointsPresent;
pub use eku_email_protection_present::EkuEmailProtectionPresent;
pub use eku_no_server_auth::EkuNoServerAuth;
pub use email_in_san::EmailInSan;
pub use key_usage_critical::KeyUsageCritical;
pub use key_usage_present::KeyUsagePresent;
pub use san_not_critical::SanNotCritical;
pub use san_present::SanPresent;
pub use single_email_subject::SingleEmailSubject;
pub use subject_country_valid::SubjectCountryValid;

use crate::Applicability;
use crate::cert::Cert;

/// Shared emailProtection-EKU gate for every S/MIME lint:
/// [`Applies`](Applicability::Applies) iff the certificate asserts the
/// `emailProtection` EKU (OID `1.3.6.1.5.5.7.3.4`) **and** is not a CA, else
/// [`NotApplicable`](Applicability::NotApplicable).
///
/// Fail policy: if either the EKU or the CA flag cannot be read we cannot scope
/// the rule, so we fail closed to not applicable (see the module-level fail
/// policy). A CA certificate is not an S/MIME end-entity, so it is also out of
/// scope.
fn applies_to_smime_leaf(cert: &Cert) -> Applicability {
    match (cert.has_email_protection(), cert.is_ca()) {
        (Ok(true), Ok(false)) => Applicability::Applies,
        _ => Applicability::NotApplicable,
    }
}
