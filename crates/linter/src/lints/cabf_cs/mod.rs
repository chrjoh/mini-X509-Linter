//! CA/Browser Forum Code-Signing Baseline Requirements (CS BR) lints.
//!
//! Each submodule holds one [`Lint`](crate::Lint) impl enforcing a single
//! requirement from the CA/Browser Forum Code-Signing Baseline Requirements,
//! tagged [`RuleSource::CabfCs`](crate::RuleSource). A curated, high-signal
//! subset of zlint's `lint_cs_*` menu (8 lints) rather than the full catalogue.
//!
//! # Scoping policy (codeSigning-EKU-gated — LOAD-BEARING)
//!
//! Unlike the `cabf_br` family (which scopes broadly to every non-CA leaf),
//! every CS lint here uses an identical, **narrow** gate: it applies only to a
//! certificate that asserts the `codeSigning` EKU (OID `1.3.6.1.5.5.7.3.3`).
//! Concretely each [`applies`](crate::Lint::applies) is:
//!
//! ```text
//! if cert.has_code_signing()? { Applies } else { NotApplicable }
//! ```
//!
//! This narrow gate is deliberate: it makes every CS lint
//! [`NotApplicable`](crate::Applicability::NotApplicable) on every existing
//! TLS / generic / hygiene fixture (none assert `codeSigning`), so this feature
//! adds **no** pressure to regenerate any existing fixture. See the feature
//! plan's "Critical Design Decision".
//!
//! # Fail policy
//!
//! Mirrors the `cabf_br` / `rfc5280` / `hygiene` families:
//!
//! - An accessor `Err` in [`applies`](crate::Lint::applies) (reading the EKU)
//!   means "cannot scope the rule" → **fail closed** to
//!   [`NotApplicable`](crate::Applicability::NotApplicable) (never manufacture a
//!   false positive).
//! - An accessor `Err` in [`check`](crate::Lint::check) means "cannot evaluate
//!   this rule" → return an empty `Vec` (never fabricate a pass or failure).
//!
//! Each accessor `Err` is handled explicitly (no `unwrap`/`expect`/`panic!`) at
//! the call site.

mod authority_information_access;
mod crl_distribution_points;
mod ecdsa_curve_params;
mod eku_required;
mod key_usage_required;
mod rsa_key_size;
mod validity_period_longer_than_39_months;
mod validity_period_longer_than_460_days;

pub use authority_information_access::AuthorityInformationAccess;
pub use crl_distribution_points::CrlDistributionPoints;
pub use ecdsa_curve_params::EcdsaCurveParams;
pub use eku_required::EkuRequired;
pub use key_usage_required::KeyUsageRequired;
pub use rsa_key_size::RsaKeySize;
pub use validity_period_longer_than_39_months::ValidityPeriodLongerThan39Months;
pub use validity_period_longer_than_460_days::ValidityPeriodLongerThan460Days;

use crate::Applicability;
use crate::cert::Cert;

/// Shared codeSigning-EKU gate for every CS lint:
/// [`Applies`](Applicability::Applies) iff the certificate asserts the
/// `codeSigning` EKU (OID `1.3.6.1.5.5.7.3.3`), else
/// [`NotApplicable`](Applicability::NotApplicable).
///
/// Fail policy: if the EKU cannot be read we cannot scope the rule, so we fail
/// closed to not applicable (see the module-level fail policy).
fn applies_to_code_signing(cert: &Cert) -> Applicability {
    match cert.has_code_signing() {
        Ok(true) => Applicability::Applies,
        Ok(false) | Err(_) => Applicability::NotApplicable,
    }
}
