//! CA/Browser Forum Extended Validation (EV) Guidelines lints.
//!
//! Each submodule holds one [`Lint`](crate::Lint) impl enforcing a single,
//! structurally-checkable requirement from the CA/Browser Forum EV Guidelines,
//! tagged [`RuleSource::CabfEv`](crate::RuleSource). EV is the stricter
//! identity-assurance profile layered on top of the Baseline Requirements
//! (EV ⊂ BR ⊂ RFC 5280): an EV cert carries verified legal-entity identity in
//! the subject DN and asserts a recognized EV policy OID. A curated,
//! high-signal subset (9 lints) of zlint's EV menu is ported here.
//!
//! # Scoping policy (EV-policy-OID self-gated — LOAD-BEARING)
//!
//! EV is **not** identified by an EKU. A leaf is "EV" because it asserts a
//! recognized EV certificate policy OID (see [`policy::EV_POLICY_OIDS`]) on top
//! of being a normal `serverAuth` TLS leaf. Every EV lint here uses an
//! identical gate via [`applies_to_ev`], which delegates to [`is_ev_scope`]:
//!
//! ```text
//! is_ev_scope = has_server_auth()? == true
//!               && any certificate_policy_oids()? is in EV_POLICY_OIDS
//! applies = if is_ev_scope { Applies } else { NotApplicable }
//! ```
//!
//! This self-gating is deliberate and is what keeps every EV lint
//! [`NotApplicable`](crate::Applicability::NotApplicable) on **every existing
//! fixture**: `good.pem` and the other TLS/BR/RFC/hygiene fixtures are non-EV
//! TLS leaves (no EV policy OID), so this feature adds **no** pressure to
//! regenerate any pre-existing fixture (no cascade). An EV cert sees them all
//! `Applies`. (See the feature plan's "EV-scope self-gating ⇒ NO cascade".)
//!
//! # Fail policy
//!
//! Mirrors the `cabf_br` / `cabf_cs` / `cabf_smime` / `rfc5280` / `hygiene`
//! families:
//!
//! - An accessor `Err` in [`applies`](crate::Lint::applies) (reading the EKU or
//!   the policy OIDs) means "cannot scope the rule" → **fail closed** to
//!   [`NotApplicable`](crate::Applicability::NotApplicable). A parse failure
//!   must never manufacture an EV finding.
//! - An accessor `Err` in [`check`](crate::Lint::check) means "cannot evaluate
//!   this rule" → return an empty `Vec` (never fabricate a pass or failure).
//!
//! Each accessor `Err` is handled explicitly (no `unwrap`/`expect`/`panic!`) at
//! the call site.

pub mod policy;

mod business_category_invalid;
mod business_category_missing;
mod jurisdiction_country_missing;
mod not_wildcard;
mod organization_id_present;
mod organization_name_missing;
mod san_no_ip_address;
mod serial_number_missing;
mod validity_max_398_days;

pub use business_category_invalid::BusinessCategoryInvalid;
pub use business_category_missing::BusinessCategoryMissing;
pub use jurisdiction_country_missing::JurisdictionCountryMissing;
pub use not_wildcard::NotWildcard;
pub use organization_id_present::OrganizationIdPresent;
pub use organization_name_missing::OrganizationNameMissing;
pub use san_no_ip_address::SanNoIpAddress;
pub use serial_number_missing::SerialNumberMissing;
pub use validity_max_398_days::ValidityMax398Days;

use crate::Applicability;
use crate::cert::Cert;

/// Returns `true` if `cert` is in **EV scope**: it is a `serverAuth` TLS leaf
/// **and** asserts at least one recognized EV policy OID (see
/// [`policy::EV_POLICY_OIDS`]).
///
/// Fail-closed: if either [`Cert::has_server_auth`] or
/// [`Cert::certificate_policy_oids`] returns `Err`, the certificate is treated
/// as *not* EV (a parse failure must never manufacture an EV finding). A cert
/// asserting only unrecognized (DV/OV) policy OIDs is likewise not in EV scope.
fn is_ev_scope(cert: &Cert) -> bool {
    let has_server_auth = matches!(cert.has_server_auth(), Ok(true));
    if !has_server_auth {
        return false;
    }
    match cert.certificate_policy_oids() {
        Ok(oids) => oids.iter().any(|oid| policy::is_ev_policy(oid)),
        Err(_) => false,
    }
}

/// Shared EV-scope gate for every EV lint:
/// [`Applies`](Applicability::Applies) iff [`is_ev_scope`] is true, else
/// [`NotApplicable`](Applicability::NotApplicable).
///
/// See the module-level scoping and fail policies.
fn applies_to_ev(cert: &Cert) -> Applicability {
    if is_ev_scope(cert) {
        Applicability::Applies
    } else {
        Applicability::NotApplicable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn good_pem_is_not_in_ev_scope() {
        // good.pem is a serverAuth TLS leaf with no EV policy OID.
        let cert = load_fixture("good.pem");
        assert!(!is_ev_scope(&cert));
        assert_eq!(applies_to_ev(&cert), Applicability::NotApplicable);
    }
}
