//! Post-quantum signature-algorithm hygiene and structural lints
//! ([`RuleSource::Pqc`](crate::RuleSource::Pqc)).
//!
//! Each submodule holds one [`Lint`](crate::Lint) impl enforcing a single
//! structural / hygiene requirement for the two NIST-standardised post-quantum
//! **signature** families an X.509 certificate can carry in its SPKI and
//! signature `AlgorithmIdentifier`:
//!
//! - **ML-DSA** (Module-Lattice Digital Signature Algorithm) — NIST FIPS 204.
//! - **SLH-DSA** (Stateless Hash-Based Digital Signature Algorithm) — NIST
//!   FIPS 205.
//!
//! The encoding rules these lints enforce (absent `AlgorithmIdentifier.parameters`,
//! mandated public-key length per parameter set, signature-key KeyUsage
//! consistency, recognised parameter set) come from the IETF LAMPS X.509
//! algorithm-identifier profiles for ML-DSA / SLH-DSA (RFC number **TBC** — not
//! hard-coded in any lint doc) on top of FIPS 204 / FIPS 205. They are
//! algorithm-structure checks, **not** CA/Browser Forum Baseline-Requirements
//! checks.
//!
//! # Scoping policy (PQC-SPKI-gated — LOAD-BEARING)
//!
//! [`RuleSource::Pqc`](crate::RuleSource::Pqc) is a **universal** source (folded
//! into every certificate purpose's allowed-source set, like
//! [`Rfc5280`](crate::RuleSource::Rfc5280) and
//! [`Hygiene`](crate::RuleSource::Hygiene)). Universality only controls which
//! filter buckets these lints appear in — each lint still **self-gates** in
//! [`applies`](crate::Lint::applies) via the shared [`applies_to_pqc`] helper: it
//! returns [`Applies`](crate::Applicability::Applies) only when the certificate's
//! SPKI algorithm is an ML-DSA or SLH-DSA arc member (any parameter set,
//! **including the unknown-arc-member case** so `pqc_algorithm_known` can fire),
//! and [`NotApplicable`](crate::Applicability::NotApplicable) for every classical
//! (RSA / EC) or `Other` key. This self-gate is what keeps the universal source
//! from cascading onto any existing RSA/EC fixture (see the feature 13 plan,
//! "THE KEY DESIGN DECISION").
//!
//! # Fail policy
//!
//! Mirrors the `cabf_cs` / `cabf_br` / `rfc5280` / `hygiene` families:
//!
//! - An accessor `Err` in [`applies`](crate::Lint::applies) (reading the SPKI
//!   algorithm) means "cannot scope the rule" → **fail closed** to
//!   [`NotApplicable`](crate::Applicability::NotApplicable) (never manufacture a
//!   false positive).
//! - An accessor `Err` in [`check`](crate::Lint::check) means "cannot evaluate
//!   this rule" → return an empty `Vec` (never fabricate a pass or failure).
//!
//! Each accessor `Err` is handled explicitly (no `unwrap`/`expect`/`panic!`).

mod algorithm_known;
mod kem_params;
mod key_usage_consistency;
mod mlkem_algorithm_known;
mod mlkem_key_usage_consistency;
mod mlkem_public_key_length;
mod mlkem_spki_parameters_absent;
mod params;
mod public_key_length;
mod signature_parameters_absent;
mod spki_parameters_absent;

pub use algorithm_known::AlgorithmKnown;
pub use key_usage_consistency::KeyUsageConsistency;
pub use mlkem_algorithm_known::MlKemAlgorithmKnown;
pub use mlkem_key_usage_consistency::MlKemKeyUsageConsistency;
pub use mlkem_public_key_length::MlKemPublicKeyLength;
pub use mlkem_spki_parameters_absent::MlKemSpkiParametersAbsent;
pub use public_key_length::PublicKeyLength;
pub use signature_parameters_absent::SignatureParametersAbsent;
pub use spki_parameters_absent::SpkiParametersAbsent;

use crate::Applicability;
use crate::cert::{Cert, PublicKeyAlg};

/// Shared PQC-SPKI gate for every `pqc` lint:
/// [`Applies`](Applicability::Applies) iff the certificate's SPKI algorithm is an
/// ML-DSA or SLH-DSA arc member (any parameter set, **including**
/// [`PqcParamSet::Unknown`](crate::cert::PqcParamSet::Unknown) so
/// `pqc_algorithm_known` can fire through the registry), else
/// [`NotApplicable`](Applicability::NotApplicable).
///
/// Fail policy: if the SPKI algorithm cannot be read we cannot scope the rule, so
/// we fail closed to not applicable (see the module-level fail policy).
fn applies_to_pqc(cert: &Cert) -> Applicability {
    match cert.public_key_algorithm() {
        Ok(PublicKeyAlg::MlDsa(_)) | Ok(PublicKeyAlg::SlhDsa(_)) => Applicability::Applies,
        // Rsa / Ec / MlKem / Other, or an unreadable SPKI algorithm → not in scope.
        Ok(_) | Err(_) => Applicability::NotApplicable,
    }
}

/// Shared ML-KEM-SPKI gate for every `mlkem` lint:
/// [`Applies`](Applicability::Applies) iff the certificate's SPKI algorithm is an
/// ML-KEM "kems" arc member (any parameter set, **including**
/// [`PqcParamSet::Unknown`](crate::cert::PqcParamSet::Unknown) so
/// `pqc_mlkem_algorithm_known` can fire through the registry), else
/// [`NotApplicable`](Applicability::NotApplicable). The signature gate
/// [`applies_to_pqc`] never admits an ML-KEM key, so the two PQC families self-gate
/// independently.
///
/// Fail policy: if the SPKI algorithm cannot be read we cannot scope the rule, so
/// we fail closed to not applicable (see the module-level fail policy).
fn applies_to_mlkem(cert: &Cert) -> Applicability {
    match cert.public_key_algorithm() {
        Ok(PublicKeyAlg::MlKem(_)) => Applicability::Applies,
        // Rsa / Ec / MlDsa / SlhDsa / Other, or an unreadable SPKI algorithm →
        // not in scope.
        Ok(_) | Err(_) => Applicability::NotApplicable,
    }
}
