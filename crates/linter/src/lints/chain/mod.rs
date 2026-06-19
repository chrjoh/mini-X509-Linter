//! Chain-aware lints (`RuleSource::Chain`, lint-id prefix `chain_*`).
//!
//! Unlike every other lint family these reason ACROSS certificates — they
//! inspect adjacent `(subject, issuer)` links of a chain built by
//! [`build_chain`](crate::chain::build_chain) rather than a single certificate.
//! They implement the [`ChainLint`](crate::ChainLint) trait and run in the
//! separate chain pass ([`ChainRegistry`](crate::ChainRegistry)).
//!
//! # Two kinds of chain lint
//!
//! - **Construction-driven** ([`SubjectIssuerDnMatch`], [`NotInOrder`],
//!   [`IssuerNotInChain`]): their findings come from the construction
//!   diagnostics that [`build_chain`](crate::chain::build_chain) produces; the
//!   engine injects them. Their pairwise `check` is a no-op (it returns empty)
//!   and the engine skips it ([`ChainLint::is_construction_driven`] returns
//!   `true`). They exist as registry entries so they stay counted and ordered.
//! - **Pairwise link lints** ([`AkiSkiMatch`], [`IssuerIsCa`],
//!   [`PathLenRespected`], [`ValidityNested`], and — under the `verify` feature —
//!   [`SignatureValid`]): each inspects one adjacent link.
//!
//! # Fail policy
//!
//! Every facade accessor returns `Result<_, CertError>`. Following the per-cert
//! lints' precedent, a chain lint treats an accessor `Err` as "cannot evaluate
//! this link" and returns no findings — it never fabricates a pass nor a
//! spurious failure from data it could not read, and never panics.
//!
//! [`ChainLint`]: crate::ChainLint
//! [`ChainLint::is_construction_driven`]: crate::ChainLint::is_construction_driven

mod aki_ski_match;
mod issuer_is_ca;
mod issuer_not_in_chain;
mod not_in_order;
mod path_len_respected;
mod subject_issuer_dn_match;
mod validity_nested;

pub use aki_ski_match::AkiSkiMatch;
pub use issuer_is_ca::IssuerIsCa;
pub use issuer_not_in_chain::IssuerNotInChain;
pub use not_in_order::NotInOrder;
pub use path_len_respected::PathLenRespected;
pub use subject_issuer_dn_match::SubjectIssuerDnMatch;
pub use validity_nested::ValidityNested;

#[cfg(feature = "verify")]
mod subject_signature;
#[cfg(feature = "verify")]
pub mod verify;
#[cfg(feature = "verify")]
pub use subject_signature::SignatureValid;
