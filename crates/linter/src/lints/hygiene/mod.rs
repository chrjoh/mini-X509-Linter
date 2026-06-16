//! Certificate hygiene lints.
//!
//! These checks are not mandated by RFC 5280 or the CA/Browser Forum Baseline
//! Requirements; they flag practices that are widely considered undesirable.
//! All lints here report [`RuleSource::Hygiene`](crate::RuleSource::Hygiene).

pub mod ecdsa_curve_allowlist;
pub mod no_sha1_signature;
pub mod not_expired;
pub mod rsa_key_min_2048;

pub use ecdsa_curve_allowlist::EcdsaCurveAllowlist;
pub use no_sha1_signature::NoSha1Signature;
pub use not_expired::NotExpired;
pub use rsa_key_min_2048::RsaKeyMin2048;
