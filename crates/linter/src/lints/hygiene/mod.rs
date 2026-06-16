//! Certificate hygiene lints.
//!
//! These checks are not mandated by RFC 5280 or the CA/Browser Forum Baseline
//! Requirements; they flag practices that are widely considered undesirable.
//! All lints here report [`RuleSource::Hygiene`](crate::RuleSource::Hygiene).

pub mod not_expired;

pub use not_expired::NotExpired;
