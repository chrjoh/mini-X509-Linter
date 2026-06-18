//! The provenance of a lint rule: which specification or policy it enforces.

#[cfg(feature = "serde")]
use serde::Serialize;

/// Identifies the authority a [`Lint`](crate::Lint) derives its rule from.
///
/// This is attached to every [`LintOutcome`](crate::LintOutcome) so callers can
/// filter or group findings by the standard they originate from.
///
/// When serialized (with the `serde` feature), variants are rendered in
/// `snake_case` to match the CLI `--source` vocabulary: `rfc5280`, `cabf_br`,
/// `cabf_cs`, `hygiene`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RuleSource {
    /// RFC 5280 — the Internet X.509 Public Key Infrastructure certificate profile.
    Rfc5280,
    /// CA/Browser Forum Baseline Requirements for publicly-trusted certificates.
    CabfBr,
    /// CA/Browser Forum Code-Signing Baseline Requirements.
    CabfCs,
    /// General certificate hygiene that is not mandated by a specific standard
    /// but is widely considered good practice.
    Hygiene,
}
