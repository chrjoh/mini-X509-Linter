//! The provenance of a lint rule: which specification or policy it enforces.

/// Identifies the authority a [`Lint`](crate::Lint) derives its rule from.
///
/// This is attached to every [`LintOutcome`](crate::LintOutcome) so callers can
/// filter or group findings by the standard they originate from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSource {
    /// RFC 5280 — the Internet X.509 Public Key Infrastructure certificate profile.
    Rfc5280,
    /// CA/Browser Forum Baseline Requirements for publicly-trusted certificates.
    CabfBr,
    /// General certificate hygiene that is not mandated by a specific standard
    /// but is widely considered good practice.
    Hygiene,
}
