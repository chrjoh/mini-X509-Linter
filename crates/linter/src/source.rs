//! The provenance of a lint rule: which specification or policy it enforces.

#[cfg(feature = "serde")]
use serde::Serialize;

/// Identifies the authority a [`Lint`](crate::Lint) derives its rule from.
///
/// This is attached to every [`LintOutcome`](crate::LintOutcome) so callers can
/// filter or group findings by the standard they originate from.
///
/// When serialized (with the `serde` feature), variants are rendered in
/// `snake_case` to match the CLI `--source` vocabulary: `rfc5280`, `pqc`,
/// `cabf_br`, `cabf_ev`, `cabf_cs`, `cabf_smime`, `hygiene`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RuleSource {
    /// RFC 5280 — the Internet X.509 Public Key Infrastructure certificate profile.
    Rfc5280,
    /// Post-quantum (ML-DSA / SLH-DSA) signature-algorithm hygiene and structural
    /// checks — a universal, non-CABF source. Like [`Rfc5280`](RuleSource::Rfc5280)
    /// and [`Hygiene`](RuleSource::Hygiene) it is folded into every certificate
    /// purpose's allowed-source set; its lints self-gate on the SPKI algorithm
    /// being ML-DSA / SLH-DSA, so they stay silent on classical (RSA/EC) keys.
    Pqc,
    /// CA/Browser Forum Baseline Requirements for publicly-trusted certificates.
    CabfBr,
    /// CA/Browser Forum Extended Validation (EV) Guidelines — the stricter
    /// identity-assurance profile layered on top of the Baseline Requirements
    /// for TLS-server certificates that assert a recognized EV policy OID.
    CabfEv,
    /// CA/Browser Forum Code-Signing Baseline Requirements.
    CabfCs,
    /// CA/Browser Forum S/MIME Baseline Requirements for email-protection
    /// (S/MIME) certificates.
    CabfSmime,
    /// General certificate hygiene that is not mandated by a specific standard
    /// but is widely considered good practice.
    Hygiene,
}
