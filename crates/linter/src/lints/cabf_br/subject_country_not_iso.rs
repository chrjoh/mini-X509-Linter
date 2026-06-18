//! The `cabf_br_subject_country_not_iso` lint (CA/Browser Forum BR §7.1.4.2.2).
//!
//! BR §7.1.4.2.2: if a subject `countryName` (C) attribute is present it MUST be
//! a two-letter ISO 3166-1 alpha-2 country code. The user-assigned code `XX`
//! (used by some CAs when the country cannot be determined) is explicitly
//! allowed. Each country value that is neither a recognised alpha-2 code nor
//! `XX` is flagged as a [`Severity::Error`].
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//! When no country attribute is present there is nothing to check (no finding).
//!
//! # ISO 3166-1 source
//!
//! The valid-code set is a small **in-module allowlist** (no external crate),
//! comprising the ISO 3166-1 alpha-2 codes plus the user-assigned `XX`. The list
//! is hand-maintained from the published ISO 3166-1 standard; this keeps the
//! lint dependency-free. Comparison is ASCII case-insensitive (codes are
//! conventionally uppercase, but we normalise defensively).
//!
//! # Fail policy
//!
//! An accessor `Err` in `check` means "cannot evaluate" → empty `Vec`; an
//! accessor `Err` in `applies` (`is_ca`) means "cannot scope" → `NotApplicable`.

use super::applies_to_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// ISO 3166-1 alpha-2 country codes (current, hand-maintained from the ISO
/// 3166-1 standard) plus the explicitly-allowed user-assigned code `XX`.
const VALID_ALPHA2: &[&str] = &[
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
    "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS",
    "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
    "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
    "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
    "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
    "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM",
    "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
    "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
    "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
    "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
    "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
    "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
    "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
    "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
    "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM",
    "ZW", // user-assigned, allowed by BR practice:
    "XX",
];

/// Whether `code` is a recognised ISO 3166-1 alpha-2 code (or `XX`),
/// case-insensitively.
fn is_valid_country_code(code: &str) -> bool {
    let upper = code.trim().to_ascii_uppercase();
    VALID_ALPHA2.contains(&upper.as_str())
}

/// Requires every subject `countryName` to be a valid ISO 3166-1 alpha-2 code.
#[derive(Debug, Clone, Default)]
pub struct SubjectCountryNotIso;

impl SubjectCountryNotIso {
    /// Creates the lint.
    pub fn new() -> Self {
        SubjectCountryNotIso
    }
}

/// Pure decision: one [`Finding`] per country value that is not a valid alpha-2
/// code; empty when there are no (or only valid) country values.
fn evaluate(countries: &[String]) -> Vec<Finding> {
    countries
        .iter()
        .filter(|code| !is_valid_country_code(code))
        .map(|code| Finding {
            severity: Severity::Error,
            message: format!(
                "subject countryName \"{code}\" is not a valid ISO 3166-1 alpha-2 code; \
                 CA/Browser Forum BR §7.1.4.2.2 requires a two-letter ISO 3166-1 country code"
            ),
        })
        .collect()
}

impl Lint for SubjectCountryNotIso {
    fn id(&self) -> &'static str {
        "cabf_br_subject_country_not_iso"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.subject_country_values() {
            Ok(countries) => evaluate(&countries),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_string()
    }

    #[test]
    fn passes_when_no_country() {
        assert!(evaluate(&[]).is_empty());
    }

    #[test]
    fn passes_for_valid_code() {
        assert!(evaluate(&[s("US")]).is_empty());
    }

    #[test]
    fn passes_for_lowercase_valid_code() {
        assert!(evaluate(&[s("se")]).is_empty());
    }

    #[test]
    fn passes_for_xx() {
        assert!(evaluate(&[s("XX")]).is_empty());
    }

    #[test]
    fn flags_unknown_two_letter_code() {
        let findings = evaluate(&[s("ZZ")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains("ZZ"));
    }

    #[test]
    fn flags_three_letter_code() {
        let findings = evaluate(&[s("USA")]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("USA"));
    }

    #[test]
    fn emits_one_finding_per_offending_value() {
        let findings = evaluate(&[s("ZZ"), s("US"), s("USA")]);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SubjectCountryNotIso::new();
        assert_eq!(lint.id(), "cabf_br_subject_country_not_iso");
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
