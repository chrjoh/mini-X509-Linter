//! The `cabf_smime_subject_country_valid` lint
//! (CA/Browser Forum S/MIME BR §7.1.4.2).
//!
//! S/MIME BR §7.1.4.2: if a subject `countryName` (C) attribute is present it
//! MUST be a two-letter (ISO 3166-1 alpha-2-shaped) value. Each country value
//! that is not exactly two ASCII letters is flagged as a [`Severity::Error`]
//! (one finding per offending value).
//!
//! If no country attribute is present there is nothing to check (the attribute
//! is optional), so no finding is emitted.
//!
//! # Validation policy
//!
//! This is a *shape* check only: the value must be exactly two ASCII alphabetic
//! characters. It does NOT verify membership in the ISO 3166-1 code list — that
//! stronger check lives in the BR `cabf_br_subject_country_not_iso` lint. (The
//! S/MIME BR text requires the two-letter shape; the registered-code check is
//! left to the BR set so the two rule sets stay independently meaningful.)
//!
//! emailProtection-EKU-gated (see [`applies_to_smime_leaf`]).

use super::applies_to_smime_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires every subject `countryName` to be exactly two ASCII letters.
#[derive(Debug, Clone, Default)]
pub struct SubjectCountryValid;

impl SubjectCountryValid {
    /// Creates the lint.
    pub fn new() -> Self {
        SubjectCountryValid
    }
}

/// Whether `value` is exactly two ASCII alphabetic characters.
fn is_two_letter(value: &str) -> bool {
    value.len() == 2 && value.bytes().all(|b| b.is_ascii_alphabetic())
}

/// Pure decision: one [`Finding`] per country value that is not exactly two
/// ASCII letters; empty when there are no (or only valid-shaped) values.
///
/// Kept separate so the shape policy can be unit-tested with plain strings.
fn evaluate(countries: &[String]) -> Vec<Finding> {
    countries
        .iter()
        .filter(|value| !is_two_letter(value))
        .map(|value| Finding {
            severity: Severity::Error,
            message: format!(
                "subject countryName \"{value}\" is not a two-letter value; CA/Browser Forum \
                 S/MIME BR §7.1.4.2 requires an ISO 3166-1 alpha-2-shaped (two-letter) country code"
            ),
        })
        .collect()
}

impl Lint for SubjectCountryValid {
    fn id(&self) -> &'static str {
        "cabf_smime_subject_country_valid"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfSmime
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_smime_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable subject means we cannot evaluate; emit
        // nothing.
        match cert.subject_country_names() {
            Ok(countries) => evaluate(&countries),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    fn good_cert() -> Cert {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
        let bytes = std::fs::read(path).unwrap();
        let mut certs = Cert::from_pem(&bytes).unwrap();
        certs.remove(0)
    }

    fn s(v: &str) -> String {
        v.to_string()
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_when_no_country() {
            assert!(evaluate(&[]).is_empty());
        }

        #[test]
        fn passes_for_two_letter_value() {
            assert!(evaluate(&[s("US")]).is_empty());
        }

        #[test]
        fn fires_for_three_letter_value() {
            let findings = evaluate(&[s("USA")]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("USA"));
        }

        #[test]
        fn fires_for_one_letter_value() {
            assert_eq!(evaluate(&[s("U")]).len(), 1);
        }

        #[test]
        fn fires_for_two_char_non_alpha_value() {
            assert_eq!(evaluate(&[s("U1")]).len(), 1);
        }

        #[test]
        fn emits_one_finding_per_offending_value() {
            let findings = evaluate(&[s("USA"), s("US"), s("XYZ")]);
            assert_eq!(findings.len(), 2);
        }
    }

    #[test]
    fn not_applicable_for_non_smime_leaf() {
        let cert = good_cert();
        assert_eq!(
            SubjectCountryValid::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SubjectCountryValid::new();
        assert_eq!(lint.id(), "cabf_smime_subject_country_valid");
        assert_eq!(lint.source(), RuleSource::CabfSmime);
    }
}
