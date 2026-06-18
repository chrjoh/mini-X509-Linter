//! The `cabf_smime_san_not_critical` lint (CA/Browser Forum S/MIME BR §7.1.2.3).
//!
//! S/MIME BR §7.1.2.3: when the subject DN is non-empty, the Subject Alternative
//! Name extension SHOULD NOT be marked critical. (RFC 5280 §4.2.1.6 only
//! *requires* SAN to be critical when the subject is empty; marking it critical
//! alongside a populated subject DN harms interoperability.) A critical SAN on a
//! certificate with a non-empty subject is flagged as a [`Severity::Warn`].
//!
//! When the subject DN is empty, a critical SAN is correct, so nothing is
//! emitted. When the SAN extension is absent there is nothing to check (its
//! absence is [`SanPresent`](super::SanPresent)'s concern).
//!
//! emailProtection-EKU-gated (see [`applies_to_smime_leaf`]).

use super::applies_to_smime_leaf;
use crate::cert::{Cert, SanView};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Warns when the SAN is marked critical while the subject DN is non-empty.
#[derive(Debug, Clone, Default)]
pub struct SanNotCritical;

impl SanNotCritical {
    /// Creates the lint.
    pub fn new() -> Self {
        SanNotCritical
    }
}

/// Pure decision: fires only when a SAN extension is present, marked critical,
/// and the subject DN is non-empty.
///
/// `san` is `None` when the SAN extension is absent. Kept separate so the logic
/// can be unit-tested without constructing a certificate.
fn evaluate(san: Option<SanView>, subject_is_empty: bool) -> Vec<Finding> {
    let san_critical = san.is_some_and(|s| s.critical);
    if san_critical && !subject_is_empty {
        vec![Finding {
            severity: Severity::Warn,
            message: "the Subject Alternative Name extension is marked critical while the subject \
                      DN is non-empty; CA/Browser Forum S/MIME BR §7.1.2.3 recommends it not be \
                      critical in that case"
                .to_string(),
        }]
    } else {
        Vec::new()
    }
}

impl Lint for SanNotCritical {
    fn id(&self) -> &'static str {
        "cabf_smime_san_not_critical"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfSmime
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_smime_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: any unreadable accessor means we cannot evaluate; emit
        // nothing.
        let san = match cert.subject_alt_name() {
            Ok(san) => san,
            Err(_) => return Vec::new(),
        };
        let subject_is_empty = match cert.subject_is_empty() {
            Ok(empty) => empty,
            Err(_) => return Vec::new(),
        };
        evaluate(san, subject_is_empty)
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

    fn san(critical: bool) -> SanView {
        SanView {
            critical,
            is_empty: false,
        }
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_when_san_not_critical() {
            assert!(evaluate(Some(san(false)), false).is_empty());
        }

        #[test]
        fn passes_when_san_absent() {
            assert!(evaluate(None, false).is_empty());
        }

        #[test]
        fn passes_when_subject_empty_and_san_critical() {
            assert!(evaluate(Some(san(true)), true).is_empty());
        }

        #[test]
        fn warns_when_critical_and_subject_non_empty() {
            let findings = evaluate(Some(san(true)), false);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Warn);
        }
    }

    #[test]
    fn not_applicable_for_non_smime_leaf() {
        let cert = good_cert();
        assert_eq!(
            SanNotCritical::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SanNotCritical::new();
        assert_eq!(lint.id(), "cabf_smime_san_not_critical");
        assert_eq!(lint.source(), RuleSource::CabfSmime);
    }
}
