//! The `chain_validity_nested` chain lint.
//!
//! A subject certificate's validity window SHOULD fall within its issuer's:
//! `issuer.not_before <= subject.not_before` AND `subject.not_after <=
//! issuer.not_after`. A certificate that is valid beyond the lifetime of the CA
//! that issued it is a deployment smell — not a strict RFC 5280 MUST — so a
//! violation is reported as **Warn**.
//!
//! This check is **clock-independent**: it compares the two certificates' own
//! `notBefore`/`notAfter` bounds against each other, never against "now", so the
//! chain report stays snapshot-stable.
//!
//! # Degradation
//!
//! Any accessor `Err` reading either bound on either cert yields no finding (the
//! link cannot be evaluated; never a panic).

use crate::cert::Cert;
use crate::{ChainLint, Finding, RuleSource, Severity};

/// Warns when the subject's validity window is not nested within the issuer's.
#[derive(Debug, Clone, Default)]
pub struct ValidityNested;

impl ValidityNested {
    /// Creates the lint.
    pub fn new() -> Self {
        ValidityNested
    }
}

impl ChainLint for ValidityNested {
    fn id(&self) -> &'static str {
        "chain_validity_nested"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Chain
    }

    fn check(&self, subject: &Cert, issuer: &Cert) -> Vec<Finding> {
        // Accessor Err on any of the four bounds → cannot evaluate → no finding.
        let (Ok(s_nb), Ok(s_na), Ok(i_nb), Ok(i_na)) = (
            subject.not_before(),
            subject.not_after(),
            issuer.not_before(),
            issuer.not_after(),
        ) else {
            return Vec::new();
        };

        let mut findings = Vec::new();
        if s_nb < i_nb {
            findings.push(Finding {
                severity: Severity::Warn,
                message: format!(
                    "subject notBefore ({}) precedes the issuer's notBefore ({}); \
                     the subject's validity window is not nested within the issuer's",
                    s_nb, i_nb,
                ),
            });
        }
        if s_na > i_na {
            findings.push(Finding {
                severity: Severity::Warn,
                message: format!(
                    "subject notAfter ({}) is later than the issuer's notAfter ({}); \
                     the subject outlives the issuer that signed it",
                    s_na, i_na,
                ),
            });
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_one(pem: &[u8]) -> Cert {
        let mut certs = Cert::from_pem(pem).expect("fixture must parse");
        certs.pop().expect("fixture must contain one cert")
    }

    const LEAF_PEM: &[u8] = include_bytes!("../../chain_testdata/link_leaf.pem");
    const INTER_PEM: &[u8] = include_bytes!("../../chain_testdata/link_inter.pem");

    #[test]
    fn passes_when_windows_are_equal_or_nested() {
        // All link fixtures share the same BR_OK validity window, so the leaf's
        // window is (equal to and therefore) nested within the inter's.
        let leaf = load_one(LEAF_PEM);
        let inter = load_one(INTER_PEM);
        assert!(ValidityNested::new().check(&leaf, &inter).is_empty());
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = ValidityNested::new();
        assert_eq!(lint.id(), "chain_validity_nested");
        assert_eq!(lint.source(), RuleSource::Chain);
    }
}
