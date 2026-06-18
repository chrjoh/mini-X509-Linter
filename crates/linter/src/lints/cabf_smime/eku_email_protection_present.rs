//! The `cabf_smime_eku_email_protection_present` lint
//! (CA/Browser Forum S/MIME BR §7.1.2.3).
//!
//! S/MIME BR §7.1.2.3 (EKU): an S/MIME certificate MUST assert the
//! `emailProtection` extended key usage purpose (OID `1.3.6.1.5.5.7.3.4`). A
//! certificate missing that purpose is flagged as a [`Severity::Error`].
//!
//! # Why this lint can never fire through the registry
//!
//! Every `cabf_smime` lint — this one included — is `applies()`-gated on the
//! emailProtection EKU already being present (see [`applies_to_smime_leaf`]). So
//! a certificate that reaches this lint's [`check`](Lint::check) via the normal
//! `Registry::run` path *by construction* asserts `emailProtection`, and this
//! check cannot produce a finding through that path.
//!
//! It is retained deliberately, mirroring zlint's S/MIME EKU assertion and the
//! sibling `cabf_cs_eku_required`:
//!
//! - under `--purpose smime` (or `--source cabf_smime`) the S/MIME set is the
//!   *declared intent*, so the explicit assertion stays documented and
//!   self-describing, and the rule set reads completely against §7.1.2.3; and
//! - it is a defensive, **fail-closed** assertion for any direct caller that
//!   invokes `check` outside the gate (e.g. a unit test) — such a caller on a
//!   non-emailProtection leaf gets the `Error`.
//!
//! Because of the gate, this lint has no through-the-registry violating fixture;
//! its firing path is exercised by calling `check` directly on a
//! non-emailProtection leaf, or by the pure `evaluate` helper below.

use super::applies_to_smime_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires an S/MIME certificate to assert the `emailProtection` EKU.
#[derive(Debug, Clone, Default)]
pub struct EkuEmailProtectionPresent;

impl EkuEmailProtectionPresent {
    /// Creates the lint.
    pub fn new() -> Self {
        EkuEmailProtectionPresent
    }
}

/// Pure decision: turns "is `emailProtection` asserted?" into zero or one
/// findings.
///
/// Kept separate so the fail-closed logic can be unit-tested without
/// constructing a certificate.
fn evaluate(has_email_protection: bool) -> Vec<Finding> {
    if has_email_protection {
        Vec::new()
    } else {
        vec![Finding {
            severity: Severity::Error,
            message: "the emailProtection EKU (OID 1.3.6.1.5.5.7.3.4) is required for an S/MIME \
                      certificate (CA/Browser Forum S/MIME BR §7.1.2.3)"
                .to_string(),
        }]
    }
}

impl Lint for EkuEmailProtectionPresent {
    fn id(&self) -> &'static str {
        "cabf_smime_eku_email_protection_present"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfSmime
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_smime_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable EKU means we cannot evaluate; emit nothing.
        match cert.has_email_protection() {
            Ok(present) => evaluate(present),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    /// good.pem is a non-emailProtection TLS leaf — used for scoping and for the
    /// defensive fail-closed `check` path when invoked directly.
    fn good_cert() -> Cert {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
        let bytes = std::fs::read(path).unwrap();
        let mut certs = Cert::from_pem(&bytes).unwrap();
        certs.remove(0)
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_when_email_protection_present() {
            assert!(evaluate(true).is_empty());
        }

        #[test]
        fn fires_when_email_protection_absent() {
            let findings = evaluate(false);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }
    }

    #[test]
    fn not_applicable_for_non_smime_leaf() {
        let cert = good_cert();
        assert_eq!(
            EkuEmailProtectionPresent::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn check_fails_closed_when_invoked_directly_on_non_smime_leaf() {
        // good.pem has serverAuth but not emailProtection; calling `check`
        // directly (outside the gate) exercises the defensive fail-closed path.
        let cert = good_cert();
        let findings = EkuEmailProtectionPresent::new().check(&cert);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = EkuEmailProtectionPresent::new();
        assert_eq!(lint.id(), "cabf_smime_eku_email_protection_present");
        assert_eq!(lint.source(), RuleSource::CabfSmime);
    }
}
