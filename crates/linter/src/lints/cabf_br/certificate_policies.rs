//! The `cabf_br_certificate_policies_present` and
//! `cabf_br_certificate_policies_reserved_oid` lints
//! (CA/Browser Forum BR §7.1.2.7.9 / §7.1.6.1).
//!
//! Two sibling rules over the CertificatePolicies extension, sharing one
//! accessor and one file:
//!
//! - [`CertificatePoliciesPresent`] (BR §7.1.2.7.9): a subscriber TLS
//!   certificate MUST include a CertificatePolicies extension. A leaf with no
//!   policy OIDs is flagged [`Severity::Warn`] (defence-in-depth — see the
//!   feature-17 Cascade-Management strategy for why this is a `Warn`).
//! - [`CertificatePoliciesReservedOid`] (BR §7.1.6.1): **when** a
//!   CertificatePolicies extension is present, it MUST assert at least one
//!   CA/Browser Forum reserved policy OID — domain-validated `2.23.140.1.2.1`,
//!   organization-validated `2.23.140.1.2.2`, or individual-validated
//!   `2.23.140.1.2.3`. A policies extension that lists none of these is flagged
//!   [`Severity::Error`]. This rule is silent when CertificatePolicies is absent
//!   (that case belongs to [`CertificatePoliciesPresent`]).
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//!
//! # Fail policy
//!
//! An accessor `Err` in `check` means "cannot evaluate" → empty `Vec`; an
//! accessor `Err` in `applies` (`is_ca`) means "cannot scope" → `NotApplicable`.

use super::applies_to_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// The CA/Browser Forum reserved subscriber-certificate policy OIDs
/// (BR §7.1.6.1): domain-validated, organization-validated, individual-validated.
const RESERVED_POLICY_OIDS: [&str; 3] = [
    "2.23.140.1.2.1", // domain-validated (DV)
    "2.23.140.1.2.2", // organization-validated (OV)
    "2.23.140.1.2.3", // individual-validated (IV)
];

/// Requires a CertificatePolicies extension on a subscriber certificate.
#[derive(Debug, Clone, Default)]
pub struct CertificatePoliciesPresent;

impl CertificatePoliciesPresent {
    /// Creates the lint.
    pub fn new() -> Self {
        CertificatePoliciesPresent
    }
}

/// Requires a reserved CABF policy OID when CertificatePolicies is present.
#[derive(Debug, Clone, Default)]
pub struct CertificatePoliciesReservedOid;

impl CertificatePoliciesReservedOid {
    /// Creates the lint.
    pub fn new() -> Self {
        CertificatePoliciesReservedOid
    }
}

/// Pure decision for the presence rule: one [`Severity::Warn`] [`Finding`] when
/// no policy OIDs are present, none otherwise.
fn evaluate_present(policy_oids: &[String]) -> Vec<Finding> {
    if policy_oids.is_empty() {
        vec![Finding {
            severity: Severity::Warn,
            message: "certificate has no CertificatePolicies extension; \
                      CA/Browser Forum BR §7.1.2.7.9 requires it in a subscriber \
                      TLS certificate"
                .to_string(),
        }]
    } else {
        Vec::new()
    }
}

/// Pure decision for the reserved-OID rule: one [`Severity::Error`] [`Finding`]
/// when CertificatePolicies is present but none of the reserved CABF OIDs is
/// listed. Silent when no policies are present (that case is owned by the
/// presence rule).
fn evaluate_reserved(policy_oids: &[String]) -> Vec<Finding> {
    if policy_oids.is_empty() {
        return Vec::new();
    }
    let has_reserved = policy_oids
        .iter()
        .any(|oid| RESERVED_POLICY_OIDS.contains(&oid.as_str()));
    if has_reserved {
        Vec::new()
    } else {
        vec![Finding {
            severity: Severity::Error,
            message: "CertificatePolicies asserts no CA/Browser Forum reserved policy OID \
                      (none of 2.23.140.1.2.1 DV, 2.23.140.1.2.2 OV, 2.23.140.1.2.3 IV); \
                      CA/Browser Forum BR §7.1.6.1 requires at least one"
                .to_string(),
        }]
    }
}

impl Lint for CertificatePoliciesPresent {
    fn id(&self) -> &'static str {
        "cabf_br_certificate_policies_present"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.certificate_policy_oids() {
            Ok(oids) => evaluate_present(&oids),
            Err(_) => Vec::new(),
        }
    }
}

impl Lint for CertificatePoliciesReservedOid {
    fn id(&self) -> &'static str {
        "cabf_br_certificate_policies_reserved_oid"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        match cert.certificate_policy_oids() {
            Ok(oids) => evaluate_reserved(&oids),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oids(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    mod present {
        use super::*;

        #[test]
        fn warns_when_no_policies() {
            let findings = evaluate_present(&[]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Warn);
            assert!(findings[0].message.contains("CertificatePolicies"));
        }

        #[test]
        fn passes_when_any_policy_present() {
            assert!(evaluate_present(&oids(&["2.23.140.1.2.1"])).is_empty());
        }

        #[test]
        fn passes_for_non_reserved_policy_too() {
            // Presence rule cares only about presence, not which OID.
            assert!(evaluate_present(&oids(&["1.3.6.1.4.1.99999.1"])).is_empty());
        }

        #[test]
        fn has_correct_id_and_source() {
            let lint = CertificatePoliciesPresent::new();
            assert_eq!(lint.id(), "cabf_br_certificate_policies_present");
            assert_eq!(lint.source(), RuleSource::CabfBr);
        }
    }

    mod reserved {
        use super::*;

        #[test]
        fn silent_when_no_policies() {
            // The absent case is owned by the presence rule.
            assert!(evaluate_reserved(&[]).is_empty());
        }

        #[test]
        fn passes_for_dv_reserved_oid() {
            assert!(evaluate_reserved(&oids(&["2.23.140.1.2.1"])).is_empty());
        }

        #[test]
        fn passes_for_ov_reserved_oid() {
            assert!(evaluate_reserved(&oids(&["2.23.140.1.2.2"])).is_empty());
        }

        #[test]
        fn passes_when_reserved_among_others() {
            assert!(
                evaluate_reserved(&oids(&["1.3.6.1.4.1.99999.1", "2.23.140.1.2.3"])).is_empty()
            );
        }

        #[test]
        fn fires_when_only_non_reserved_oid() {
            let findings = evaluate_reserved(&oids(&["1.3.6.1.4.1.99999.1"]));
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("reserved"));
        }

        #[test]
        fn has_correct_id_and_source() {
            let lint = CertificatePoliciesReservedOid::new();
            assert_eq!(lint.id(), "cabf_br_certificate_policies_reserved_oid");
            assert_eq!(lint.source(), RuleSource::CabfBr);
        }
    }
}
