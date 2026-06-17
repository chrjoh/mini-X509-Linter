//! The `cabf_br_ext_key_usage_server_auth_present` lint
//! (CA/Browser Forum BR §7.1.2.7).
//!
//! BR §7.1.2.7 requires a Subscriber (TLS server) Certificate to assert the
//! `id-kp-serverAuth` Extended Key Usage purpose (OID `1.3.6.1.5.5.7.3.1`). A
//! non-CA leaf that lacks `serverAuth` — whether because its EKU lists other
//! purposes only, or because it carries no EKU extension at all — is flagged as
//! a [`Severity::Error`].
//!
//! Broad-scoped: applies to every non-CA leaf, [`NotApplicable`] for CA certs.
//! Because scoping is NOT EKU-gated, an EKU-less leaf reaches this lint and fires
//! here (rather than being silently skipped).

use super::applies_to_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires a non-CA leaf to assert the `serverAuth` EKU purpose.
#[derive(Debug, Clone, Default)]
pub struct ExtKeyUsageServerAuthPresent;

impl ExtKeyUsageServerAuthPresent {
    /// Creates the lint.
    pub fn new() -> Self {
        ExtKeyUsageServerAuthPresent
    }
}

/// Pure decision: maps "does this leaf assert serverAuth?" to zero or one
/// findings.
///
/// Kept separate so the rule can be unit-tested with a plain `bool`.
fn evaluate(has_server_auth: bool) -> Vec<Finding> {
    if has_server_auth {
        Vec::new()
    } else {
        vec![Finding {
            severity: Severity::Error,
            message: "certificate does not assert the serverAuth Extended Key Usage \
                      (OID 1.3.6.1.5.5.7.3.1); CA/Browser Forum BR §7.1.2.7 requires it for \
                      TLS server certificates"
                .to_string(),
        }]
    }
}

impl Lint for ExtKeyUsageServerAuthPresent {
    fn id(&self) -> &'static str {
        "cabf_br_ext_key_usage_server_auth_present"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfBr
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable EKU means we cannot evaluate; emit nothing
        // (see module docs). Unreachable for a pre-validated `Cert`.
        match cert.has_server_auth() {
            Ok(has) => evaluate(has),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    /// Loads a single cert from a workspace `testdata` fixture by file name.
    fn load_fixture(name: &str) -> Cert {
        let path = format!(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/{}"),
            name
        );
        let bytes = std::fs::read(&path).unwrap();
        let mut certs = Cert::from_pem(&bytes).unwrap();
        certs.remove(0)
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_when_server_auth_present() {
            assert!(evaluate(true).is_empty());
        }

        #[test]
        fn fires_when_server_auth_absent() {
            let findings = evaluate(false);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("serverAuth"));
        }
    }

    #[test]
    fn not_applicable_for_ca_cert() {
        let cert = load_fixture("rfc5280_ca_bc_not_critical.pem");
        assert_eq!(
            ExtKeyUsageServerAuthPresent::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = ExtKeyUsageServerAuthPresent::new();
        assert_eq!(lint.id(), "cabf_br_ext_key_usage_server_auth_present");
        assert_eq!(lint.source(), RuleSource::CabfBr);
    }
}
