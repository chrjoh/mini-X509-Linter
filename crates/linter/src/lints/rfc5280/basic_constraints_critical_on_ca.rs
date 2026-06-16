//! The `rfc5280_basic_constraints_critical_on_ca` lint (RFC 5280 §4.2.1.9).
//!
//! RFC 5280 §4.2.1.9: "Conforming CAs MUST include this extension in all CA
//! certificates that contain public keys used to validate digital signatures on
//! certificates and MUST mark the extension as critical in such certificates."
//! This lint is scoped to CA certificates and fails when their Basic
//! Constraints extension is not marked critical.

use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires CA certificates to mark Basic Constraints critical.
#[derive(Debug, Clone, Default)]
pub struct BasicConstraintsCriticalOnCa;

impl BasicConstraintsCriticalOnCa {
    /// Creates the lint.
    pub fn new() -> Self {
        BasicConstraintsCriticalOnCa
    }
}

impl Lint for BasicConstraintsCriticalOnCa {
    fn id(&self) -> &'static str {
        "rfc5280_basic_constraints_critical_on_ca"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Rfc5280
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        // Scoped to CA certificates. Fail policy: if CA-ness cannot be
        // determined, treat the rule as out of scope (NotApplicable) rather than
        // guessing — we never run a CA-only check on a cert we cannot classify.
        match cert.is_ca() {
            Ok(true) => Applicability::Applies,
            Ok(false) | Err(_) => Applicability::NotApplicable,
        }
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // `applies` guarantees this is a CA cert, so Basic Constraints is
        // present with `cA = true`. Fail policy: unreadable extension means we
        // cannot evaluate criticality; emit nothing (see module docs).
        let bc = match cert.basic_constraints() {
            Ok(Some(bc)) => bc,
            Ok(None) | Err(_) => return Vec::new(),
        };

        if bc.critical {
            return Vec::new();
        }

        vec![Finding {
            severity: Severity::Error,
            message: "CA certificate does not mark Basic Constraints critical; \
                      RFC 5280 §4.2.1.9 requires it to be critical"
                .to_string(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    // A CA cert with critical BasicConstraints CA:TRUE.
    const GOOD_CA_PEM: &[u8] = b"\
-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIUMEVvgM5RLvNLwl0CpYQKB9Hp5vowDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMZ29vZC5leGFtcGxlMCAXDTI0MDEwMTAwMDAwMFoYDzIx
MjQwMTAxMDAwMDAwWjAXMRUwEwYDVQQDDAxnb29kLmV4YW1wbGUwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkCYfXtr44fwqCzvyGVIocEF63AushxDWf
cIkFoEmJvocMuLYjGYJYJERFkfmewjMxkpefvOxvaG3yTTKMKPbqyCy14AXdYNVu
LQBkabl6fB/RzvVgqfFGuieqtAIJAZ9wHi2dZQ8dkDDMZTkhZ6+aNGz8nfuSRu09
6p33MrM5nTnzc47lOWlVrS4BqhUVVc6QGyk4GeiDx85JEC/uiJm7XOvkJ2yuczko
H9pZRZhxfQYlek/wBLaXRxPhs+t4QiClZv9OcthSuvbwAp86kjlhg+lSD/SAzi0V
HZwl2FzuY6E6uf4VfYai5+02IIOojg/ZSlS2JYUUhJegQqq5EI6/AgMBAAGjUzBR
MB0GA1UdDgQWBBS5Z3XGfJEqJgu3cOQ2/xtFoqVIoTAfBgNVHSMEGDAWgBS5Z3XG
fJEqJgu3cOQ2/xtFoqVIoTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQBF5CJ4L9cOFgBGg+FKcrYFEl44wkxGXbsnBboHI3TmuuZFWnJigf6s0fql
jc/wc5z6VxMpyffoJka+Yyj1+rAGAi1rs7XJGNFEwvBt3t+EBS+m+oLayN6M0PyW
9M56DA4RQ94r41kBpRZ7csxGS445FdF3v/tX4wyvp3iEt9xooQJbUsVA5YWIxw7m
UJPlG7T5AvQLi6uDXdz3jINPkFXiyiY0TST9ovBEUcaEm0dflkzuxalpgBqgl/M1
2NX13Gvbs4x8q4YE/bA5hivzacVDpIdOPogqIgYANBQVlyAK81pFcXUXeobhKcOe
oWraeM6JK6PALHP6RN1XoUTQaOT5
-----END CERTIFICATE-----
";

    fn load_one(pem: &[u8]) -> Cert {
        let mut certs = Cert::from_pem(pem).expect("fixture must parse");
        certs.pop().expect("fixture must contain one cert")
    }

    #[test]
    fn applies_to_ca_cert() {
        let cert = load_one(GOOD_CA_PEM);
        assert_eq!(
            BasicConstraintsCriticalOnCa::new().applies(&cert),
            Applicability::Applies
        );
    }

    #[test]
    fn passes_when_ca_marks_basic_constraints_critical() {
        let cert = load_one(GOOD_CA_PEM);
        assert!(BasicConstraintsCriticalOnCa::new().check(&cert).is_empty());
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = BasicConstraintsCriticalOnCa::new();
        assert_eq!(lint.id(), "rfc5280_basic_constraints_critical_on_ca");
        assert_eq!(lint.source(), RuleSource::Rfc5280);
    }
}
