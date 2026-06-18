//! The `rfc5280_ca_subject_field_empty` lint (RFC 5280 §4.1.2.6).
//!
//! RFC 5280 §4.1.2.6: "The subject field identifies the entity associated with
//! the public key [...] If the subject is a CA (e.g., the basic constraints
//! extension, as discussed in Section 4.2.1.9, is present and the value of cA is
//! TRUE), then the subject field MUST be populated with a non-empty
//! distinguished name [...]"
//!
//! This lint is scoped to CA certificates and fails when their subject DN is an
//! empty sequence.

use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires CA certificates to have a non-empty subject DN.
#[derive(Debug, Clone, Default)]
pub struct CaSubjectFieldEmpty;

impl CaSubjectFieldEmpty {
    /// Creates the lint.
    pub fn new() -> Self {
        CaSubjectFieldEmpty
    }
}

impl Lint for CaSubjectFieldEmpty {
    fn id(&self) -> &'static str {
        "rfc5280_ca_subject_field_empty"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Rfc5280
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        // Scoped to CA certificates. Fail policy: if CA-ness cannot be
        // determined, treat the rule as out of scope (see module docs).
        match cert.is_ca() {
            Ok(true) => Applicability::Applies,
            Ok(false) | Err(_) => Applicability::NotApplicable,
        }
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // `applies` guarantees this is a CA cert. Fail policy: if subject
        // emptiness cannot be read, emit nothing (see module docs).
        match cert.subject_is_empty() {
            Ok(true) => vec![Finding {
                severity: Severity::Error,
                message: "CA certificate has an empty subject DN; \
                          RFC 5280 §4.1.2.6 requires CA certificates to have a \
                          non-empty subject"
                    .to_string(),
            }],
            Ok(false) | Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    // A CA cert with a non-empty subject (CN=good.example): passes the lint.
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
            CaSubjectFieldEmpty::new().applies(&cert),
            Applicability::Applies
        );
    }

    #[test]
    fn passes_ca_with_non_empty_subject() {
        let cert = load_one(GOOD_CA_PEM);
        assert!(CaSubjectFieldEmpty::new().check(&cert).is_empty());
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = CaSubjectFieldEmpty::new();
        assert_eq!(lint.id(), "rfc5280_ca_subject_field_empty");
        assert_eq!(lint.source(), RuleSource::Rfc5280);
    }
}
