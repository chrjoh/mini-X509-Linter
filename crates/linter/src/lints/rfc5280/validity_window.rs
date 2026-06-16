//! The `rfc5280_validity_not_after_after_not_before` lint (RFC 5280 §4.1.2.5).
//!
//! RFC 5280 §4.1.2.5: "The certificate validity period is the time interval
//! during which the CA warrants that it will maintain information about the
//! status of the certificate. The field is represented as a SEQUENCE of two
//! dates: the date on which the certificate validity period begins (notBefore)
//! and the date on which the certificate validity period ends (notAfter)." A
//! coherent interval requires `notAfter` to be strictly later than `notBefore`;
//! an empty or inverted window is malformed.

use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires `notAfter` to be strictly later than `notBefore`.
#[derive(Debug, Clone, Default)]
pub struct ValidityNotAfterAfterNotBefore;

impl ValidityNotAfterAfterNotBefore {
    /// Creates the lint.
    pub fn new() -> Self {
        ValidityNotAfterAfterNotBefore
    }
}

impl Lint for ValidityNotAfterAfterNotBefore {
    fn id(&self) -> &'static str {
        "rfc5280_validity_not_after_after_not_before"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Rfc5280
    }

    fn applies(&self, _cert: &Cert) -> Applicability {
        Applicability::Applies
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: if either bound is unreadable we cannot compare them, so
        // emit nothing (see module docs). Unreachable for a pre-validated `Cert`.
        let not_before = match cert.not_before() {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };
        let not_after = match cert.not_after() {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        if not_after > not_before {
            return Vec::new();
        }

        vec![Finding {
            severity: Severity::Error,
            message: format!(
                "notAfter ({}) is not later than notBefore ({}); \
                 RFC 5280 §4.1.2.5 requires a positive-length validity window",
                not_after.timestamp(),
                not_before.timestamp(),
            ),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    // notBefore=2024-01-01, notAfter=2124-01-01 — a valid window.
    const GOOD_PEM: &[u8] = b"\
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
    fn applies_always() {
        let cert = load_one(GOOD_PEM);
        assert_eq!(
            ValidityNotAfterAfterNotBefore::new().applies(&cert),
            Applicability::Applies
        );
    }

    #[test]
    fn passes_for_well_ordered_window() {
        let cert = load_one(GOOD_PEM);
        assert!(
            ValidityNotAfterAfterNotBefore::new()
                .check(&cert)
                .is_empty()
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = ValidityNotAfterAfterNotBefore::new();
        assert_eq!(lint.id(), "rfc5280_validity_not_after_after_not_before");
        assert_eq!(lint.source(), RuleSource::Rfc5280);
    }
}
