//! The `rfc5280_serial_number_positive` lint (RFC 5280 §4.1.2.2).
//!
//! RFC 5280 §4.1.2.2: "The serial number MUST be a positive integer assigned by
//! the CA to each certificate. [...] Conforming CAs MUST NOT use serialNumber
//! values longer than 20 octets." Two distinct requirements live here:
//!
//! 1. the value must be positive (neither zero nor negative), and
//! 2. its DER INTEGER content must be at most 20 octets.
//!
//! A serial can violate both at once, so this lint may emit two findings.

use crate::cert::{Cert, SerialSummary};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Maximum conforming serial length in DER INTEGER content octets.
const MAX_SERIAL_OCTETS: usize = 20;

/// Requires a positive serial number of at most 20 octets.
#[derive(Debug, Clone, Default)]
pub struct SerialNumberPositive;

impl SerialNumberPositive {
    /// Creates the lint.
    pub fn new() -> Self {
        SerialNumberPositive
    }
}

/// Pure decision: turns a [`SerialSummary`] into zero, one, or two findings.
///
/// Kept separate so each requirement can be unit-tested without constructing a
/// certificate.
fn evaluate(summary: SerialSummary) -> Vec<Finding> {
    let mut findings = Vec::new();

    if summary.is_zero {
        findings.push(Finding {
            severity: Severity::Error,
            message: "serial number is zero; RFC 5280 §4.1.2.2 requires a positive integer"
                .to_string(),
        });
    } else if summary.is_negative {
        findings.push(Finding {
            severity: Severity::Error,
            message: "serial number is negative; RFC 5280 §4.1.2.2 requires a positive integer"
                .to_string(),
        });
    }

    if summary.octet_len > MAX_SERIAL_OCTETS {
        findings.push(Finding {
            severity: Severity::Error,
            message: format!(
                "serial number is {} octets; RFC 5280 §4.1.2.2 forbids serials longer than {MAX_SERIAL_OCTETS} octets",
                summary.octet_len
            ),
        });
    }

    findings
}

impl Lint for SerialNumberPositive {
    fn id(&self) -> &'static str {
        "rfc5280_serial_number_positive"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Rfc5280
    }

    fn applies(&self, _cert: &Cert) -> Applicability {
        Applicability::Applies
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: unreadable serial means we cannot evaluate; emit nothing
        // (see module docs). Unreachable for a pre-validated `Cert`.
        match cert.serial_summary() {
            Ok(summary) => evaluate(summary),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

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

    mod evaluate {
        use super::*;

        #[test]
        fn passes_for_positive_short_serial() {
            let summary = SerialSummary {
                is_zero: false,
                is_negative: false,
                octet_len: 20,
            };
            assert!(evaluate(summary).is_empty());
        }

        #[test]
        fn flags_zero_serial() {
            let summary = SerialSummary {
                is_zero: true,
                is_negative: false,
                octet_len: 1,
            };
            let findings = evaluate(summary);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }

        #[test]
        fn flags_negative_serial() {
            let summary = SerialSummary {
                is_zero: false,
                is_negative: true,
                octet_len: 8,
            };
            assert_eq!(evaluate(summary).len(), 1);
        }

        #[test]
        fn flags_overlong_serial() {
            let summary = SerialSummary {
                is_zero: false,
                is_negative: false,
                octet_len: 21,
            };
            assert_eq!(evaluate(summary).len(), 1);
        }

        #[test]
        fn flags_both_zero_and_overlong() {
            let summary = SerialSummary {
                is_zero: true,
                is_negative: false,
                octet_len: 25,
            };
            assert_eq!(evaluate(summary).len(), 2);
        }
    }

    #[test]
    fn applies_always() {
        let cert = load_one(GOOD_PEM);
        assert_eq!(
            SerialNumberPositive::new().applies(&cert),
            Applicability::Applies
        );
    }

    #[test]
    fn passes_for_good_cert() {
        let cert = load_one(GOOD_PEM);
        assert!(SerialNumberPositive::new().check(&cert).is_empty());
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SerialNumberPositive::new();
        assert_eq!(lint.id(), "rfc5280_serial_number_positive");
        assert_eq!(lint.source(), RuleSource::Rfc5280);
    }
}
