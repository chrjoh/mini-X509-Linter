//! The `rfc5280_key_usage_present_when_ca` lint (RFC 5280 §4.2.1.3).
//!
//! RFC 5280 §4.2.1.3: "If the keyCertSign bit is asserted, then the cA bit in
//! the basic constraints extension (Section 4.2.1.9) MUST also be asserted."
//! Conversely, a CA certificate that signs other certificates needs the
//! `keyCertSign` bit. This lint is scoped to CA certificates and fails when Key
//! Usage is absent or does not assert `keyCertSign`.

use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires CA certificates to assert `keyCertSign` in Key Usage.
#[derive(Debug, Clone, Default)]
pub struct KeyUsagePresentWhenCa;

impl KeyUsagePresentWhenCa {
    /// Creates the lint.
    pub fn new() -> Self {
        KeyUsagePresentWhenCa
    }
}

impl Lint for KeyUsagePresentWhenCa {
    fn id(&self) -> &'static str {
        "rfc5280_key_usage_present_when_ca"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Rfc5280
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        // Scoped to CA certificates. Fail policy: if CA-ness is unknown, treat
        // as out of scope (see module docs).
        match cert.is_ca() {
            Ok(true) => Applicability::Applies,
            Ok(false) | Err(_) => Applicability::NotApplicable,
        }
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: unreadable extension means we cannot evaluate; emit
        // nothing (see module docs).
        let key_usage = match cert.key_usage() {
            Ok(ku) => ku,
            Err(_) => return Vec::new(),
        };

        match key_usage {
            None => vec![Finding {
                severity: Severity::Error,
                message: "CA certificate has no Key Usage extension; \
                          RFC 5280 §4.2.1.3 expects keyCertSign on certificate-signing CAs"
                    .to_string(),
            }],
            Some(ku) if !ku.key_cert_sign => vec![Finding {
                severity: Severity::Error,
                message: "CA certificate's Key Usage does not assert keyCertSign; \
                          RFC 5280 §4.2.1.3 requires it for certificate-signing CAs"
                    .to_string(),
            }],
            Some(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    // A CA cert (BasicConstraints CA:TRUE). Note this particular fixture has no
    // Key Usage extension, so it exercises the "absent" failure path.
    const CA_NO_KEY_USAGE_PEM: &[u8] = b"\
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
        let cert = load_one(CA_NO_KEY_USAGE_PEM);
        assert_eq!(
            KeyUsagePresentWhenCa::new().applies(&cert),
            Applicability::Applies
        );
    }

    #[test]
    fn flags_ca_missing_key_usage() {
        // This CA fixture has no Key Usage extension, so the lint must fail it.
        let cert = load_one(CA_NO_KEY_USAGE_PEM);
        let findings = KeyUsagePresentWhenCa::new().check(&cert);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = KeyUsagePresentWhenCa::new();
        assert_eq!(lint.id(), "rfc5280_key_usage_present_when_ca");
        assert_eq!(lint.source(), RuleSource::Rfc5280);
    }
}
