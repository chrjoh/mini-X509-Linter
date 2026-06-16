//! The `rfc5280_version_is_v3` lint (RFC 5280 §4.1.2.1).
//!
//! RFC 5280 §4.1.2.1: "When extensions are used, as expected in this profile,
//! version MUST be 3 (value is 2)." The DER `version` field is `0` for v1, `1`
//! for v2, and `2` for v3. So any certificate carrying extensions must encode
//! version `2`.

use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// DER `Version` value for X.509 v3 (`version` field omitted/0 means v1).
const VERSION_V3: u32 = 2;

/// Requires v3 (`version == 2`) whenever the certificate carries extensions.
#[derive(Debug, Clone, Default)]
pub struct VersionIsV3;

impl VersionIsV3 {
    /// Creates the lint.
    pub fn new() -> Self {
        VersionIsV3
    }
}

impl Lint for VersionIsV3 {
    fn id(&self) -> &'static str {
        "rfc5280_version_is_v3"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Rfc5280
    }

    fn applies(&self, _cert: &Cert) -> Applicability {
        // The rule is universally relevant; the extension/version coupling is
        // evaluated in `check`.
        Applicability::Applies
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable field means we cannot evaluate the rule, so
        // emit nothing (see module docs). A `Cert` is always pre-validated DER,
        // so this branch is effectively unreachable.
        let has_extensions = match cert.has_extensions() {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        if !has_extensions {
            return Vec::new();
        }

        let version = match cert.version() {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };

        if version == VERSION_V3 {
            return Vec::new();
        }

        vec![Finding {
            severity: Severity::Error,
            message: format!(
                "certificate carries extensions but encodes version {version} (v{}); \
                 RFC 5280 §4.1.2.1 requires version 2 (v3) when extensions are present",
                version + 1
            ),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    // A valid v3 certificate with extensions (BasicConstraints etc.).
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
        assert_eq!(VersionIsV3::new().applies(&cert), Applicability::Applies);
    }

    #[test]
    fn passes_for_v3_cert_with_extensions() {
        let cert = load_one(GOOD_PEM);
        assert!(VersionIsV3::new().check(&cert).is_empty());
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = VersionIsV3::new();
        assert_eq!(lint.id(), "rfc5280_version_is_v3");
        assert_eq!(lint.source(), RuleSource::Rfc5280);
    }
}
