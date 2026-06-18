//! The `rfc5280_ext_key_usage_without_bits` lint (RFC 5280 §4.2.1.12).
//!
//! RFC 5280 §4.2.1.12: "This extension indicates one or more purposes for which
//! the certified public key may be used [...] ExtKeyUsageSyntax ::= SEQUENCE
//! SIZE (1..MAX) OF KeyPurposeId." The SEQUENCE has a minimum size of one, so an
//! EKU extension that carries no `KeyPurposeId` is malformed.
//!
//! This lint is scoped to certificates that carry an EKU extension and fails
//! when that extension contains no key purposes at all (no `anyExtendedKeyUsage`,
//! no recognised purpose, and no `other` purpose OIDs).

use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires a present EKU extension to contain at least one `KeyPurposeId`.
#[derive(Debug, Clone, Default)]
pub struct ExtKeyUsageWithoutBits;

impl ExtKeyUsageWithoutBits {
    /// Creates the lint.
    pub fn new() -> Self {
        ExtKeyUsageWithoutBits
    }
}

impl Lint for ExtKeyUsageWithoutBits {
    fn id(&self) -> &'static str {
        "rfc5280_ext_key_usage_without_bits"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Rfc5280
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        // Scoped to certs that carry an EKU extension. Fail policy: if the
        // extension cannot be read, treat the rule as out of scope (see module
        // docs).
        match cert.extended_key_usage() {
            Ok(Some(_)) => Applicability::Applies,
            Ok(None) | Err(_) => Applicability::NotApplicable,
        }
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // `applies` guarantees an EKU extension exists. Fail policy: unreadable
        // extension means we cannot evaluate; emit nothing (see module docs).
        let eku = match cert.extended_key_usage() {
            Ok(Some(eku)) => eku,
            Ok(None) | Err(_) => return Vec::new(),
        };

        if eku.is_empty {
            vec![Finding {
                severity: Severity::Error,
                message: "ExtendedKeyUsage extension is present but contains no \
                          KeyPurposeId; RFC 5280 §4.2.1.12 requires at least one"
                    .to_string(),
            }]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    // good.pem: a leaf carrying EKU=serverAuth (one purpose) — passes the lint.
    const LEAF_WITH_EKU_PEM: &[u8] = b"\
-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIBETANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBBnb29k
LmV4YW1wbGUuY29tMB4XDTI2MDYwMTAwMDAwMFoXDTI3MDYwMTAwMDAwMFowGzEZ
MBcGA1UEAwwQZ29vZC5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAOVqsq5MvB+yyI4NRCM7AoV145FqR9bjJW1XwBHq1oOsMH7jy9JA
Dd37dxgZ6c184luYA1O3fSx0N7lWQFDo8M2ZHWtlK/EHHa7lM2A9fJbFAid6K4SQ
FKRkFckqX0RasPV8Cy0g6EaN3Wvi4RXIKeHgvSGuVW6EMCizwTAjtHurIxvcf4ZU
kkmAFItv1F+CPSmRHnrjPqfrClRpDHNXqnXtgxOjW7sb7RdFDNLo2OFlDWWF69A7
Na4OhJtoR8PJgftQAUT+U/f8HliG64dhFfLu4xWWRgVWrPkO7Cah8mCwNWvFNPR5
TQPPJiZ0pSjK8MNrZmV7iK+uJc1XuqxbWLkCAwEAAaNeMFwwCQYDVR0TBAIwADAT
BgNVHSUEDDAKBggrBgEFBQcDATAbBgNVHREEFDASghBnb29kLmV4YW1wbGUuY29t
MB0GA1UdDgQWBBQdM1O88ecxlvln0vxyCvCWfS9MEzANBgkqhkiG9w0BAQsFAAOC
AQEAjj/gfkw2Mw7TCgCGWbdc8c7HjV9OQMcm0kNC7S5baFwCgk2L3bKmzIcIZuQy
ErSSlzNCJde0PdTVTx/1bsGPKpgLF/ea15ciJZ+MPvdnOuVVIiaG1G69HLSa5E8q
v5Dv2yX1drGBJHAFiV44vx+04qyqgRRpZbLKr+2n7F3ny6syIl2OK0++RAIue4W/
hCD60KaCpZDjjnT+EQOwdIK131NH8ELTGWbTKd3meuKnNJByPHPwuzK2ybWl7B3/
hHHWDhUD3r/G9CsO500Gwq9C+2djz003D/1sgUiuv93+8HoeotnMOWRwmsDs5nDQ
f63Xm57T5UNHDT/XSK4j6q6dJw==
-----END CERTIFICATE-----
";

    // A CA cert with no EKU extension — the lint is out of scope for it.
    const NO_EKU_PEM: &[u8] = b"\
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
    fn applies_when_eku_present() {
        let cert = load_one(LEAF_WITH_EKU_PEM);
        assert_eq!(
            ExtKeyUsageWithoutBits::new().applies(&cert),
            Applicability::Applies
        );
    }

    #[test]
    fn not_applicable_when_eku_absent() {
        let cert = load_one(NO_EKU_PEM);
        assert_eq!(
            ExtKeyUsageWithoutBits::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn passes_eku_with_a_purpose() {
        let cert = load_one(LEAF_WITH_EKU_PEM);
        assert!(ExtKeyUsageWithoutBits::new().check(&cert).is_empty());
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = ExtKeyUsageWithoutBits::new();
        assert_eq!(lint.id(), "rfc5280_ext_key_usage_without_bits");
        assert_eq!(lint.source(), RuleSource::Rfc5280);
    }
}
