//! The `rfc5280_ext_san_no_entries` lint (RFC 5280 §4.2.1.6).
//!
//! RFC 5280 §4.2.1.6: "SubjectAltName ::= GeneralNames" and
//! "GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName." The SEQUENCE has a
//! minimum size of one, so a SAN extension that contains no `GeneralName` is
//! malformed.
//!
//! This lint is scoped to certificates that carry a SAN extension and fails when
//! that extension contains zero general names.

use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires a present SAN extension to contain at least one general name.
#[derive(Debug, Clone, Default)]
pub struct ExtSanNoEntries;

impl ExtSanNoEntries {
    /// Creates the lint.
    pub fn new() -> Self {
        ExtSanNoEntries
    }
}

impl Lint for ExtSanNoEntries {
    fn id(&self) -> &'static str {
        "rfc5280_ext_san_no_entries"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Rfc5280
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        // Scoped to certs that carry a SAN extension. Fail policy: if the
        // extension cannot be read, treat as out of scope (see module docs).
        match cert.subject_alt_name() {
            Ok(Some(_)) => Applicability::Applies,
            Ok(None) | Err(_) => Applicability::NotApplicable,
        }
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // `applies` guarantees a SAN extension exists. Fail policy: unreadable
        // extension means we cannot evaluate; emit nothing (see module docs).
        let san = match cert.subject_alt_name() {
            Ok(Some(san)) => san,
            Ok(None) | Err(_) => return Vec::new(),
        };

        if san.is_empty {
            vec![Finding {
                severity: Severity::Error,
                message: "subjectAltName extension is present but contains no \
                          general names; RFC 5280 §4.2.1.6 requires at least one"
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

    // good.pem: a leaf with a SAN carrying one DNS name — passes the lint.
    const SAN_WITH_ENTRY_PEM: &[u8] = b"\
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

    // A cert with NO SAN extension — the lint is out of scope for it.
    const NO_SAN_PEM: &[u8] = b"\
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
    fn applies_when_san_present() {
        let cert = load_one(SAN_WITH_ENTRY_PEM);
        assert_eq!(
            ExtSanNoEntries::new().applies(&cert),
            Applicability::Applies
        );
    }

    #[test]
    fn not_applicable_when_san_absent() {
        let cert = load_one(NO_SAN_PEM);
        assert_eq!(
            ExtSanNoEntries::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn passes_san_with_one_entry() {
        let cert = load_one(SAN_WITH_ENTRY_PEM);
        assert!(ExtSanNoEntries::new().check(&cert).is_empty());
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = ExtSanNoEntries::new();
        assert_eq!(lint.id(), "rfc5280_ext_san_no_entries");
        assert_eq!(lint.source(), RuleSource::Rfc5280);
    }
}
