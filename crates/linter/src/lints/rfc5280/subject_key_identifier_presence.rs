//! The SubjectKeyIdentifier presence lints (RFC 5280 §4.2.1.2).
//!
//! RFC 5280 §4.2.1.2: "To facilitate certification path construction, this
//! extension MUST appear in all conforming CA certificates [...] this extension
//! SHOULD be included in all end entity certificates [...]"
//!
//! This file houses two sibling lints derived from that single section:
//!
//! - [`ExtSubjectKeyIdentifierMissingCa`] — a CA certificate MUST include a
//!   SubjectKeyIdentifier extension ([`Severity::Error`]). Scoped to CA certs.
//! - [`ExtSubjectKeyIdentifierMissingSubCert`] — a sub-certificate (non-CA leaf)
//!   SHOULD include a SubjectKeyIdentifier extension ([`Severity::Warn`]).
//!   Scoped to non-CA leaves.

use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires CA certificates to include a SubjectKeyIdentifier extension
/// (RFC 5280 §4.2.1.2, MUST).
#[derive(Debug, Clone, Default)]
pub struct ExtSubjectKeyIdentifierMissingCa;

impl ExtSubjectKeyIdentifierMissingCa {
    /// Creates the lint.
    pub fn new() -> Self {
        ExtSubjectKeyIdentifierMissingCa
    }
}

impl Lint for ExtSubjectKeyIdentifierMissingCa {
    fn id(&self) -> &'static str {
        "rfc5280_ext_subject_key_identifier_missing_ca"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Rfc5280
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        // Scoped to CA certificates. Fail policy: if CA-ness cannot be
        // determined, treat as out of scope (see module docs).
        match cert.is_ca() {
            Ok(true) => Applicability::Applies,
            Ok(false) | Err(_) => Applicability::NotApplicable,
        }
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // `applies` guarantees this is a CA cert. Fail policy: if SKI presence
        // cannot be read, emit nothing (see module docs).
        match cert.has_subject_key_identifier() {
            Ok(false) => vec![Finding {
                severity: Severity::Error,
                message: "CA certificate has no SubjectKeyIdentifier extension; \
                          RFC 5280 §4.2.1.2 requires it in all conforming CA \
                          certificates"
                    .to_string(),
            }],
            Ok(true) | Err(_) => Vec::new(),
        }
    }
}

/// Recommends sub-certificates (non-CA leaves) include a SubjectKeyIdentifier
/// extension (RFC 5280 §4.2.1.2, SHOULD).
#[derive(Debug, Clone, Default)]
pub struct ExtSubjectKeyIdentifierMissingSubCert;

impl ExtSubjectKeyIdentifierMissingSubCert {
    /// Creates the lint.
    pub fn new() -> Self {
        ExtSubjectKeyIdentifierMissingSubCert
    }
}

impl Lint for ExtSubjectKeyIdentifierMissingSubCert {
    fn id(&self) -> &'static str {
        "rfc5280_ext_subject_key_identifier_missing_sub_cert"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Rfc5280
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        // Scoped to non-CA leaves. Fail policy: if CA-ness cannot be determined,
        // treat as out of scope (see module docs).
        match cert.is_ca() {
            Ok(false) => Applicability::Applies,
            Ok(true) | Err(_) => Applicability::NotApplicable,
        }
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // `applies` guarantees this is a non-CA leaf. Fail policy: if SKI
        // presence cannot be read, emit nothing (see module docs).
        match cert.has_subject_key_identifier() {
            Ok(false) => vec![Finding {
                severity: Severity::Warn,
                message: "sub-certificate has no SubjectKeyIdentifier extension; \
                          RFC 5280 §4.2.1.2 recommends (SHOULD) including it"
                    .to_string(),
            }],
            Ok(true) | Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    // good.pem: a non-CA leaf that HAS a SubjectKeyIdentifier extension.
    const LEAF_WITH_SKI_PEM: &[u8] = b"\
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

    // A CA cert that HAS a SubjectKeyIdentifier extension.
    const CA_WITH_SKI_PEM: &[u8] = b"\
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
    fn ca_lint_applies_to_ca_and_passes_with_ski() {
        let cert = load_one(CA_WITH_SKI_PEM);
        let lint = ExtSubjectKeyIdentifierMissingCa::new();
        assert_eq!(lint.applies(&cert), Applicability::Applies);
        assert!(lint.check(&cert).is_empty());
    }

    #[test]
    fn ca_lint_not_applicable_to_leaf() {
        let cert = load_one(LEAF_WITH_SKI_PEM);
        assert_eq!(
            ExtSubjectKeyIdentifierMissingCa::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn sub_cert_lint_applies_to_leaf_and_passes_with_ski() {
        let cert = load_one(LEAF_WITH_SKI_PEM);
        let lint = ExtSubjectKeyIdentifierMissingSubCert::new();
        assert_eq!(lint.applies(&cert), Applicability::Applies);
        assert!(lint.check(&cert).is_empty());
    }

    #[test]
    fn sub_cert_lint_not_applicable_to_ca() {
        let cert = load_one(CA_WITH_SKI_PEM);
        assert_eq!(
            ExtSubjectKeyIdentifierMissingSubCert::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn correct_ids_and_sources() {
        let ca = ExtSubjectKeyIdentifierMissingCa::new();
        assert_eq!(ca.id(), "rfc5280_ext_subject_key_identifier_missing_ca");
        assert_eq!(ca.source(), RuleSource::Rfc5280);

        let leaf = ExtSubjectKeyIdentifierMissingSubCert::new();
        assert_eq!(
            leaf.id(),
            "rfc5280_ext_subject_key_identifier_missing_sub_cert"
        );
        assert_eq!(leaf.source(), RuleSource::Rfc5280);
    }
}
