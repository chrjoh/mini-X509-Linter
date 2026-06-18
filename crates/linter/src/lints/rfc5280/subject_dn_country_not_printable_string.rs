//! The `rfc5280_subject_dn_country_not_printable_string` lint
//! (RFC 5280 §4.1.2.6 / Appendix A).
//!
//! RFC 5280 Appendix A constrains `countryName` to PrintableString:
//! `X520countryName ::= PrintableString (SIZE (2))`. A subject `countryName`
//! (C) attribute encoded with any other ASN.1 string type (e.g. UTF8String or
//! IA5String) is non-conforming.
//!
//! This lint is scoped to certificates whose subject DN carries a `countryName`
//! attribute and fails when that attribute value is not encoded as a
//! PrintableString.

use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires a subject `countryName` to be encoded as a PrintableString.
#[derive(Debug, Clone, Default)]
pub struct SubjectDnCountryNotPrintableString;

impl SubjectDnCountryNotPrintableString {
    /// Creates the lint.
    pub fn new() -> Self {
        SubjectDnCountryNotPrintableString
    }
}

impl Lint for SubjectDnCountryNotPrintableString {
    fn id(&self) -> &'static str {
        "rfc5280_subject_dn_country_not_printable_string"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Rfc5280
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        // Scoped to certs whose subject DN has a countryName attribute. The
        // accessor returns `None` when no country attribute exists. Fail policy:
        // if the subject cannot be read, treat as out of scope (see module
        // docs).
        match cert.subject_country_is_printable_string() {
            Ok(Some(_)) => Applicability::Applies,
            Ok(None) | Err(_) => Applicability::NotApplicable,
        }
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // `applies` guarantees a country attribute exists. Fail policy: if the
        // encoding cannot be read, emit nothing (see module docs).
        match cert.subject_country_is_printable_string() {
            Ok(Some(false)) => vec![Finding {
                severity: Severity::Error,
                message: "subject countryName is not encoded as a PrintableString; \
                          RFC 5280 Appendix A (X520countryName) requires \
                          PrintableString"
                    .to_string(),
            }],
            Ok(Some(true)) | Ok(None) | Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    // good.pem: a leaf with NO countryName attribute — the lint is out of scope.
    const NO_COUNTRY_PEM: &[u8] = b"\
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

    fn load_one(pem: &[u8]) -> Cert {
        let mut certs = Cert::from_pem(pem).expect("fixture must parse");
        certs.pop().expect("fixture must contain one cert")
    }

    #[test]
    fn not_applicable_without_country_attribute() {
        let cert = load_one(NO_COUNTRY_PEM);
        assert_eq!(
            SubjectDnCountryNotPrintableString::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn passes_when_no_country_attribute() {
        // Without a country attribute the check yields no findings.
        let cert = load_one(NO_COUNTRY_PEM);
        assert!(
            SubjectDnCountryNotPrintableString::new()
                .check(&cert)
                .is_empty()
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SubjectDnCountryNotPrintableString::new();
        assert_eq!(lint.id(), "rfc5280_subject_dn_country_not_printable_string");
        assert_eq!(lint.source(), RuleSource::Rfc5280);
    }
}
