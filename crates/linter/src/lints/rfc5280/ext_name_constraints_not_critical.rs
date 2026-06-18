//! The `rfc5280_ext_name_constraints_not_critical` lint (RFC 5280 §4.2.1.10).
//!
//! RFC 5280 §4.2.1.10: "Conforming CAs MUST mark this extension as critical
//! [...]" — i.e. whenever the Name Constraints extension is present it MUST be
//! marked critical.
//!
//! This lint is scoped to certificates that carry a Name Constraints extension
//! and fails when that extension is not marked critical.

use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires a present Name Constraints extension to be marked critical.
#[derive(Debug, Clone, Default)]
pub struct ExtNameConstraintsNotCritical;

impl ExtNameConstraintsNotCritical {
    /// Creates the lint.
    pub fn new() -> Self {
        ExtNameConstraintsNotCritical
    }
}

impl Lint for ExtNameConstraintsNotCritical {
    fn id(&self) -> &'static str {
        "rfc5280_ext_name_constraints_not_critical"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Rfc5280
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        // Scoped to certs that carry a Name Constraints extension. Fail policy:
        // if the extension cannot be read, treat as out of scope (see module
        // docs).
        match cert.name_constraints() {
            Ok(Some(_)) => Applicability::Applies,
            Ok(None) | Err(_) => Applicability::NotApplicable,
        }
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // `applies` guarantees a Name Constraints extension exists. Fail policy:
        // unreadable extension means we cannot evaluate; emit nothing (see
        // module docs).
        let nc = match cert.name_constraints() {
            Ok(Some(nc)) => nc,
            Ok(None) | Err(_) => return Vec::new(),
        };

        if nc.critical {
            Vec::new()
        } else {
            vec![Finding {
                severity: Severity::Error,
                message: "NameConstraints extension is present but not marked \
                          critical; RFC 5280 §4.2.1.10 requires it to be critical"
                    .to_string(),
            }]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    // good.pem: a leaf with NO Name Constraints — the lint is out of scope.
    const NO_NAME_CONSTRAINTS_PEM: &[u8] = b"\
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
    fn not_applicable_without_name_constraints() {
        let cert = load_one(NO_NAME_CONSTRAINTS_PEM);
        assert_eq!(
            ExtNameConstraintsNotCritical::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = ExtNameConstraintsNotCritical::new();
        assert_eq!(lint.id(), "rfc5280_ext_name_constraints_not_critical");
        assert_eq!(lint.source(), RuleSource::Rfc5280);
    }
}
