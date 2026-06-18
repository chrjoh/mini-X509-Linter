//! The `rfc5280_path_len_constraint_improperly_included` lint
//! (RFC 5280 §4.2.1.9).
//!
//! RFC 5280 §4.2.1.9: "CAs MUST NOT include the pathLenConstraint field unless
//! the cA boolean is asserted and the key usage extension asserts the
//! keyCertSign bit." A `pathLenConstraint` value is only meaningful on a CA
//! certificate that signs other certificates; its presence anywhere else is a
//! conformance error.
//!
//! This lint is scoped to certificates that carry a `pathLenConstraint` and
//! fails unless the certificate is a CA (`cA = TRUE`) whose Key Usage asserts
//! `keyCertSign`.

use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Flags a `pathLenConstraint` present on a non-CA / non-keyCertSign cert.
#[derive(Debug, Clone, Default)]
pub struct PathLenConstraintImproperlyIncluded;

impl PathLenConstraintImproperlyIncluded {
    /// Creates the lint.
    pub fn new() -> Self {
        PathLenConstraintImproperlyIncluded
    }
}

impl Lint for PathLenConstraintImproperlyIncluded {
    fn id(&self) -> &'static str {
        "rfc5280_path_len_constraint_improperly_included"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Rfc5280
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        // Scoped to certs whose Basic Constraints carry a pathLenConstraint.
        // Fail policy: if Basic Constraints cannot be read, treat as out of
        // scope (see module docs).
        match cert.basic_constraints() {
            Ok(Some(bc)) if bc.path_len.is_some() => Applicability::Applies,
            Ok(_) | Err(_) => Applicability::NotApplicable,
        }
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // `applies` guarantees a pathLenConstraint is present. The constraint is
        // only legitimate on a CA whose Key Usage asserts keyCertSign.
        //
        // Fail policy: if either CA-ness or Key Usage cannot be read, we cannot
        // safely declare the inclusion improper, so emit nothing (see module
        // docs).
        let is_ca = match cert.is_ca() {
            Ok(is_ca) => is_ca,
            Err(_) => return Vec::new(),
        };
        let key_cert_sign = match cert.key_usage() {
            Ok(Some(ku)) => ku.key_cert_sign,
            Ok(None) => false,
            Err(_) => return Vec::new(),
        };

        if is_ca && key_cert_sign {
            Vec::new()
        } else {
            vec![Finding {
                severity: Severity::Error,
                message: "pathLenConstraint is present but the certificate is not \
                          a CA asserting keyCertSign; RFC 5280 §4.2.1.9 forbids \
                          this"
                    .to_string(),
            }]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    // good.pem: a leaf with NO pathLenConstraint — the lint is out of scope.
    const NO_PATH_LEN_PEM: &[u8] = b"\
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
    fn not_applicable_without_path_len() {
        let cert = load_one(NO_PATH_LEN_PEM);
        assert_eq!(
            PathLenConstraintImproperlyIncluded::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = PathLenConstraintImproperlyIncluded::new();
        assert_eq!(lint.id(), "rfc5280_path_len_constraint_improperly_included");
        assert_eq!(lint.source(), RuleSource::Rfc5280);
    }
}
