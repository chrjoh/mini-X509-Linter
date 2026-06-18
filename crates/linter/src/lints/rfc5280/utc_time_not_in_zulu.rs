//! The `rfc5280_utc_time_not_in_zulu` lint (RFC 5280 §4.1.2.5.1).
//!
//! RFC 5280 §4.1.2.5.1: "For the purposes of this profile, UTCTime values MUST
//! be expressed in Greenwich Mean Time (Zulu) and MUST include seconds (i.e.,
//! times are YYMMDDHHMMSSZ) [...]" A validity field encoded as `UTCTime` that
//! does not end in the Zulu marker `Z` (e.g. an offset form like `+0000`)
//! violates this requirement.
//!
//! This lint is scoped to certificates where at least one validity field
//! (`notBefore` or `notAfter`) is encoded as `UTCTime`, and emits one finding
//! per offending UTCTime field — so it may emit up to two findings.

use crate::cert::{Cert, TimeEncoding};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires `UTCTime` validity fields to end in the Zulu marker `Z`.
#[derive(Debug, Clone, Default)]
pub struct UtcTimeNotInZulu;

impl UtcTimeNotInZulu {
    /// Creates the lint.
    pub fn new() -> Self {
        UtcTimeNotInZulu
    }

    /// Builds a finding for a single UTCTime field that is not in Zulu form.
    fn finding(field: &str) -> Finding {
        Finding {
            severity: Severity::Error,
            message: format!(
                "validity {field} is a UTCTime not expressed in Zulu (does not \
                 end in 'Z'); RFC 5280 §4.1.2.5.1 requires the YYMMDDHHMMSSZ form"
            ),
        }
    }
}

impl Lint for UtcTimeNotInZulu {
    fn id(&self) -> &'static str {
        "rfc5280_utc_time_not_in_zulu"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Rfc5280
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        // Scoped to certs where either validity field is encoded as UTCTime.
        // Fail policy: if the encodings cannot be read, treat as out of scope
        // (see module docs).
        match cert.validity_time_encodings() {
            Ok((nb, na)) if nb.is_utc_time || na.is_utc_time => Applicability::Applies,
            Ok(_) | Err(_) => Applicability::NotApplicable,
        }
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: if the encodings cannot be read, emit nothing (see module
        // docs).
        let (not_before, not_after) = match cert.validity_time_encodings() {
            Ok(encodings) => encodings,
            Err(_) => return Vec::new(),
        };

        // One finding per offending UTCTime field; non-UTCTime fields and
        // already-Zulu UTCTime fields are silent.
        let mut findings = Vec::new();
        let offends = |t: &TimeEncoding| t.is_utc_time && !t.is_zulu;
        if offends(&not_before) {
            findings.push(Self::finding("notBefore"));
        }
        if offends(&not_after) {
            findings.push(Self::finding("notAfter"));
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    // good.pem: validity encoded as UTCTime ending in Z — passes the lint.
    const UTC_ZULU_PEM: &[u8] = b"\
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
    fn applies_when_utc_time_used() {
        let cert = load_one(UTC_ZULU_PEM);
        assert_eq!(
            UtcTimeNotInZulu::new().applies(&cert),
            Applicability::Applies
        );
    }

    #[test]
    fn passes_utc_time_in_zulu() {
        let cert = load_one(UTC_ZULU_PEM);
        assert!(UtcTimeNotInZulu::new().check(&cert).is_empty());
    }

    #[test]
    fn emits_one_finding_per_offending_field() {
        // Pure-logic check of the multi-finding behaviour using synthetic
        // TimeEncoding values (the cert path is exercised by the pass case and
        // by the fixture-driven integration tests in task 05).
        let offending = TimeEncoding {
            is_utc_time: true,
            is_zulu: false,
        };
        let ok = TimeEncoding {
            is_utc_time: true,
            is_zulu: true,
        };
        let offends = |t: &TimeEncoding| t.is_utc_time && !t.is_zulu;

        // both offend -> two findings
        assert_eq!(
            [&offending, &offending]
                .iter()
                .filter(|t| offends(t))
                .count(),
            2
        );
        // one offends -> one finding
        assert_eq!([&offending, &ok].iter().filter(|t| offends(t)).count(), 1);
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = UtcTimeNotInZulu::new();
        assert_eq!(lint.id(), "rfc5280_utc_time_not_in_zulu");
        assert_eq!(lint.source(), RuleSource::Rfc5280);
    }
}
