//! The `rfc5280_san_present_if_subject_empty` lint (RFC 5280 §4.1.2.6 / §4.2.1.6).
//!
//! RFC 5280 §4.1.2.6: "If the subject is a CA [...] then the subject field MUST
//! be populated [...] Otherwise, the subject name MAY be an empty sequence [...]
//! If the subject field contains an empty sequence, then the issuing CA MUST
//! include a subjectAltName extension that is marked as critical." RFC 5280
//! §4.2.1.6 reiterates that SAN MUST be critical when the subject is empty.
//!
//! This lint is scoped to certificates whose subject DN is empty and fails when
//! either no SAN is present or the SAN is present but not marked critical.

use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires a critical SAN whenever the subject DN is empty.
#[derive(Debug, Clone, Default)]
pub struct SanPresentIfSubjectEmpty;

impl SanPresentIfSubjectEmpty {
    /// Creates the lint.
    pub fn new() -> Self {
        SanPresentIfSubjectEmpty
    }
}

impl Lint for SanPresentIfSubjectEmpty {
    fn id(&self) -> &'static str {
        "rfc5280_san_present_if_subject_empty"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Rfc5280
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        // Scoped to empty-subject certificates. Fail policy: if subject
        // emptiness cannot be determined, treat the rule as out of scope rather
        // than guessing (see module docs).
        match cert.subject_is_empty() {
            Ok(true) => Applicability::Applies,
            Ok(false) | Err(_) => Applicability::NotApplicable,
        }
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // `applies` guarantees the subject DN is empty. Fail policy: unreadable
        // SAN means we cannot evaluate; emit nothing (see module docs).
        let san = match cert.subject_alt_name() {
            Ok(san) => san,
            Err(_) => return Vec::new(),
        };

        match san {
            None => vec![Finding {
                severity: Severity::Error,
                message: "subject DN is empty but no subjectAltName extension is present; \
                          RFC 5280 §4.1.2.6 requires a critical SAN in this case"
                    .to_string(),
            }],
            Some(san) if !san.critical => vec![Finding {
                severity: Severity::Error,
                message: "subject DN is empty but subjectAltName is not marked critical; \
                          RFC 5280 §4.2.1.6 requires the SAN to be critical in this case"
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

    // A cert with a non-empty subject (CN=good.example): the lint is out of
    // scope for it.
    const NON_EMPTY_SUBJECT_PEM: &[u8] = b"\
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
    fn not_applicable_when_subject_present() {
        let cert = load_one(NON_EMPTY_SUBJECT_PEM);
        assert_eq!(
            SanPresentIfSubjectEmpty::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = SanPresentIfSubjectEmpty::new();
        assert_eq!(lint.id(), "rfc5280_san_present_if_subject_empty");
        assert_eq!(lint.source(), RuleSource::Rfc5280);
    }
}
