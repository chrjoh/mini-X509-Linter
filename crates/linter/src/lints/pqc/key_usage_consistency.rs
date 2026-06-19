//! The `pqc_key_usage_consistency` lint.
//!
//! ML-DSA / SLH-DSA are **signature** algorithms, so the certificate's Key Usage
//! must be consistent with a signature key:
//!
//! - asserting any of the five encryption-class bits — `keyEncipherment`
//!   (bit 2), `dataEncipherment` (bit 3), `keyAgreement` (bit 4), `encipherOnly`
//!   (bit 7), or `decipherOnly` (bit 8) → **Error**. These bits are semantically
//!   wrong for a signature-only algorithm: a verifier that honoured them would
//!   mis-use the key for an encryption / key-establishment operation it cannot
//!   perform. Because each such bit is *actively wrong* (not merely missing), it
//!   is an Error; one finding is emitted per offending bit.
//! - an end-entity leaf (`CA:FALSE`) NOT asserting `digitalSignature` (bit 0) →
//!   **Warn**. A signature leaf SHOULD assert it, but some valid configurations
//!   omit it; an absent Key Usage extension on an EE is treated as the same
//!   missing-`digitalSignature` Warn.
//! - a CA NOT asserting `keyCertSign` (bit 5) → **Warn**. A signing CA SHOULD
//!   assert it, but unusual-but-valid CA Key Usage sets exist, so this stays a
//!   Warn to avoid false positives.
//!
//! Rationale for the split: an **Error** for the actively-wrong encryption bits
//! (the verifier-misuse hazard), a **Warn** for the absent-but-recommended
//! signing bits (a SHOULD, not a MUST). One [`check`](Lint::check) may emit
//! several findings — one per offending / missing bit, each named.
//!
//! Basis: RFC 5280 §4.2.1.3 (Key Usage bit semantics) + the IETF LAMPS ML-DSA /
//! SLH-DSA X.509 algorithm-identifier profile (RFC number TBC) treating these as
//! signature algorithms.
//!
//! PQC-SPKI-gated (see [`applies_to_pqc`]).

use super::applies_to_pqc;
use crate::cert::{Cert, KeyUsageView};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Checks a PQC signature key's Key Usage bits for consistency.
#[derive(Debug, Clone, Default)]
pub struct KeyUsageConsistency;

impl KeyUsageConsistency {
    /// Creates the lint.
    pub fn new() -> Self {
        KeyUsageConsistency
    }
}

/// Pure decision: turns the (optional) Key Usage view plus the CA flag into zero
/// or more findings (one per offending / missing bit).
///
/// `None` models an absent Key Usage extension; on an EE that yields the
/// missing-`digitalSignature` Warn. Kept separate so the logic is unit-testable
/// without constructing a certificate.
fn evaluate(key_usage: Option<KeyUsageView>, is_ca: bool) -> Vec<Finding> {
    let mut findings = Vec::new();

    // The actively-wrong encryption bits — Error (only checkable when KU exists).
    if let Some(ku) = key_usage {
        if ku.key_encipherment {
            findings.push(Finding {
                severity: Severity::Error,
                message: "the keyEncipherment key usage bit (RFC 5280 §4.2.1.3, bit 2) is \
                          asserted on an ML-DSA / SLH-DSA signature key, which cannot perform \
                          key encipherment"
                    .to_string(),
            });
        }
        if ku.data_encipherment {
            findings.push(Finding {
                severity: Severity::Error,
                message: "the dataEncipherment key usage bit (RFC 5280 §4.2.1.3, bit 3) is \
                          asserted on an ML-DSA / SLH-DSA signature key, which cannot perform \
                          data encipherment"
                    .to_string(),
            });
        }
        if ku.key_agreement {
            findings.push(Finding {
                severity: Severity::Error,
                message: "the keyAgreement key usage bit (RFC 5280 §4.2.1.3, bit 4) is asserted \
                          on an ML-DSA / SLH-DSA signature key, which cannot perform key \
                          agreement"
                    .to_string(),
            });
        }
        if ku.encipher_only {
            findings.push(Finding {
                severity: Severity::Error,
                message: "the encipherOnly key usage bit (RFC 5280 §4.2.1.3, bit 7) is asserted \
                          on an ML-DSA / SLH-DSA signature key, which cannot perform encipherment"
                    .to_string(),
            });
        }
        if ku.decipher_only {
            findings.push(Finding {
                severity: Severity::Error,
                message: "the decipherOnly key usage bit (RFC 5280 §4.2.1.3, bit 8) is asserted \
                          on an ML-DSA / SLH-DSA signature key, which cannot perform decipherment"
                    .to_string(),
            });
        }
    }

    // The absent-but-recommended signing bits — Warn.
    if is_ca {
        let asserts_key_cert_sign = key_usage.is_some_and(|ku| ku.key_cert_sign);
        if !asserts_key_cert_sign {
            findings.push(Finding {
                severity: Severity::Warn,
                message: "a CA certificate with an ML-DSA / SLH-DSA signature key should assert \
                          the keyCertSign key usage bit (RFC 5280 §4.2.1.3, bit 5)"
                    .to_string(),
            });
        }
    } else {
        let asserts_digital_signature = key_usage.is_some_and(|ku| ku.digital_signature);
        if !asserts_digital_signature {
            findings.push(Finding {
                severity: Severity::Warn,
                message: "an end-entity certificate with an ML-DSA / SLH-DSA signature key \
                          should assert the digitalSignature key usage bit (RFC 5280 §4.2.1.3, \
                          bit 0)"
                    .to_string(),
            });
        }
    }

    findings
}

impl Lint for KeyUsageConsistency {
    fn id(&self) -> &'static str {
        "pqc_key_usage_consistency"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Pqc
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_pqc(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: an unreadable Key Usage extension or basic-constraints
        // means we cannot evaluate; emit nothing.
        match (cert.key_usage(), cert.is_ca()) {
            (Ok(ku), Ok(is_ca)) => evaluate(ku, is_ca),
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    /// good.pem is an RSA TLS leaf — used only for scoping.
    fn good_cert() -> Cert {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
        let bytes = std::fs::read(path).unwrap();
        let mut certs = Cert::from_pem(&bytes).unwrap();
        certs.remove(0)
    }

    #[allow(clippy::too_many_arguments)]
    fn ku(
        digital_signature: bool,
        key_encipherment: bool,
        data_encipherment: bool,
        key_agreement: bool,
        key_cert_sign: bool,
        encipher_only: bool,
        decipher_only: bool,
    ) -> KeyUsageView {
        KeyUsageView {
            digital_signature,
            key_encipherment,
            data_encipherment,
            key_agreement,
            key_cert_sign,
            crl_sign: false,
            encipher_only,
            decipher_only,
            critical: true,
        }
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_clean_ee_signature_key() {
            let view = ku(true, false, false, false, false, false, false);
            assert!(evaluate(Some(view), false).is_empty());
        }

        #[test]
        fn passes_clean_ca_signature_key() {
            let view = ku(true, false, false, false, true, false, false);
            assert!(evaluate(Some(view), true).is_empty());
        }

        #[test]
        fn errors_on_key_encipherment() {
            let view = ku(true, true, false, false, false, false, false);
            let findings = evaluate(Some(view), false);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }

        #[test]
        fn errors_on_key_agreement() {
            let view = ku(true, false, false, true, false, false, false);
            let findings = evaluate(Some(view), false);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }

        #[test]
        fn errors_on_data_encipherment() {
            // Setup: a signature EE asserting dataEncipherment (bit 3).
            let view = ku(true, false, true, false, false, false, false);
            // Invoke
            let findings = evaluate(Some(view), false);
            // Find & Expect: exactly one Error for the wrong bit.
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("dataEncipherment"));
        }

        #[test]
        fn errors_on_encipher_only() {
            // Setup: a signature EE asserting encipherOnly (bit 7).
            let view = ku(true, false, false, false, false, true, false);
            // Invoke
            let findings = evaluate(Some(view), false);
            // Find & Expect
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("encipherOnly"));
        }

        #[test]
        fn errors_on_decipher_only() {
            // Setup: a signature EE asserting decipherOnly (bit 8).
            let view = ku(true, false, false, false, false, false, true);
            // Invoke
            let findings = evaluate(Some(view), false);
            // Find & Expect
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("decipherOnly"));
        }

        #[test]
        fn warns_ee_missing_digital_signature() {
            let view = ku(false, false, false, false, false, false, false);
            let findings = evaluate(Some(view), false);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Warn);
        }

        #[test]
        fn warns_ca_missing_key_cert_sign() {
            let view = ku(true, false, false, false, false, false, false);
            let findings = evaluate(Some(view), true);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Warn);
        }

        #[test]
        fn absent_key_usage_on_ee_warns_missing_digital_signature() {
            let findings = evaluate(None, false);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Warn);
        }

        #[test]
        fn emits_multiple_findings_for_multiple_offences() {
            // All five encryption-class wrong-bits asserted AND missing
            // digitalSignature on an EE: 5 Errors + 1 Warn.
            let view = ku(false, true, true, true, false, true, true);
            let findings = evaluate(Some(view), false);
            assert_eq!(findings.len(), 6);
            let errors = findings
                .iter()
                .filter(|f| f.severity == Severity::Error)
                .count();
            let warnings = findings
                .iter()
                .filter(|f| f.severity == Severity::Warn)
                .count();
            assert_eq!(errors, 5);
            assert_eq!(warnings, 1);
        }
    }

    #[test]
    fn not_applicable_for_non_pqc_leaf() {
        let cert = good_cert();
        assert_eq!(
            KeyUsageConsistency::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = KeyUsageConsistency::new();
        assert_eq!(lint.id(), "pqc_key_usage_consistency");
        assert_eq!(lint.source(), RuleSource::Pqc);
    }
}
