//! The `pqc_mlkem_key_usage_consistency` lint.
//!
//! ML-KEM is a **key-establishment (KEM)** algorithm — an *encryption-only* key.
//! Its Key Usage consistency rule is the **inverse** of the PQC *signature* rule
//! (`pqc_key_usage_consistency`):
//!
//! - asserting `digitalSignature` (bit 0), `keyCertSign` (bit 5) or `cRLSign`
//!   (bit 6) → **Error** (one finding per offending bit, each named). These
//!   signing bits are *actively wrong* for a KEM key: a verifier honouring them
//!   would mis-use the key for an operation it cannot perform. The Error applies
//!   **regardless of the CA flag** — an ML-KEM key cannot sign, so there is no
//!   "a CA SHOULD assert keyCertSign" Warn here (that would directly contradict
//!   the forbidden-signing-bit rule).
//! - an end-entity leaf (`CA:FALSE`) asserting **neither** `keyEncipherment`
//!   (bit 2) **nor** `keyAgreement` (bit 4) → **Warn**. A KEM end-entity SHOULD
//!   assert at least one (ML-KEM is used for key establishment; both spellings
//!   appear across profiles). An absent Key Usage extension on an EE is treated as
//!   the same missing-encryption-bit Warn.
//!
//! `dataEncipherment` (bit 3) is **permitted-but-discouraged**: it is a legacy
//! bulk-encryption bit, not how ML-KEM is used. We deliberately do **not** flag it
//! here, to keep the lint conservative and avoid false positives (documented per
//! the feature 16 plan, Open Question 2).
//!
//! Rationale for the split mirrors the signature rule: **Error** for the
//! actively-wrong signing bits (the verifier-misuse hazard), **Warn** for the
//! absent-but-recommended encryption bit (a SHOULD, not a MUST). One
//! [`check`](Lint::check) may emit several findings — one per offending / missing
//! bit, each named.
//!
//! Basis: RFC 5280 §4.2.1.3 (Key Usage bit semantics) + the IETF LAMPS ML-KEM
//! X.509 algorithm-identifier profile (NIST FIPS 203, RFC/draft number TBC)
//! treating ML-KEM as a key-establishment algorithm.
//!
//! ML-KEM-SPKI-gated (see [`applies_to_mlkem`](super::applies_to_mlkem)).

use super::applies_to_mlkem;
use crate::cert::{Cert, KeyUsageView};
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Checks an ML-KEM key's Key Usage bits for consistency.
#[derive(Debug, Clone, Default)]
pub struct MlKemKeyUsageConsistency;

impl MlKemKeyUsageConsistency {
    /// Creates the lint.
    pub fn new() -> Self {
        MlKemKeyUsageConsistency
    }
}

/// Pure decision: turns the (optional) Key Usage view plus the CA flag into zero
/// or more findings (one per offending / missing bit).
///
/// `None` models an absent Key Usage extension; on an EE that yields the
/// missing-encryption-bit Warn. Kept separate so the logic is unit-testable
/// without constructing a certificate.
fn evaluate(key_usage: Option<KeyUsageView>, is_ca: bool) -> Vec<Finding> {
    let mut findings = Vec::new();

    // The actively-wrong signing bits — Error (only checkable when KU exists).
    // These apply regardless of the CA flag: an ML-KEM key cannot sign.
    if let Some(ku) = key_usage {
        if ku.digital_signature {
            findings.push(Finding {
                severity: Severity::Error,
                message: "the digitalSignature key usage bit (RFC 5280 §4.2.1.3, bit 0) is \
                          asserted on an ML-KEM key-establishment key, which cannot sign"
                    .to_string(),
            });
        }
        if ku.key_cert_sign {
            findings.push(Finding {
                severity: Severity::Error,
                message: "the keyCertSign key usage bit (RFC 5280 §4.2.1.3, bit 5) is asserted \
                          on an ML-KEM key-establishment key, which cannot sign certificates"
                    .to_string(),
            });
        }
        if ku.crl_sign {
            findings.push(Finding {
                severity: Severity::Error,
                message: "the cRLSign key usage bit (RFC 5280 §4.2.1.3, bit 6) is asserted on \
                          an ML-KEM key-establishment key, which cannot sign CRLs"
                    .to_string(),
            });
        }
    }

    // The absent-but-recommended encryption bits — Warn (end-entity only).
    if !is_ca {
        let asserts_key_establishment =
            key_usage.is_some_and(|ku| ku.key_encipherment || ku.key_agreement);
        if !asserts_key_establishment {
            findings.push(Finding {
                severity: Severity::Warn,
                message: "an end-entity ML-KEM certificate should assert at least one of the \
                          keyEncipherment (RFC 5280 §4.2.1.3, bit 2) or keyAgreement (bit 4) \
                          key usage bits for key establishment"
                    .to_string(),
            });
        }
    }

    findings
}

impl Lint for MlKemKeyUsageConsistency {
    fn id(&self) -> &'static str {
        "pqc_mlkem_key_usage_consistency"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Pqc
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_mlkem(cert)
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

    /// Builds a `KeyUsageView` literal for the bits this lint reads; the unread
    /// bits are left `false`.
    fn ku(
        digital_signature: bool,
        key_encipherment: bool,
        key_agreement: bool,
        key_cert_sign: bool,
        crl_sign: bool,
    ) -> KeyUsageView {
        KeyUsageView {
            digital_signature,
            key_encipherment,
            data_encipherment: false,
            key_agreement,
            key_cert_sign,
            crl_sign,
            encipher_only: false,
            decipher_only: false,
            critical: true,
        }
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_clean_ee_kem_key_with_key_encipherment() {
            let view = ku(false, true, false, false, false);
            assert!(evaluate(Some(view), false).is_empty());
        }

        #[test]
        fn passes_clean_ee_kem_key_with_key_agreement() {
            let view = ku(false, false, true, false, false);
            assert!(evaluate(Some(view), false).is_empty());
        }

        #[test]
        fn errors_on_digital_signature() {
            let view = ku(true, true, false, false, false);
            let findings = evaluate(Some(view), false);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }

        #[test]
        fn errors_on_key_cert_sign_regardless_of_ca() {
            // keyCertSign is an Error on a CA too — and the missing-encryption
            // Warn is suppressed for a CA, so this is the only finding.
            let view = ku(false, true, false, true, false);
            let findings = evaluate(Some(view), true);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }

        #[test]
        fn errors_on_crl_sign() {
            let view = ku(false, true, false, false, true);
            let findings = evaluate(Some(view), false);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
        }

        #[test]
        fn warns_ee_missing_both_encryption_bits() {
            let view = ku(false, false, false, false, false);
            let findings = evaluate(Some(view), false);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Warn);
        }

        #[test]
        fn absent_key_usage_on_ee_warns_missing_encryption_bits() {
            let findings = evaluate(None, false);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Warn);
        }

        #[test]
        fn ca_without_encryption_bits_does_not_warn() {
            // The missing-encryption Warn is end-entity only; an absent KU on a
            // CA yields no finding.
            assert!(evaluate(None, true).is_empty());
        }

        #[test]
        fn does_not_flag_data_encipherment() {
            // dataEncipherment is permitted-but-discouraged — not flagged. With
            // keyEncipherment also set there is no missing-encryption Warn either.
            let view = KeyUsageView {
                digital_signature: false,
                key_encipherment: true,
                data_encipherment: true,
                key_agreement: false,
                key_cert_sign: false,
                crl_sign: false,
                encipher_only: false,
                decipher_only: false,
                critical: true,
            };
            assert!(evaluate(Some(view), false).is_empty());
        }

        #[test]
        fn emits_multiple_findings_for_multiple_offences() {
            // All three signing bits asserted AND no encryption bit on an EE.
            let view = ku(true, false, false, true, true);
            let findings = evaluate(Some(view), false);
            assert_eq!(findings.len(), 4);
            let errors = findings
                .iter()
                .filter(|f| f.severity == Severity::Error)
                .count();
            let warnings = findings
                .iter()
                .filter(|f| f.severity == Severity::Warn)
                .count();
            assert_eq!(errors, 3);
            assert_eq!(warnings, 1);
        }
    }

    #[test]
    fn not_applicable_for_non_mlkem_leaf() {
        let cert = good_cert();
        assert_eq!(
            MlKemKeyUsageConsistency::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = MlKemKeyUsageConsistency::new();
        assert_eq!(lint.id(), "pqc_mlkem_key_usage_consistency");
        assert_eq!(lint.source(), RuleSource::Pqc);
    }
}
