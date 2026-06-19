//! Isolated signature-verification dispatch for `chain_signature_valid`
//! (RFC 5280 §4.1.1.3). **Contains ALL crypto-crate usage** so the `ring` /
//! `fips204` / `fips205` dependencies are confined to this one
//! `#[cfg(feature = "verify")]` module.
//!
//! The single entry point `verify_signature` maps a signature-algorithm OID to
//! the right pure-Rust backend and returns a `VerifyOutcome`:
//!
//! - **`ring`** — RSA PKCS#1 v1.5 + SHA-256/384/512; ECDSA P-256+SHA-256 and
//!   P-384+SHA-384; Ed25519.
//! - **`fips204`** — ML-DSA-44 / 65 / 87 (FIPS 204).
//! - **`fips205`** — SLH-DSA SHA2 / SHAKE parameter sets (FIPS 205).
//!
//! # Fail-open policy
//!
//! Any algorithm NOT in the matrix above maps to `VerifyOutcome::Unsupported`
//! — never `VerifyOutcome::Failed`. We make NO claim about an algorithm our
//! backends cannot check (notably RSA-PSS and ECDSA P-521, which `ring` does not
//! verify here). The OID → backend mapping is the single source of truth for
//! "supported" vs "Unsupported".
//!
//! # Panic-freedom
//!
//! Malformed inputs (an unparseable SPKI, a wrong-length signature, a key that a
//! backend rejects) degrade to `VerifyOutcome::Failed` or
//! `VerifyOutcome::Unsupported` — never a panic. Specifically, an SPKI that
//! cannot be parsed at all maps to `Unsupported` (we cannot even identify the
//! key); a parseable key whose signature does not check maps to `Failed`.
//!
//! # Maturity caveat
//!
//! `fips204` / `fips205` are pre-1.0 and generally unaudited. That is acceptable
//! here: this module verifies signatures over PUBLIC certificate data, never
//! protects secrets.

use ring::signature;
use x509_parser::prelude::FromDer;
use x509_parser::x509::SubjectPublicKeyInfo;

/// The result of attempting to verify one certificate signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyOutcome {
    /// The signature verified against the issuer's public key.
    Verified,
    /// The signature did NOT verify (a forged / mismatched / corrupted link, or
    /// a malformed key/signature for a SUPPORTED algorithm).
    Failed,
    /// The algorithm is not in the supported matrix; no claim is made (fail-open).
    Unsupported,
}

// Classical signature-algorithm OIDs (dotted form).
const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const OID_RSA_SHA384: &str = "1.2.840.113549.1.1.12";
const OID_RSA_SHA512: &str = "1.2.840.113549.1.1.13";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_ED25519: &str = "1.3.101.112";

// EC named-curve OIDs (in the SPKI parameters).
const OID_CURVE_P256: &str = "1.2.840.10045.3.1.7";
const OID_CURVE_P384: &str = "1.3.132.0.34";

// The shared NIST sigAlgs arc for ML-DSA / SLH-DSA.
const PQC_ARC_PREFIX: &str = "2.16.840.1.101.3.4.3.";

/// Verifies `signature` over `tbs_der` against the public key in `issuer_spki`,
/// dispatching on `sig_alg_oid` (the subject cert's outer signatureAlgorithm OID
/// in dotted form).
///
/// `issuer_spki` is the full `SubjectPublicKeyInfo` DER of the issuer cert (as
/// returned by `Cert::issuer_spki_bytes`).
pub(crate) fn verify_signature(
    sig_alg_oid: &str,
    tbs_der: &[u8],
    signature: &[u8],
    issuer_spki: &[u8],
) -> VerifyOutcome {
    // Parse the SPKI to recover the algorithm OID and the raw public-key bytes
    // (the subjectPublicKey BIT STRING content). An unparseable SPKI → we cannot
    // identify the key → Unsupported (fail-open).
    let Ok((_rest, spki)) = SubjectPublicKeyInfo::from_der(issuer_spki) else {
        return VerifyOutcome::Unsupported;
    };
    let key_bytes: &[u8] = &spki.subject_public_key.data;
    let key_alg_oid = spki.algorithm.algorithm.to_string();

    match sig_alg_oid {
        OID_RSA_SHA256 => verify_ring(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            key_bytes,
            tbs_der,
            signature,
        ),
        OID_RSA_SHA384 => verify_ring(
            &signature::RSA_PKCS1_2048_8192_SHA384,
            key_bytes,
            tbs_der,
            signature,
        ),
        OID_RSA_SHA512 => verify_ring(
            &signature::RSA_PKCS1_2048_8192_SHA512,
            key_bytes,
            tbs_der,
            signature,
        ),
        OID_ECDSA_SHA256 => {
            // Curve must be P-256 for SHA-256 per the supported matrix.
            if !spki_curve_is(&spki, OID_CURVE_P256) {
                return VerifyOutcome::Unsupported;
            }
            verify_ring(
                &signature::ECDSA_P256_SHA256_ASN1,
                key_bytes,
                tbs_der,
                signature,
            )
        }
        OID_ECDSA_SHA384 => {
            if !spki_curve_is(&spki, OID_CURVE_P384) {
                return VerifyOutcome::Unsupported;
            }
            verify_ring(
                &signature::ECDSA_P384_SHA384_ASN1,
                key_bytes,
                tbs_der,
                signature,
            )
        }
        OID_ED25519 => verify_ring(&signature::ED25519, key_bytes, tbs_der, signature),
        other => {
            // ML-DSA / SLH-DSA share the sigAlgs arc; the public key OID equals
            // the signature OID for these. Dispatch on the slot.
            if let Some(outcome) = verify_pqc(other, &key_alg_oid, key_bytes, tbs_der, signature) {
                outcome
            } else {
                // Anything else (RSA-PSS 1.2.840.113549.1.1.10, ECDSA-SHA512,
                // P-521, unknown OIDs) is fail-open Unsupported.
                VerifyOutcome::Unsupported
            }
        }
    }
}

/// Verifies a classical signature via `ring`'s `UnparsedPublicKey`.
///
/// For RSA the `key_bytes` are the DER PKCS#1 `RSAPublicKey` (the SPKI BIT STRING
/// content); for ECDSA the raw uncompressed point; for Ed25519 the 32-byte key —
/// each exactly what `ring` expects for the chosen algorithm. A verification
/// error (bad key, wrong-length signature, or a genuine mismatch) → `Failed`.
fn verify_ring(
    alg: &'static dyn signature::VerificationAlgorithm,
    key_bytes: &[u8],
    message: &[u8],
    signature: &[u8],
) -> VerifyOutcome {
    let key = signature::UnparsedPublicKey::new(alg, key_bytes);
    match key.verify(message, signature) {
        Ok(()) => VerifyOutcome::Verified,
        Err(_) => VerifyOutcome::Failed,
    }
}

/// Whether the SPKI's EC named-curve parameter equals `want_oid`.
fn spki_curve_is(spki: &SubjectPublicKeyInfo<'_>, want_oid: &str) -> bool {
    use x509_parser::asn1_rs::Oid;
    let Some(params) = spki.algorithm.parameters.as_ref() else {
        return false;
    };
    let Ok(oid) = Oid::try_from(params) else {
        return false;
    };
    oid.to_string() == want_oid
}

/// Dispatches a PQC signature OID (ML-DSA / SLH-DSA) to `fips204` / `fips205`.
///
/// Returns `None` when `sig_oid` is not a recognized PQC parameter-set OID (so
/// the caller falls through to `Unsupported`). For ML-DSA / SLH-DSA the public
/// key OID (`key_alg_oid`) must match the signature OID; a mismatch → `Failed`
/// (the presented key is not for this algorithm). A wrong-length key or signature
/// → `Failed`.
fn verify_pqc(
    sig_oid: &str,
    key_alg_oid: &str,
    key_bytes: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Option<VerifyOutcome> {
    let suffix = sig_oid.strip_prefix(PQC_ARC_PREFIX)?;
    if suffix.contains('.') {
        return None;
    }
    let slot: u32 = suffix.parse().ok()?;

    // The SPKI key algorithm must be the same PQC algorithm as the signature.
    if key_alg_oid != sig_oid {
        return Some(VerifyOutcome::Failed);
    }

    match slot {
        // ML-DSA (FIPS 204).
        17 => Some(verify_ml_dsa_44(key_bytes, message, signature)),
        18 => Some(verify_ml_dsa_65(key_bytes, message, signature)),
        19 => Some(verify_ml_dsa_87(key_bytes, message, signature)),
        // SLH-DSA (FIPS 205) — the 12 published parameter sets .20..=.31.
        20 => Some(verify_slh::<fips205::slh_dsa_sha2_128s::PublicKey>(
            key_bytes, message, signature,
        )),
        21 => Some(verify_slh::<fips205::slh_dsa_sha2_128f::PublicKey>(
            key_bytes, message, signature,
        )),
        22 => Some(verify_slh::<fips205::slh_dsa_sha2_192s::PublicKey>(
            key_bytes, message, signature,
        )),
        23 => Some(verify_slh::<fips205::slh_dsa_sha2_192f::PublicKey>(
            key_bytes, message, signature,
        )),
        24 => Some(verify_slh::<fips205::slh_dsa_sha2_256s::PublicKey>(
            key_bytes, message, signature,
        )),
        25 => Some(verify_slh::<fips205::slh_dsa_sha2_256f::PublicKey>(
            key_bytes, message, signature,
        )),
        26 => Some(verify_slh::<fips205::slh_dsa_shake_128s::PublicKey>(
            key_bytes, message, signature,
        )),
        27 => Some(verify_slh::<fips205::slh_dsa_shake_128f::PublicKey>(
            key_bytes, message, signature,
        )),
        28 => Some(verify_slh::<fips205::slh_dsa_shake_192s::PublicKey>(
            key_bytes, message, signature,
        )),
        29 => Some(verify_slh::<fips205::slh_dsa_shake_192f::PublicKey>(
            key_bytes, message, signature,
        )),
        30 => Some(verify_slh::<fips205::slh_dsa_shake_256s::PublicKey>(
            key_bytes, message, signature,
        )),
        31 => Some(verify_slh::<fips205::slh_dsa_shake_256f::PublicKey>(
            key_bytes, message, signature,
        )),
        // Reserved-but-unassigned SLH-DSA slots and anything else: not verifiable.
        _ => None,
    }
}

/// Verifies an ML-DSA-44 signature via `fips204`. A wrong-length key or signature
/// → `Failed`. The X.509 ML-DSA context string is empty.
fn verify_ml_dsa_44(key_bytes: &[u8], message: &[u8], signature: &[u8]) -> VerifyOutcome {
    use fips204::ml_dsa_44;
    use fips204::traits::{SerDes, Verifier};

    let Ok(pk_arr) = <[u8; ml_dsa_44::PK_LEN]>::try_from(key_bytes) else {
        return VerifyOutcome::Failed;
    };
    let Ok(sig_arr) = <[u8; ml_dsa_44::SIG_LEN]>::try_from(signature) else {
        return VerifyOutcome::Failed;
    };
    let Ok(pk) = ml_dsa_44::PublicKey::try_from_bytes(pk_arr) else {
        return VerifyOutcome::Failed;
    };
    if pk.verify(message, &sig_arr, &[]) {
        VerifyOutcome::Verified
    } else {
        VerifyOutcome::Failed
    }
}

/// Verifies an ML-DSA-65 signature via `fips204`.
fn verify_ml_dsa_65(key_bytes: &[u8], message: &[u8], signature: &[u8]) -> VerifyOutcome {
    use fips204::ml_dsa_65;
    use fips204::traits::{SerDes, Verifier};

    let Ok(pk_arr) = <[u8; ml_dsa_65::PK_LEN]>::try_from(key_bytes) else {
        return VerifyOutcome::Failed;
    };
    let Ok(sig_arr) = <[u8; ml_dsa_65::SIG_LEN]>::try_from(signature) else {
        return VerifyOutcome::Failed;
    };
    let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(pk_arr) else {
        return VerifyOutcome::Failed;
    };
    if pk.verify(message, &sig_arr, &[]) {
        VerifyOutcome::Verified
    } else {
        VerifyOutcome::Failed
    }
}

/// Verifies an ML-DSA-87 signature via `fips204`.
fn verify_ml_dsa_87(key_bytes: &[u8], message: &[u8], signature: &[u8]) -> VerifyOutcome {
    use fips204::ml_dsa_87;
    use fips204::traits::{SerDes, Verifier};

    let Ok(pk_arr) = <[u8; ml_dsa_87::PK_LEN]>::try_from(key_bytes) else {
        return VerifyOutcome::Failed;
    };
    let Ok(sig_arr) = <[u8; ml_dsa_87::SIG_LEN]>::try_from(signature) else {
        return VerifyOutcome::Failed;
    };
    let Ok(pk) = ml_dsa_87::PublicKey::try_from_bytes(pk_arr) else {
        return VerifyOutcome::Failed;
    };
    if pk.verify(message, &sig_arr, &[]) {
        VerifyOutcome::Verified
    } else {
        VerifyOutcome::Failed
    }
}

/// Verifies an SLH-DSA signature via `fips205`, generic over the parameter-set
/// public-key type. A wrong-length key or signature → `Failed`. The X.509
/// SLH-DSA context string is empty.
fn verify_slh<P>(key_bytes: &[u8], message: &[u8], signature: &[u8]) -> VerifyOutcome
where
    P: fips205::traits::SerDes + fips205::traits::Verifier,
    <P as fips205::traits::SerDes>::ByteArray: for<'a> TryFrom<&'a [u8]>,
    <P as fips205::traits::Verifier>::Signature: for<'a> TryFrom<&'a [u8]>,
{
    let Ok(pk_arr) = <P as fips205::traits::SerDes>::ByteArray::try_from(key_bytes) else {
        return VerifyOutcome::Failed;
    };
    let Ok(sig_arr) =
        <<P as fips205::traits::Verifier>::Signature as TryFrom<&[u8]>>::try_from(signature)
    else {
        return VerifyOutcome::Failed;
    };
    let Ok(pk) = P::try_from_bytes(&pk_arr) else {
        return VerifyOutcome::Failed;
    };
    if pk.verify(message, &sig_arr, &[]) {
        VerifyOutcome::Verified
    } else {
        VerifyOutcome::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    fn load_one(pem: &[u8]) -> Cert {
        let mut certs = Cert::from_pem(pem).expect("fixture must parse");
        certs.pop().expect("fixture must contain one cert")
    }

    // A self-signed RSA-2048 / SHA-256 cert: its self-signature verifies against
    // its own SPKI, exercising the RSA PKCS#1 v1.5 + SHA-256 path end-to-end.
    const SELF_SIGNED_RSA_PEM: &[u8] = include_bytes!("../../chain_testdata/link_root.pem");
    // A real leaf→inter link (RSA): leaf's signature verifies against inter's key.
    const LEAF_PEM: &[u8] = include_bytes!("../../chain_testdata/link_leaf.pem");
    const INTER_PEM: &[u8] = include_bytes!("../../chain_testdata/link_inter.pem");

    #[test]
    fn known_good_rsa_self_signature_verifies() {
        let cert = load_one(SELF_SIGNED_RSA_PEM);
        let oid = cert.signature_algorithm_oid().unwrap();
        let tbs = cert.tbs_der().unwrap();
        let sig = cert.signature_value_bytes().unwrap();
        let spki = cert.issuer_spki_bytes().unwrap();
        assert_eq!(
            verify_signature(&oid, &tbs, &sig, &spki),
            VerifyOutcome::Verified
        );
    }

    #[test]
    fn real_leaf_signature_verifies_against_intermediate() {
        let leaf = load_one(LEAF_PEM);
        let inter = load_one(INTER_PEM);
        let oid = leaf.signature_algorithm_oid().unwrap();
        let tbs = leaf.tbs_der().unwrap();
        let sig = leaf.signature_value_bytes().unwrap();
        let spki = inter.issuer_spki_bytes().unwrap();
        assert_eq!(
            verify_signature(&oid, &tbs, &sig, &spki),
            VerifyOutcome::Verified
        );
    }

    #[test]
    fn corrupted_signature_fails() {
        let cert = load_one(SELF_SIGNED_RSA_PEM);
        let oid = cert.signature_algorithm_oid().unwrap();
        let tbs = cert.tbs_der().unwrap();
        let mut sig = cert.signature_value_bytes().unwrap();
        // Flip a bit in the signature.
        sig[0] ^= 0x01;
        let spki = cert.issuer_spki_bytes().unwrap();
        assert_eq!(
            verify_signature(&oid, &tbs, &sig, &spki),
            VerifyOutcome::Failed
        );
    }

    #[test]
    fn wrong_issuer_key_fails() {
        // leaf's signature checked against the ROOT's key (not its real issuer).
        let leaf = load_one(LEAF_PEM);
        let root = load_one(SELF_SIGNED_RSA_PEM);
        let oid = leaf.signature_algorithm_oid().unwrap();
        let tbs = leaf.tbs_der().unwrap();
        let sig = leaf.signature_value_bytes().unwrap();
        let spki = root.issuer_spki_bytes().unwrap();
        assert_eq!(
            verify_signature(&oid, &tbs, &sig, &spki),
            VerifyOutcome::Failed
        );
    }

    #[test]
    fn unknown_algorithm_is_unsupported() {
        let cert = load_one(SELF_SIGNED_RSA_PEM);
        let tbs = cert.tbs_der().unwrap();
        let sig = cert.signature_value_bytes().unwrap();
        let spki = cert.issuer_spki_bytes().unwrap();
        // RSA-PSS OID is deliberately outside the supported matrix → fail-open.
        assert_eq!(
            verify_signature("1.2.840.113549.1.1.10", &tbs, &sig, &spki),
            VerifyOutcome::Unsupported
        );
    }

    #[test]
    fn malformed_spki_is_unsupported() {
        assert_eq!(
            verify_signature(OID_RSA_SHA256, b"tbs", b"sig", b"not-a-spki"),
            VerifyOutcome::Unsupported
        );
    }
}
