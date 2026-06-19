//! Auditable parameter-set → mandated public-key-length table for the NIST
//! post-quantum **key-encapsulation** family (ML-KEM) recognised by the `pqc`
//! lint source.
//!
//! This is the KEM counterpart to the signature [`params`](super::params) table
//! (kept deliberately separate for auditability). The key length is the
//! load-bearing value for `pqc_mlkem_public_key_length`: it is the exact byte
//! length the IETF LAMPS ML-KEM X.509 algorithm-identifier profile defines as the
//! SPKI public key (the raw *encapsulation key*) for the named parameter set —
//! the BIT STRING value octets, excluding the unused-bits octet — matching
//! [`Cert::public_key_raw_len`](crate::cert::Cert::public_key_raw_len).
//!
//! # Sources (re-verify against the published documents)
//!
//! - **ML-KEM — NIST FIPS 203, §8 (sizes table).** The *encapsulation key*
//!   (public-key) sizes are:
//!   - ML-KEM-512  → **800**  bytes
//!   - ML-KEM-768  → **1184** bytes
//!   - ML-KEM-1024 → **1568** bytes
//!
//!   These follow from FIPS 203: the encapsulation key is `384 * k + 32` bytes,
//!   with `k = 2` (ML-KEM-512), `k = 3` (ML-KEM-768), `k = 4` (ML-KEM-1024),
//!   giving `768 + 32 = 800`, `1152 + 32 = 1184`, and `1536 + 32 = 1568`.
//!
//! The parameter-set short names below MUST match exactly the names
//! [`Cert::public_key_algorithm`](crate::cert::Cert::public_key_algorithm)
//! carries in [`PqcParamSet::Known`](crate::cert::PqcParamSet) (sourced from the
//! NIST `2.16.840.1.101.3.4.4` "kems" OID arc in `cert.rs`).

/// One row of the ML-KEM parameter-set → public-key-length table: the canonical
/// FIPS short name and the mandated raw encapsulation-key byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqcKemParamInfo {
    /// The canonical FIPS short name (e.g. `"ML-KEM-768"`).
    pub name: &'static str,
    /// The mandated raw encapsulation-key (public-key) length in bytes
    /// (NIST FIPS 203 §8).
    pub public_key_len: usize,
}

/// The full table of recognised ML-KEM parameter sets and their
/// encapsulation-key (public-key) lengths (NIST FIPS 203 §8).
pub const PQC_KEM_PARAM_TABLE: &[PqcKemParamInfo] = &[
    PqcKemParamInfo {
        name: "ML-KEM-512",
        public_key_len: 800,
    },
    PqcKemParamInfo {
        name: "ML-KEM-768",
        public_key_len: 1184,
    },
    PqcKemParamInfo {
        name: "ML-KEM-1024",
        public_key_len: 1568,
    },
];

/// Looks up the mandated raw encapsulation-key byte length for a recognised
/// ML-KEM parameter set by its canonical FIPS short name.
///
/// Returns `None` for a name not in [`PQC_KEM_PARAM_TABLE`] — i.e. the
/// "unknown arc member" case, for which there is no known length to validate
/// (`pqc_mlkem_public_key_length` therefore emits no finding;
/// `pqc_mlkem_algorithm_known` owns that case).
pub fn expected_mlkem_public_key_len(param_set: &str) -> Option<usize> {
    PQC_KEM_PARAM_TABLE
        .iter()
        .find(|info| info.name == param_set)
        .map(|info| info.public_key_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod expected_mlkem_public_key_len {
        use super::*;

        #[test]
        fn ml_kem_512_is_800() {
            assert_eq!(expected_mlkem_public_key_len("ML-KEM-512"), Some(800));
        }

        #[test]
        fn ml_kem_768_is_1184() {
            assert_eq!(expected_mlkem_public_key_len("ML-KEM-768"), Some(1184));
        }

        #[test]
        fn ml_kem_1024_is_1568() {
            assert_eq!(expected_mlkem_public_key_len("ML-KEM-1024"), Some(1568));
        }

        #[test]
        fn unknown_param_set_has_no_length() {
            assert_eq!(expected_mlkem_public_key_len("ML-KEM-2048"), None);
            assert_eq!(
                expected_mlkem_public_key_len("2.16.840.1.101.3.4.4.4"),
                None
            );
        }
    }

    #[test]
    fn table_covers_all_three_named_sets() {
        assert_eq!(PQC_KEM_PARAM_TABLE.len(), 3);
    }
}
