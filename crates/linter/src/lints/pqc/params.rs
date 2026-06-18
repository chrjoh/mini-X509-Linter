//! Auditable parameter-set → mandated public-key-length table for the two NIST
//! post-quantum signature families recognised by the `pqc` lint source.
//!
//! The key length is the load-bearing value for `pqc_public_key_length`: it is
//! the exact byte length the LAMPS X.509 algorithm-identifier profile defines as
//! the SPKI public key for the named parameter set (the BIT STRING value octets,
//! excluding the unused-bits octet — matching
//! [`Cert::public_key_raw_len`](crate::cert::Cert::public_key_raw_len)).
//!
//! # Sources (re-verify against the published documents)
//!
//! - **ML-DSA — NIST FIPS 204, Table 2 (sizes of keys and signatures).** The
//!   public-key sizes are:
//!   - ML-DSA-44 → **1312** bytes
//!   - ML-DSA-65 → **1952** bytes
//!   - ML-DSA-87 → **2592** bytes
//! - **SLH-DSA — NIST FIPS 205, Table 8 (SLH-DSA parameter sets).** The public
//!   key is `2 * n` bytes, where `n` is the security parameter in bytes
//!   (`n = 16` for the 128-bit sets, `24` for 192-bit, `32` for 256-bit). The
//!   `s` (small) / `f` (fast) variant and the SHA2 / SHAKE hash family do not
//!   change the public-key size, so:
//!   - SLH-DSA-*-128{s,f} → **32** bytes
//!   - SLH-DSA-*-192{s,f} → **48** bytes
//!   - SLH-DSA-*-256{s,f} → **64** bytes
//!
//! The parameter-set short names below MUST match exactly the names
//! [`Cert::public_key_algorithm`](crate::cert::Cert::public_key_algorithm)
//! carries in [`PqcParamSet::Known`](crate::cert::PqcParamSet) (sourced from the
//! NIST `2.16.840.1.101.3.4.3` "sigAlgs" OID arc in `cert.rs`).

/// One row of the parameter-set → public-key-length table: the canonical FIPS
/// short name and the mandated raw public-key byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqcParamInfo {
    /// The canonical FIPS short name (e.g. `"ML-DSA-65"`).
    pub name: &'static str,
    /// The mandated raw public-key length in bytes (FIPS 204 / FIPS 205).
    pub public_key_len: usize,
}

/// The full table of recognised parameter sets and their public-key lengths.
///
/// ML-DSA (FIPS 204, Table 2) followed by SLH-DSA (FIPS 205, Table 8).
pub const PQC_PARAM_TABLE: &[PqcParamInfo] = &[
    // ML-DSA (FIPS 204) — public-key sizes in bytes.
    PqcParamInfo {
        name: "ML-DSA-44",
        public_key_len: 1312,
    },
    PqcParamInfo {
        name: "ML-DSA-65",
        public_key_len: 1952,
    },
    PqcParamInfo {
        name: "ML-DSA-87",
        public_key_len: 2592,
    },
    // SLH-DSA (FIPS 205) — public key is 2*n bytes; SHA2 family.
    PqcParamInfo {
        name: "SLH-DSA-SHA2-128s",
        public_key_len: 32,
    },
    PqcParamInfo {
        name: "SLH-DSA-SHA2-128f",
        public_key_len: 32,
    },
    PqcParamInfo {
        name: "SLH-DSA-SHA2-192s",
        public_key_len: 48,
    },
    PqcParamInfo {
        name: "SLH-DSA-SHA2-192f",
        public_key_len: 48,
    },
    PqcParamInfo {
        name: "SLH-DSA-SHA2-256s",
        public_key_len: 64,
    },
    PqcParamInfo {
        name: "SLH-DSA-SHA2-256f",
        public_key_len: 64,
    },
    // SLH-DSA (FIPS 205) — SHAKE family (same sizes as the SHA2 counterparts).
    PqcParamInfo {
        name: "SLH-DSA-SHAKE-128s",
        public_key_len: 32,
    },
    PqcParamInfo {
        name: "SLH-DSA-SHAKE-128f",
        public_key_len: 32,
    },
    PqcParamInfo {
        name: "SLH-DSA-SHAKE-192s",
        public_key_len: 48,
    },
    PqcParamInfo {
        name: "SLH-DSA-SHAKE-192f",
        public_key_len: 48,
    },
    PqcParamInfo {
        name: "SLH-DSA-SHAKE-256s",
        public_key_len: 64,
    },
    PqcParamInfo {
        name: "SLH-DSA-SHAKE-256f",
        public_key_len: 64,
    },
];

/// Looks up the mandated raw public-key byte length for a recognised parameter
/// set by its canonical FIPS short name.
///
/// Returns `None` for a name not in [`PQC_PARAM_TABLE`] — i.e. the
/// "unknown arc member" case, for which there is no known length to validate
/// (`pqc_public_key_length` therefore emits no finding; `pqc_algorithm_known`
/// owns that case).
pub fn expected_public_key_len(param_set: &str) -> Option<usize> {
    PQC_PARAM_TABLE
        .iter()
        .find(|info| info.name == param_set)
        .map(|info| info.public_key_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod expected_public_key_len {
        use super::*;

        #[test]
        fn ml_dsa_44_is_1312() {
            assert_eq!(expected_public_key_len("ML-DSA-44"), Some(1312));
        }

        #[test]
        fn ml_dsa_65_is_1952() {
            assert_eq!(expected_public_key_len("ML-DSA-65"), Some(1952));
        }

        #[test]
        fn ml_dsa_87_is_2592() {
            assert_eq!(expected_public_key_len("ML-DSA-87"), Some(2592));
        }

        #[test]
        fn slh_dsa_128_sets_are_32() {
            assert_eq!(expected_public_key_len("SLH-DSA-SHA2-128s"), Some(32));
            assert_eq!(expected_public_key_len("SLH-DSA-SHA2-128f"), Some(32));
            assert_eq!(expected_public_key_len("SLH-DSA-SHAKE-128s"), Some(32));
            assert_eq!(expected_public_key_len("SLH-DSA-SHAKE-128f"), Some(32));
        }

        #[test]
        fn slh_dsa_192_sets_are_48() {
            assert_eq!(expected_public_key_len("SLH-DSA-SHA2-192s"), Some(48));
            assert_eq!(expected_public_key_len("SLH-DSA-SHA2-192f"), Some(48));
            assert_eq!(expected_public_key_len("SLH-DSA-SHAKE-192s"), Some(48));
            assert_eq!(expected_public_key_len("SLH-DSA-SHAKE-192f"), Some(48));
        }

        #[test]
        fn slh_dsa_256_sets_are_64() {
            assert_eq!(expected_public_key_len("SLH-DSA-SHA2-256s"), Some(64));
            assert_eq!(expected_public_key_len("SLH-DSA-SHA2-256f"), Some(64));
            assert_eq!(expected_public_key_len("SLH-DSA-SHAKE-256s"), Some(64));
            assert_eq!(expected_public_key_len("SLH-DSA-SHAKE-256f"), Some(64));
        }

        #[test]
        fn unknown_param_set_has_no_length() {
            assert_eq!(expected_public_key_len("ML-DSA-128"), None);
            assert_eq!(expected_public_key_len("2.16.840.1.101.3.4.3.32"), None);
        }
    }

    #[test]
    fn table_covers_all_15_named_sets() {
        // 3 ML-DSA + 12 SLH-DSA parameter sets.
        assert_eq!(PQC_PARAM_TABLE.len(), 15);
    }
}
