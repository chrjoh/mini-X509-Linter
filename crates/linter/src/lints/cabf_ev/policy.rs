//! Auditable allowlist of recognized Extended Validation (EV) certificate
//! policy OIDs.
//!
//! A certificate is treated as "EV" when its `certificatePolicies` extension
//! asserts one of these OIDs (on top of being a `serverAuth` TLS leaf). There is
//! **no single universal EV OID**: the CA/Browser Forum reserved `2.23.140.1.1`
//! as the EV policy identifier, but many CAs still assert their own legacy
//! CA-specific OID instead (sometimes in addition). Real EV detection therefore
//! tracks the *issuing CA's* policy OID.
//!
//! # This list is necessarily incomplete
//!
//! Exactly like the reserved-IP/internal-name classifier in
//! [`cabf_br::reserved`](crate::lints::cabf_br), this allowlist is a curated,
//! illustrative subset that **needs occasional maintenance**: CAs add EV OIDs
//! over time, and a definitive list would have to mirror the trust stores
//! (browser/zlint) that map OIDs to "this is EV". The list below is kept small,
//! auditable, and well-cited rather than exhaustive. A cert that asserts an EV
//! OID not listed here will be (correctly, conservatively) treated as *not* in
//! EV scope, so the EV lints stay silent rather than flagging a non-EV cert.

/// Recognized EV certificate policy OIDs, in dotted-decimal string form.
///
/// Each entry names the CA/source it represents:
///
/// - `2.23.140.1.1` — CA/Browser Forum **reserved EV policy identifier**
///   (`joint-iso-itu-t(2) international-organizations(23) ca-browser-forum(140)
///   certificate-policies(1) extended-validation(1)`). The single
///   vendor-neutral EV marker; modern EV certs assert this.
/// - `2.16.840.1.114412.2.1` — DigiCert EV (illustrative legacy CA-specific OID).
/// - `1.3.6.1.4.1.6449.1.2.1.5.1` — Sectigo/Comodo EV (illustrative legacy
///   CA-specific OID).
/// - `2.16.840.1.114028.10.1.2` — Entrust EV (illustrative legacy CA-specific
///   OID).
/// - `1.3.6.1.4.1.99999.1.1` — **dedicated TEST OID** under a private-enterprise
///   arc (`iso(1) identified-organization(3) dod(6) internet(1) private(4)
///   enterprise(1) 99999 ...`). Reserved for this project's openssl-generated EV
///   fixtures so they fall in EV scope without implying any real CA
///   relationship. **Test-only; never a real EV OID.**
pub const EV_POLICY_OIDS: &[&str] = &[
    // CA/Browser Forum reserved EV policy identifier.
    "2.23.140.1.1",
    // Illustrative well-known CA EV OIDs (NOT exhaustive).
    "2.16.840.1.114412.2.1",      // DigiCert EV
    "1.3.6.1.4.1.6449.1.2.1.5.1", // Sectigo/Comodo EV
    "2.16.840.1.114028.10.1.2",   // Entrust EV
    // Dedicated test OID for fixtures (private arc; test-only).
    "1.3.6.1.4.1.99999.1.1",
];

/// Returns `true` if `oid` (dotted-decimal form) is a recognized EV policy OID.
///
/// Comparison is exact string equality against [`EV_POLICY_OIDS`].
pub fn is_ev_policy(oid: &str) -> bool {
    EV_POLICY_OIDS.contains(&oid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn includes_cabf_reserved_ev_oid() {
        assert!(is_ev_policy("2.23.140.1.1"));
    }

    #[test]
    fn includes_dedicated_test_oid() {
        assert!(is_ev_policy("1.3.6.1.4.1.99999.1.1"));
    }

    #[test]
    fn excludes_arbitrary_dv_policy_oid() {
        // CA/Browser Forum DV identifier (2.23.140.1.2.1) is not EV.
        assert!(!is_ev_policy("2.23.140.1.2.1"));
    }

    #[test]
    fn excludes_empty_and_unknown_oids() {
        assert!(!is_ev_policy(""));
        assert!(!is_ev_policy("1.2.3.4"));
    }
}
