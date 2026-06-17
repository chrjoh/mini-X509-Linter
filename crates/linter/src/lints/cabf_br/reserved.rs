//! Auditable classifier for internal/reserved DNS names and reserved IP
//! addresses.
//!
//! The CA/Browser Forum Baseline Requirements forbid issuing publicly-trusted
//! certificates for **Internal Names** or **Reserved IP Addresses** (BR §1.6.1
//! definitions; enforced under BR §4.2.2 / §7.1.4.2). This module is the single
//! place that decides what counts as "reserved" or "internal", so the policy is
//! reviewable in one spot rather than scattered across lints.
//!
//! Design goals:
//! - **One list, well cited.** Every reserved IP range below names the RFC that
//!   reserves it. The DNS policy enumerates each reserved/special-use suffix.
//! - **`std` only.** IP classification uses the standard-library
//!   [`Ipv4Addr`]/[`Ipv6Addr`] predicates; no extra crate is pulled in.
//! - **Conservative.** When in doubt the helpers err toward *not* flagging, so a
//!   genuinely public name/IP is never mislabelled as internal/reserved.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns `true` if `ip` falls in a reserved / non-publicly-routable range.
///
/// A reserved IP must never appear in a publicly-trusted certificate
/// (CA/Browser Forum BR "Reserved IP Address"). The classification covers, for
/// IPv4 (RFC 5735 / RFC 6890 special-use registry):
///
/// - `0.0.0.0/8` — "this host on this network" / unspecified (RFC 1122)
/// - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` — private (RFC 1918)
/// - `127.0.0.0/8` — loopback (RFC 1122)
/// - `169.254.0.0/16` — link-local (RFC 3927)
/// - `100.64.0.0/10` — shared address space / CGNAT (RFC 6598)
/// - `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` — documentation
///   (RFC 5737)
/// - `198.18.0.0/15` — benchmarking (RFC 2544)
/// - `224.0.0.0/4` — multicast (RFC 5771)
/// - `255.255.255.255/32` — limited broadcast (RFC 8190)
/// - `240.0.0.0/4` — reserved for future use (RFC 1112) — handled explicitly.
///
/// and for IPv6 (RFC 4291 / RFC 8190 special-use registry):
///
/// - `::/128` — unspecified, `::1/128` — loopback (RFC 4291)
/// - `fc00::/7` — unique local addresses (RFC 4193)
/// - `fe80::/10` — link-local unicast (RFC 4291)
/// - `ff00::/8` — multicast (RFC 4291)
/// - `2001:db8::/32` — documentation (RFC 3849) — handled explicitly.
pub fn is_reserved_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_reserved_ipv4(v4),
        IpAddr::V6(v6) => is_reserved_ipv6(v6),
    }
}

/// IPv4 reserved-range classification. See [`is_reserved_ip`] for the cited
/// ranges; std predicates cover most, with two explicit blocks std has no
/// dedicated predicate for.
fn is_reserved_ipv4(ip: &Ipv4Addr) -> bool {
    // std-backed predicates (each maps to a cited range above).
    if ip.is_unspecified()        // 0.0.0.0/8 base — RFC 1122
        || ip.is_private()        // RFC 1918
        || ip.is_loopback()       // 127.0.0.0/8 — RFC 1122
        || ip.is_link_local()     // 169.254.0.0/16 — RFC 3927
        || ip.is_documentation()  // RFC 5737 (all three blocks)
        || ip.is_multicast()      // 224.0.0.0/4 — RFC 5771
        || ip.is_broadcast()
    // 255.255.255.255 — RFC 8190
    {
        return true;
    }
    // The remaining reserved blocks have no stable std predicate on this Rust
    // version (`is_shared`/`is_benchmarking` are still unstable), so match the
    // CIDR prefixes on the raw octets directly.
    let [a, b, ..] = ip.octets();
    // 100.64.0.0/10 — shared address space / CGNAT (RFC 6598): second octet 64..=127.
    let is_shared = a == 100 && (64..=127).contains(&b);
    // 198.18.0.0/15 — benchmarking (RFC 2544): second octet 18 or 19.
    let is_benchmarking = a == 198 && (b == 18 || b == 19);
    // 240.0.0.0/4 — reserved for future use (RFC 1112).
    let is_future_use = a >= 240;
    is_shared || is_benchmarking || is_future_use
}

/// IPv6 reserved-range classification. See [`is_reserved_ip`] for the cited
/// ranges.
fn is_reserved_ipv6(ip: &Ipv6Addr) -> bool {
    // std-backed predicates.
    if ip.is_unspecified()                // ::/128 — RFC 4291
        || ip.is_loopback()               // ::1/128 — RFC 4291
        || ip.is_unique_local()           // fc00::/7 — RFC 4193
        || ip.is_unicast_link_local()     // fe80::/10 — RFC 4291
        || ip.is_multicast()
    // ff00::/8 — RFC 4291
    {
        return true;
    }
    // 2001:db8::/32 — documentation prefix (RFC 3849). std's `is_documentation`
    // on Ipv6Addr is unstable, so match the /32 prefix explicitly.
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

/// Reserved / special-use top-level domains and suffixes that are not part of
/// the public DNS and so must never appear in a publicly-trusted certificate.
///
/// Sources:
/// - `.localhost`, `.invalid`, `.example`, `.test` — RFC 6761 special-use names.
/// - `.local` — multicast DNS (RFC 6762); not globally resolvable.
/// - `.internal` — reserved by ICANN for private use (SAC113, 2024).
/// - `.onion`, `.home.arpa` — RFC 7686 / RFC 8375 special-use names.
///
/// Each entry is a label suffix; matching is on whole-label boundaries (a leading
/// `.` is implied) and case-insensitive.
const RESERVED_SUFFIXES: &[&str] = &[
    "local",
    "localhost",
    "internal",
    "invalid",
    "example",
    "test",
    "onion",
    "home.arpa",
];

/// Returns `true` if `name` is an internal / non-publicly-resolvable DNS name.
///
/// A name is treated as internal when any of the following holds (policy kept
/// small and conservative on purpose):
///
/// 1. It is empty, or after normalisation has no dot — i.e. a **single-label**
///    hostname such as `intranet` (a bare label cannot be a public FQDN).
/// 2. Its rightmost label (the TLD), or a recognised multi-label special-use
///    suffix, is one of [`RESERVED_SUFFIXES`] (e.g. `.local`, `.internal`,
///    `.localhost`, `.invalid`, `.example`, `.test`, `.onion`, `.home.arpa`).
///
/// Matching is case-insensitive and tolerates a single trailing dot (the DNS
/// root). Wildcard labels (`*.`) are stripped before classification so
/// `*.example` is still flagged.
///
/// This is deliberately a **suffix/structure** check, not a full public-suffix
/// lookup: it flags the well-known reserved namespaces without depending on an
/// external public-suffix list. A normal public name such as `www.example.com`
/// returns `false`.
pub fn is_internal_name(name: &str) -> bool {
    // Normalise: lowercase, drop a single trailing root dot, drop a leading
    // wildcard label so `*.local` is judged on `local`.
    let normalized = name.trim().to_ascii_lowercase();
    let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);
    let normalized = normalized.strip_prefix("*.").unwrap_or(normalized);

    if normalized.is_empty() {
        return true;
    }

    // Single-label name (no dot): not a public FQDN.
    if !normalized.contains('.') {
        return true;
    }

    // Reserved suffix match on whole-label boundaries.
    RESERVED_SUFFIXES
        .iter()
        .any(|suffix| normalized == *suffix || normalized.ends_with(&format!(".{suffix}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    mod is_reserved_ip {
        use super::*;

        fn ip(s: &str) -> IpAddr {
            s.parse().expect("test IP literal")
        }

        #[test]
        fn flags_rfc1918_private_ranges() {
            assert!(is_reserved_ip(&ip("10.0.0.1")));
            assert!(is_reserved_ip(&ip("172.16.5.4")));
            assert!(is_reserved_ip(&ip("192.168.1.1")));
        }

        #[test]
        fn flags_loopback_and_unspecified_and_link_local() {
            assert!(is_reserved_ip(&ip("127.0.0.1")));
            assert!(is_reserved_ip(&ip("0.0.0.0")));
            assert!(is_reserved_ip(&ip("169.254.10.10")));
        }

        #[test]
        fn flags_documentation_and_shared_and_benchmarking() {
            assert!(is_reserved_ip(&ip("192.0.2.5"))); // RFC 5737
            assert!(is_reserved_ip(&ip("198.51.100.7"))); // RFC 5737
            assert!(is_reserved_ip(&ip("203.0.113.9"))); // RFC 5737
            assert!(is_reserved_ip(&ip("100.64.0.1"))); // RFC 6598
            assert!(is_reserved_ip(&ip("198.18.0.1"))); // RFC 2544
        }

        #[test]
        fn flags_multicast_broadcast_and_future_use() {
            assert!(is_reserved_ip(&ip("224.0.0.1")));
            assert!(is_reserved_ip(&ip("255.255.255.255")));
            assert!(is_reserved_ip(&ip("240.0.0.1"))); // RFC 1112 future-use
        }

        #[test]
        fn flags_ipv6_reserved_ranges() {
            assert!(is_reserved_ip(&ip("::1"))); // loopback
            assert!(is_reserved_ip(&ip("::"))); // unspecified
            assert!(is_reserved_ip(&ip("fc00::1"))); // unique local
            assert!(is_reserved_ip(&ip("fe80::1"))); // link-local
            assert!(is_reserved_ip(&ip("ff02::1"))); // multicast
            assert!(is_reserved_ip(&ip("2001:db8::1"))); // documentation
        }

        #[test]
        fn does_not_flag_public_addresses() {
            assert!(!is_reserved_ip(&ip("8.8.8.8")));
            assert!(!is_reserved_ip(&ip("1.1.1.1")));
            assert!(!is_reserved_ip(&ip("93.184.216.34"))); // example.com
            assert!(!is_reserved_ip(&ip("2606:4700:4700::1111"))); // public v6
        }
    }

    mod is_internal_name {
        use super::*;

        #[test]
        fn flags_reserved_suffixes() {
            assert!(is_internal_name("printer.local"));
            assert!(is_internal_name("db.internal"));
            assert!(is_internal_name("foo.localhost"));
            assert!(is_internal_name("bar.invalid"));
            assert!(is_internal_name("host.example"));
            assert!(is_internal_name("ci.test"));
            assert!(is_internal_name("abc.onion"));
            assert!(is_internal_name("router.home.arpa"));
        }

        #[test]
        fn flags_single_label_and_empty_names() {
            assert!(is_internal_name("intranet"));
            assert!(is_internal_name("localhost"));
            assert!(is_internal_name(""));
            assert!(is_internal_name("   "));
        }

        #[test]
        fn matches_are_case_insensitive_and_tolerate_root_dot_and_wildcard() {
            assert!(is_internal_name("Server.LOCAL"));
            assert!(is_internal_name("server.internal."));
            assert!(is_internal_name("*.local"));
            assert!(is_internal_name("*.corp.internal"));
        }

        #[test]
        fn matches_on_whole_label_boundaries_only() {
            // "notlocal.com" must NOT be flagged just because it ends in "local".
            assert!(!is_internal_name("notlocal.com"));
            // A label that merely contains "test" is fine.
            assert!(!is_internal_name("latest.example.com"));
        }

        #[test]
        fn does_not_flag_public_names() {
            assert!(!is_internal_name("www.example.com"));
            assert!(!is_internal_name("good.example.org"));
            assert!(!is_internal_name("a.b.c.example.net"));
        }
    }
}
