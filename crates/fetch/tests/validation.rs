//! Integration-level validation tests for the `fetch` public API.
//!
//! These exercise the *observable* behaviour of [`fetch::Target::parse`] and the
//! pre-connect guards inside [`fetch::fetch_chain`] (SNI rules, SSRF guard, port
//! range) through the crate's public surface, complementing the in-crate unit
//! tests of the private helpers. They are fully offline: every error path here is
//! reached *before* any socket I/O, so no listener is required.
//!
//! Conventions: SIFER, `.unwrap()` / `.unwrap_err()`.

use std::time::Duration;

use fetch::{FetchError, HostKind, Target, fetch_chain};

/// A short timeout: these tests never reach the network, but keep it bounded so a
/// regression that *did* attempt I/O fails fast instead of hanging.
const FAST: Duration = Duration::from_millis(500);

mod target_shape {
    use super::*;

    #[test]
    fn bare_hostname_defaults_to_443() {
        let t = Target::parse("example.test").unwrap();
        assert_eq!(t.port(), 443);
        assert_eq!(t.host(), &HostKind::Hostname("example.test".to_string()));
    }

    #[test]
    fn explicit_standard_port_is_kept() {
        let t = Target::parse("example.test:443").unwrap();
        assert_eq!(t.port(), 443);
    }

    #[test]
    fn explicit_alternate_port_is_kept() {
        let t = Target::parse("example.test:8443").unwrap();
        assert_eq!(t.port(), 8443);
    }

    #[test]
    fn port_zero_is_rejected() {
        let err = Target::parse("example.test:0").unwrap_err();
        assert!(matches!(err, FetchError::InvalidPort));
    }

    #[test]
    fn port_above_u16_max_is_rejected() {
        let err = Target::parse("example.test:65536").unwrap_err();
        assert!(matches!(err, FetchError::InvalidPort));
    }

    #[test]
    fn non_numeric_port_is_rejected() {
        let err = Target::parse("example.test:https").unwrap_err();
        assert!(matches!(err, FetchError::InvalidTarget(_)));
    }

    #[test]
    fn empty_target_is_rejected() {
        let err = Target::parse("   ").unwrap_err();
        assert!(matches!(err, FetchError::InvalidTarget(_)));
    }

    #[test]
    fn ipv4_literal_is_classified_as_ip() {
        let t = Target::parse("203.0.113.5:8443").unwrap();
        assert!(matches!(t.host(), HostKind::Ip(_)));
        assert_eq!(t.port(), 8443);
    }
}

mod sni_rules {
    use super::*;

    #[test]
    fn ip_target_without_sni_is_refused() {
        // The SNI rule is enforced before any connection attempt.
        let target = Target::parse("203.0.113.5:443").unwrap();
        let err = fetch_chain(&target, None, FAST, false).unwrap_err();
        assert!(matches!(err, FetchError::SniRequiredForIp));
    }

    #[test]
    fn invalid_sni_string_is_refused() {
        let target = Target::parse("203.0.113.5:443").unwrap();
        let err = fetch_chain(&target, Some("not a valid dns name!"), FAST, false).unwrap_err();
        assert!(matches!(err, FetchError::InvalidSni));
    }
}

mod ssrf_guard {
    use super::*;

    #[test]
    fn enabled_guard_blocks_loopback_target() {
        // With the guard on, a loopback target is rejected *before* connecting,
        // so no listener is needed and the test stays hermetic.
        let target = Target::parse("127.0.0.1:443").unwrap();
        let err = fetch_chain(&target, Some("localhost"), FAST, true).unwrap_err();
        assert!(matches!(err, FetchError::BlockedAddress));
    }

    #[test]
    fn enabled_guard_blocks_private_target() {
        let target = Target::parse("10.0.0.1:443").unwrap();
        let err = fetch_chain(&target, Some("internal.test"), FAST, true).unwrap_err();
        assert!(matches!(err, FetchError::BlockedAddress));
    }

    #[test]
    fn disabled_guard_allows_loopback_past_the_guard() {
        // With the guard OFF, the loopback target is *not* blocked. Nothing is
        // listening on this port, so the call still fails — but with a
        // connect/timeout error, never BlockedAddress. That distinguishes "guard
        // let it through" from "guard rejected it".
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::parse(&format!("127.0.0.1:{port}")).unwrap();
        let err =
            fetch_chain(&target, Some("localhost"), Duration::from_secs(2), false).unwrap_err();

        assert!(
            !matches!(err, FetchError::BlockedAddress),
            "guard disabled: loopback must not be blocked (got {err:?})"
        );
        assert!(
            matches!(err, FetchError::Connect | FetchError::Timeout),
            "expected a connect/timeout error past the guard, got {err:?}"
        );
    }
}

mod timeout {
    use super::*;

    #[test]
    fn refused_connection_returns_within_budget() {
        // Hermetic + fast: a closed local port refuses immediately. We assert the
        // call returns a connect/timeout error well within a generous wall-clock
        // budget (proving it does not hang), rather than asserting on exact
        // timing which would be flaky.
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::parse(&format!("127.0.0.1:{port}")).unwrap();
        let started = std::time::Instant::now();
        let err =
            fetch_chain(&target, Some("localhost"), Duration::from_secs(3), false).unwrap_err();
        let elapsed = started.elapsed();

        assert!(
            matches!(err, FetchError::Connect | FetchError::Timeout),
            "expected Connect/Timeout, got {err:?}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "the call must return promptly, took {elapsed:?}"
        );
    }
}
