//! `--purpose` behaviour tests for the `mini-x509-lint` binary.
//!
//! These drive the *actual* compiled binary and verify the purpose -> source
//! scoping: `tls-server` forces the `cabf_br` set, `generic` skips it, and
//! `auto` resolves per cert from the leaf's serverAuth EKU. The central
//! regression guard is the false-positive fix: a non-TLS leaf
//! (`leaf_no_server_auth.pem`, clientAuth-only) must NOT trip any `cabf_br`
//! lint under the default `auto` purpose.
//!
//! ## Fixtures generated with openssl 3.6.2 (recipe summary)
//!
//! `leaf_no_server_auth.pem` — a self-signed non-CA leaf, RSA-2048/SHA-256, v3,
//! serial 51, CA:FALSE, `extendedKeyUsage=clientAuth` (NO serverAuth),
//! `subjectAltName=DNS:no-server-auth.example.com`, non-empty subject
//! `CN=no-server-auth.example.com`, window 2026-06-01 -> 2027-07-06 (400 days).
//! It is clean for rfc5280 + hygiene. The 400-day window is deliberate: under
//! `--purpose tls-server` it trips `cabf_br_validity_max_398_days`, while under
//! default `auto` (no serverAuth -> generic) the whole `cabf_br` set is skipped
//! so that finding never surfaces.
//!
//! ## Determinism
//!
//! Assertions use stable substrings (lint ids, the `purpose:` header) and exit
//! codes — never the volatile `hygiene_not_expired` timestamp.

use std::path::PathBuf;
use std::process::{Command, Output};

/// Absolute path to the compiled `mini-x509-lint` binary under test.
const BIN: &str = env!("CARGO_BIN_EXE_mini-x509-lint");

/// Resolves a fixture path under the workspace-root `testdata/` directory.
fn fixture(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("..");
    path.push("testdata");
    path.push(name);
    path
}

/// Returns the absolute fixture path as a `String` for passing as an argument.
fn fixture_arg(name: &str) -> String {
    fixture(name).to_string_lossy().into_owned()
}

/// Runs the binary with `args` and returns the captured [`Output`].
fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn mini-x509-lint binary")
}

/// Runs the binary and returns its stdout decoded as UTF-8.
fn stdout(args: &[&str]) -> String {
    String::from_utf8(run(args).stdout).expect("stdout must be UTF-8")
}

/// Runs the binary and returns its exit code.
fn exit_code(args: &[&str]) -> Option<i32> {
    run(args).status.code()
}

mod tls_server_runs_br {
    use super::*;

    #[test]
    fn server_auth_leaf_runs_cabf_br() {
        // --purpose tls-server on a serverAuth leaf -> the [cabf_br] group is
        // present in verbose text and its lints execute.
        let out = stdout(&[
            &fixture_arg("good.pem"),
            "--purpose",
            "tls-server",
            "--verbose",
        ]);
        assert!(out.contains("[cabf_br]"), "tls-server must run cabf_br");
        assert!(
            out.contains("cabf_br_ext_key_usage_server_auth_present"),
            "the BR serverAuth lint must be listed under tls-server"
        );
    }

    #[test]
    fn forced_override_runs_br_on_non_server_auth_leaf() {
        // --purpose tls-server forces BR even when serverAuth is absent: the
        // serverAuth-present lint fires (proving `auto` is only a heuristic).
        let out = stdout(&[
            &fixture_arg("leaf_no_server_auth.pem"),
            "--purpose",
            "tls-server",
        ]);
        assert!(
            out.contains("cabf_br_ext_key_usage_server_auth_present"),
            "forced tls-server must fire the BR serverAuth lint"
        );
        // The 400-day window also trips the validity lint under forced BR.
        assert!(
            out.contains("cabf_br_validity_max_398_days"),
            "forced tls-server must run the BR validity lint"
        );
        let code = exit_code(&[
            &fixture_arg("leaf_no_server_auth.pem"),
            "--purpose",
            "tls-server",
            "--fail-on",
            "error",
        ]);
        assert_eq!(code, Some(1), "forced BR errors must trip --fail-on error");
    }
}

mod generic_skips_br {
    use super::*;

    #[test]
    fn generic_omits_cabf_br_group() {
        // --purpose generic on a serverAuth leaf -> cabf_br is NOT run and NOT
        // emitted (not even as NotApplicable); rfc5280 + hygiene still run.
        let out = stdout(&[
            &fixture_arg("good.pem"),
            "--purpose",
            "generic",
            "--verbose",
        ]);
        assert!(
            !out.contains("[cabf_br]"),
            "generic must drop the cabf_br group entirely"
        );
        assert!(
            !out.contains("cabf_br_"),
            "generic must not emit any cabf_br lint outcome"
        );
        assert!(out.contains("[rfc5280]"), "rfc5280 must still run");
        assert!(out.contains("[hygiene]"), "hygiene must still run");
    }

    #[test]
    fn generic_skips_br_in_json() {
        // JSON must also omit cabf_br outcomes under generic.
        let raw = stdout(&[
            &fixture_arg("good.pem"),
            "--purpose",
            "generic",
            "--format",
            "json",
        ]);
        let value: serde_json::Value = serde_json::from_str(&raw).expect("JSON must parse");
        let arr = value.as_array().expect("top-level JSON must be an array");
        for entry in arr {
            let source = entry["source"].as_str().unwrap_or("");
            assert_ne!(
                source, "cabf_br",
                "generic must produce no cabf_br outcomes"
            );
        }
    }
}

mod auto_resolution {
    use super::*;

    #[test]
    fn auto_runs_br_on_server_auth_leaf() {
        // good.pem asserts serverAuth -> auto resolves tls-server -> BR runs.
        let out = stdout(&[&fixture_arg("good.pem"), "--verbose"]);
        assert!(
            out.contains("[cabf_br]"),
            "auto must run BR on a serverAuth leaf"
        );
    }

    #[test]
    fn auto_skips_br_on_non_server_auth_leaf() {
        // The core false-positive guard: leaf_no_server_auth has clientAuth
        // only, so auto -> generic and the serverAuth-present lint must NOT fire.
        let out = stdout(&[&fixture_arg("leaf_no_server_auth.pem")]);
        assert!(
            !out.contains("cabf_br_ext_key_usage_server_auth_present"),
            "auto on a non-serverAuth leaf must not trip the BR serverAuth lint"
        );
        assert!(
            !out.contains("cabf_br_"),
            "auto -> generic must produce no cabf_br findings on a non-TLS leaf"
        );
    }

    #[test]
    fn auto_skips_br_exit_code_is_zero() {
        // End-to-end proof: the only would-be error (BR serverAuth + validity)
        // is skipped, so --fail-on error exits 0.
        let code = exit_code(&[
            &fixture_arg("leaf_no_server_auth.pem"),
            "--purpose",
            "generic",
            "--fail-on",
            "error",
        ]);
        assert_eq!(code, Some(0));

        // And the same under the default auto resolution.
        let auto_code = exit_code(&[
            &fixture_arg("leaf_no_server_auth.pem"),
            "--fail-on",
            "error",
        ]);
        assert_eq!(auto_code, Some(0));
    }
}

mod default_equals_auto {
    use super::*;

    #[test]
    fn default_matches_explicit_auto_on_server_auth_leaf() {
        let default = stdout(&[&fixture_arg("good.pem"), "--verbose"]);
        let explicit = stdout(&[&fixture_arg("good.pem"), "--purpose", "auto", "--verbose"]);
        assert_eq!(
            default, explicit,
            "default output must equal --purpose auto"
        );

        let default_code = exit_code(&[&fixture_arg("good.pem")]);
        let explicit_code = exit_code(&[&fixture_arg("good.pem"), "--purpose", "auto"]);
        assert_eq!(
            default_code, explicit_code,
            "default exit must equal --purpose auto"
        );
    }

    #[test]
    fn default_matches_explicit_auto_on_non_server_auth_leaf() {
        let default = stdout(&[&fixture_arg("leaf_no_server_auth.pem"), "--verbose"]);
        let explicit = stdout(&[
            &fixture_arg("leaf_no_server_auth.pem"),
            "--purpose",
            "auto",
            "--verbose",
        ]);
        assert_eq!(
            default, explicit,
            "default output must equal --purpose auto"
        );
    }
}

mod source_intersection {
    use super::*;

    #[test]
    fn source_cabf_br_with_generic_runs_nothing_from_br() {
        // Empty intersection: --source cabf_br but --purpose generic drops BR.
        // Not an error; simply no cabf_br findings.
        let out = stdout(&[
            &fixture_arg("cabf_br_validity_400_days.pem"),
            "--source",
            "cabf_br",
            "--purpose",
            "generic",
        ]);
        assert!(
            !out.contains("cabf_br_"),
            "empty intersection must yield no cabf_br outcomes"
        );
        let code = exit_code(&[
            &fixture_arg("cabf_br_validity_400_days.pem"),
            "--source",
            "cabf_br",
            "--purpose",
            "generic",
            "--fail-on",
            "error",
        ]);
        assert_eq!(
            code,
            Some(0),
            "empty intersection surfaces no error finding"
        );
    }

    #[test]
    fn tls_server_with_source_rfc5280_runs_only_rfc5280() {
        let out = stdout(&[
            &fixture_arg("good.pem"),
            "--purpose",
            "tls-server",
            "--source",
            "rfc5280",
            "--verbose",
        ]);
        assert!(out.contains("[rfc5280]"), "rfc5280 must run");
        assert!(
            !out.contains("[cabf_br]"),
            "cabf_br must be excluded by --source"
        );
        assert!(
            !out.contains("[hygiene]"),
            "hygiene must be excluded by --source"
        );
    }
}

mod verbose_purpose_header {
    use super::*;

    #[test]
    fn verbose_emits_resolved_auto_header() {
        // good.pem -> auto resolves tls-server; header notes it came from auto.
        let out = stdout(&[&fixture_arg("good.pem"), "--verbose"]);
        assert!(
            out.contains("purpose: tls-server (auto)"),
            "verbose header must show the auto-resolved purpose, got:\n{out}"
        );
    }

    #[test]
    fn verbose_emits_resolved_header_for_non_server_auth_leaf() {
        let out = stdout(&[&fixture_arg("leaf_no_server_auth.pem"), "--verbose"]);
        assert!(
            out.contains("purpose: generic (auto)"),
            "verbose header must resolve generic for a non-serverAuth leaf, got:\n{out}"
        );
    }

    #[test]
    fn verbose_explicit_purpose_header_omits_auto_marker() {
        let out = stdout(&[
            &fixture_arg("good.pem"),
            "--purpose",
            "generic",
            "--verbose",
        ]);
        assert!(
            out.contains("purpose: generic"),
            "explicit purpose header present"
        );
        assert!(
            !out.contains("(auto)"),
            "an explicit --purpose must not be marked (auto)"
        );
    }

    #[test]
    fn non_verbose_omits_purpose_header() {
        let out = stdout(&[&fixture_arg("good.pem")]);
        assert!(
            !out.contains("purpose:"),
            "default output must omit the purpose header"
        );
    }
}
