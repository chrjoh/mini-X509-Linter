//! Golden-file (snapshot) tests for the `mini-x509-lint` binary.
//!
//! These drive the *actual* compiled binary (located via the Cargo-provided
//! `CARGO_BIN_EXE_mini-x509-lint` env var) over the committed `testdata/`
//! fixtures and snapshot stdout with `insta`. They lock the text layout
//! (grouping, summary, verbose per-lint listing, purpose header) and the nested
//! JSON shape so a regression in the formatter is caught as a snapshot diff.
//!
//! ## Determinism
//!
//! Snapshots may only cover *deterministic* output. The `hygiene_not_expired`
//! finding embeds the current Unix time (`now is <unix>`), which changes every
//! run, so fixtures that surface that line (e.g. `expired.pem`) are **never**
//! snapshotted. The chosen fixtures are stable across runs:
//! - `good.pem` — auto resolves to tls-server (serverAuth EKU), so its 32 in-profile lints
//!   (rfc5280 + cabf_br + hygiene) all pass / N/A; the 8 cabf_cs lints are code-signing-only and
//!   out of profile here, so they are not run.
//! - `cabf_br_validity_400_days.pem` — the only finding is the BR validity error
//!   whose message embeds a fixed day-count (`400 days`), not a timestamp.
//! - `chain_bundle.pem` — a freshly-generated all-pass leaf + CA, no findings.
//!
//! ## Fixtures generated with openssl 3.6.2 (recipe summary)
//!
//! `chain_bundle.pem` — two concatenated self-signed certs (leaf first, CA
//! second):
//! - leaf: RSA-2048/SHA-256, v3, CA:FALSE, `extendedKeyUsage=serverAuth`,
//!   `subjectAltName=DNS:chain-leaf.example.com`, serial 101, window
//!   2026-06-01 -> 2027-06-01 (365 days). Passes all its in-profile lints (a serverAuth leaf, so
//!   cabf_cs is out of profile and not run).
//! - CA: RSA-2048/SHA-256, v3, `basicConstraints=critical,CA:TRUE`,
//!   `keyUsage=critical,keyCertSign,cRLSign`, serial 100, window
//!   2026-01-01 -> 2036-01-01. CA => cabf_br lints N/A.

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

/// Runs the binary with `args` and returns the captured [`Output`].
fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn mini-x509-lint binary")
}

/// Runs the binary and returns its stdout decoded as UTF-8.
fn stdout(args: &[&str]) -> String {
    let output = run(args);
    String::from_utf8(output.stdout).expect("stdout must be UTF-8")
}

/// Returns the absolute fixture path as a `String` for passing as an argument.
fn fixture_arg(name: &str) -> String {
    fixture(name).to_string_lossy().into_owned()
}

mod text_output {
    use super::*;

    #[test]
    fn good_pem_default_text() {
        // Setup / Invoke
        let out = stdout(&[&fixture_arg("good.pem")]);

        // Find / Expect — all-pass, collapsed per-group summary + "no findings".
        insta::assert_snapshot!("good_text", out);
    }

    #[test]
    fn cabf_br_validity_400_days_text() {
        // The only finding is the stable BR validity error (fixed "400 days"
        // count, no timestamp).
        let out = stdout(&[&fixture_arg("cabf_br_validity_400_days.pem")]);
        insta::assert_snapshot!("cabf_br_validity_400_days_text", out);
    }

    #[test]
    fn chain_bundle_text() {
        // --chain renders one labelled block per cert; both are all-pass.
        let out = stdout(&["--chain", &fixture_arg("chain_bundle.pem")]);
        insta::assert_snapshot!("chain_bundle_text", out);
    }
}

mod verbose_output {
    use super::*;

    #[test]
    fn good_pem_verbose_text() {
        // Verbose mode: a `purpose:` header, then every lint listed
        // individually (pass/n/a + lint_id) under its source group; the
        // collapsed `(N passed, M not applicable)` summary is replaced.
        let out = stdout(&[&fixture_arg("good.pem"), "--verbose"]);
        insta::assert_snapshot!("good_verbose_text", out);
    }

    #[test]
    fn verbose_is_deterministic_across_runs() {
        // Two independent runs must produce byte-identical output.
        let first = stdout(&[&fixture_arg("good.pem"), "--verbose"]);
        let second = stdout(&[&fixture_arg("good.pem"), "--verbose"]);
        assert_eq!(first, second, "verbose output must be deterministic");
    }

    #[test]
    fn default_mode_keeps_collapsed_summary() {
        // Guard the unchanged default: collapsed summary present, no purpose
        // header, no per-lint lines.
        let out = stdout(&[&fixture_arg("good.pem")]);
        assert!(
            out.contains("(7 passed, 9 not applicable)"),
            "default text must keep the collapsed per-group summary"
        );
        assert!(
            !out.contains("purpose:"),
            "default text must omit the verbose purpose header"
        );
        assert!(
            !out.contains("rfc5280_serial_number_positive"),
            "default text must not list individual lint ids"
        );
    }
}

mod json_output {
    use super::*;

    #[test]
    fn good_pem_json_shape() {
        // Re-parse and re-serialize to lock the nested shape independent of the
        // binary's exact whitespace, then snapshot.
        let raw = stdout(&[&fixture_arg("good.pem"), "--format", "json"]);
        let value: serde_json::Value = serde_json::from_str(&raw).expect("JSON output must parse");
        insta::assert_json_snapshot!("good_json", value);
    }

    #[test]
    fn json_unaffected_by_verbose() {
        // `--verbose` is text-only; JSON output must be identical with/without.
        let plain = stdout(&[&fixture_arg("good.pem"), "--format", "json"]);
        let verbose = stdout(&[&fixture_arg("good.pem"), "--format", "json", "--verbose"]);
        assert_eq!(plain, verbose, "--verbose must not change JSON output");
    }
}
