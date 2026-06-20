//! Exit-code matrix tests for the `mini-x509-lint` binary.
//!
//! These drive the *actual* compiled binary and assert on the process exit code
//! (`status.code()`) for the `--fail-on` / `--min-severity` / `--chain` matrix.
//! Exit semantics: `0` when no surfaced finding (after `--min-severity`) reaches
//! `--fail-on`; `1` when one does; non-zero for a load / parse / usage error
//! (clap reports usage errors with code `2`).
//!
//! ## Determinism
//!
//! Exit-code assertions are time-independent: `expired.pem` surfaces a `warn`
//! (`hygiene_not_expired`) whose *message* embeds the current time, but its
//! *severity* — and therefore the exit code under a given `--fail-on` — is
//! stable. The volatile message text is never asserted on here.

use std::path::PathBuf;
use std::process::Command;

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

/// A reference "now" (2026-12-01 in Unix seconds) inside every currently-valid
/// fixture window and after `expired.pem`'s past `notAfter` (2024-06-01), so the
/// expired fixture still reads expired. Pinning `--now` makes the exit codes
/// deterministic regardless of the wall clock — without it, the currently-valid
/// fixtures (good.pem, chain_valid.pem) would trip `hygiene_not_expired` once the
/// real date passes their `notAfter`, flipping the `--fail-on warn` exit codes.
const TEST_NOW: &str = "1796083200";

/// Runs the binary with `args` and returns its exit code (`None` => killed by
/// signal, which should never happen for these tests). Pins `--now` so exit codes
/// are wall-clock independent; `--now` is a no-op for the usage/arg-error paths.
fn exit_code(args: &[&str]) -> Option<i32> {
    Command::new(BIN)
        .args(["--now", TEST_NOW])
        .args(args)
        .output()
        .expect("failed to spawn mini-x509-lint binary")
        .status
        .code()
}

/// Returns the absolute fixture path as a `String` for passing as an argument.
fn fixture_arg(name: &str) -> String {
    fixture(name).to_string_lossy().into_owned()
}

mod fail_on {
    use super::*;

    #[test]
    fn good_pem_fail_on_error_exits_zero() {
        // good.pem has no findings at all -> below any threshold.
        let code = exit_code(&[&fixture_arg("good.pem"), "--fail-on", "error"]);
        assert_eq!(code, Some(0));
    }

    #[test]
    fn error_finding_fail_on_error_exits_one() {
        // cabf_br_validity_400_days has one Error finding at default purpose
        // (serverAuth leaf -> tls-server -> BR runs).
        let code = exit_code(&[
            &fixture_arg("cabf_br_validity_400_days.pem"),
            "--fail-on",
            "error",
        ]);
        assert_eq!(code, Some(1));
    }

    #[test]
    fn error_only_fail_on_fatal_exits_zero() {
        // Only Error findings present; --fail-on fatal is above them -> 0.
        let code = exit_code(&[
            &fixture_arg("cabf_br_validity_400_days.pem"),
            "--fail-on",
            "fatal",
        ]);
        assert_eq!(code, Some(0));
    }

    #[test]
    fn expired_warn_default_fail_on_error_exits_zero() {
        // expired.pem surfaces only a `warn`; default --fail-on is error -> 0.
        let code = exit_code(&[&fixture_arg("expired.pem")]);
        assert_eq!(code, Some(0));
    }

    #[test]
    fn expired_warn_fail_on_warn_exits_one() {
        // Lowering the threshold to warn makes the expiry warning trip the exit.
        let code = exit_code(&[&fixture_arg("expired.pem"), "--fail-on", "warn"]);
        assert_eq!(code, Some(1));
    }
}

mod min_severity_interaction {
    use super::*;

    #[test]
    fn finding_filtered_below_min_severity_does_not_trigger_fail_on() {
        // The warn finding is hidden by --min-severity error, so --fail-on warn
        // sees nothing surfaced and exits 0.
        let code = exit_code(&[
            &fixture_arg("expired.pem"),
            "--min-severity",
            "error",
            "--fail-on",
            "warn",
        ]);
        assert_eq!(code, Some(0));
    }

    #[test]
    fn surfaced_finding_still_triggers_fail_on() {
        // Without the filter, the same input + --fail-on warn exits 1 (proves
        // the previous test isolates the --min-severity effect).
        let code = exit_code(&[&fixture_arg("expired.pem"), "--fail-on", "warn"]);
        assert_eq!(code, Some(1));
    }
}

mod chain {
    use super::*;

    // Positive control: `chain_valid.pem` is a genuinely linked
    // leaf -> intermediate -> root chain that bundles its own self-signed root, so
    // both the per-cert pass and the chain pass surface nothing. (The earlier
    // `chain_bundle.pem` control was retired here: it is two UNRELATED self-signed
    // certs that do NOT form a chain, so under the feature-15 chain lints it
    // correctly surfaces a structural-integrity Error — covered by the
    // unrelated-bundle test below.)
    #[test]
    fn clean_chain_all_pass_exits_zero() {
        // Every per-cert and chain lint passes -> no surfaced findings.
        let code = exit_code(&["--chain", &fixture_arg("chain_valid.pem")]);
        assert_eq!(code, Some(0));
    }

    #[test]
    fn chain_exit_reflects_only_surfaced_findings() {
        // The chain links cleanly (leaf-to-root order, bundles its root) so the
        // *chain* checks surface nothing and no construction Notices appear. The
        // only surfaced finding is per-cert: under feature-17's broad BR scoping the
        // subscriber leaf — which carries no CertificatePolicies extension — emits a
        // `cabf_br_certificate_policies_present` Warn. That Warn does NOT reach the
        // default `--fail-on error` (see `clean_chain_all_pass_exits_zero`), but it
        // DOES reach `--fail-on warn`, so the exit flips to 1. This still proves the
        // exit reflects exactly the surfaced findings at the chosen threshold.
        let code = exit_code(&[
            "--chain",
            &fixture_arg("chain_valid.pem"),
            "--fail-on",
            "warn",
        ]);
        assert_eq!(code, Some(1));
    }

    #[test]
    fn unrelated_bundle_surfaces_structural_error_exits_one() {
        // `chain_bundle.pem` is two unrelated self-signed certs that do not link.
        // Under the chain lints this is a broken set: `chain_subject_issuer_dn_match`
        // fires Error, so the default --fail-on error trips a non-zero exit.
        let code = exit_code(&["--chain", &fixture_arg("chain_bundle.pem")]);
        assert_eq!(code, Some(1));
    }
}

mod errors {
    use super::*;

    #[test]
    fn missing_file_exits_nonzero() {
        let code = exit_code(&[&fixture_arg("does_not_exist.pem")]);
        assert_ne!(code, Some(0), "a missing file must exit non-zero");
    }

    #[test]
    fn invalid_flag_value_exits_nonzero() {
        // clap rejects an unknown --fail-on value with a usage error (code 2).
        let code = exit_code(&[&fixture_arg("good.pem"), "--fail-on", "bogus"]);
        assert_ne!(code, Some(0), "a bad flag value must exit non-zero");
    }

    #[test]
    fn unparseable_input_exits_nonzero() {
        // A file that exists but holds no valid certificate must fail the load
        // (the third leg of the doc comment's "load / parse / usage error"
        // contract — load and usage are covered above; this covers parse).
        let mut path = std::env::temp_dir();
        path.push(format!("mini_x509_lint_garbage_{}.bin", std::process::id()));
        std::fs::write(&path, b"this is not a certificate, neither PEM nor DER")
            .expect("must write the temp garbage file");

        let code = exit_code(&[&path.to_string_lossy()]);

        // Clean up before asserting so a failure does not leak the temp file.
        let _ = std::fs::remove_file(&path);
        assert_ne!(code, Some(0), "an unparseable input must exit non-zero");
    }
}
