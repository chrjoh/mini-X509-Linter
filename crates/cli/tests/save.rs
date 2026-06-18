//! CLI-level `--save` integration tests for `mini-x509-lint` (feature 07).
//!
//! These drive the *actual* compiled binary's `--from-host` / `--save` /
//! `--force` surface against a hermetic, in-process TLS server, and assert on the
//! written PEM bundle, the overwrite policy, the round-trip re-lint, and the
//! write-failure error path.
//!
//! ## Why an `openssl s_server` fixture (not rcgen + rustls here)?
//!
//! The handshake-level coverage in `crates/fetch/tests/handshake.rs` already
//! stands up an `rcgen` + `rustls` server in-process. This CLI test lives in the
//! `cli` crate, which intentionally has *no* TLS/rustls/rcgen dependency (network
//! is opt-in behind the `fetch` feature and stays out of the `cli` dep tree).
//! Rather than add TLS crates to the `cli` crate just for a test, the local
//! server here is a short-lived `openssl s_server` on a loopback port with an
//! `openssl`-minted self-signed cert — consistent with the project's
//! "fixtures via openssl" convention and fully offline. If `openssl` is not on
//! `PATH`, the server-backed tests **skip** (printing a notice) so the suite
//! still runs everywhere; the pure-CLI error-path tests below need no server and
//! always run.
//!
//! The whole file is gated on `#[cfg(feature = "fetch")]`: without that feature
//! the binary has no `--from-host` / `--save` flags, so there is nothing to test.

#![cfg(feature = "fetch")]

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Absolute path to the compiled `mini-x509-lint` binary under test.
///
/// Provided by Cargo whenever the binary target is built — which, for this
/// feature-gated test, means the test harness was invoked with `--features
/// fetch`, so the binary likewise has the `fetch` flags compiled in.
const BIN: &str = env!("CARGO_BIN_EXE_mini-x509-lint");

/// Returns `true` if an `openssl` binary is available on `PATH`.
fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Reserves a free loopback TCP port by binding then immediately releasing it.
///
/// There is an inherent (tiny) race between release and `s_server` re-binding,
/// but on loopback in a test it is effectively never hit; this keeps the fixture
/// self-contained with no fixed port.
fn free_loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// A unique temp directory for a test's fixtures and outputs.
fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("mini-x509-cli-save-{tag}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// A running `openssl s_server` fixture: a self-signed cert on a loopback port.
///
/// Spawned with `-www` so it serves a trivial response and keeps the listener
/// open for repeated connects; killed on drop.
struct OpensslServer {
    port: u16,
    child: Child,
    #[allow(dead_code)]
    dir: PathBuf,
}

impl OpensslServer {
    /// Mint a self-signed `CN=localhost` end-entity cert and start `s_server`.
    fn start() -> Self {
        let dir = temp_dir("server");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");

        // Self-signed end-entity (CA:FALSE) so the leaf is a normal leaf. The
        // validity window straddles "now" (-days 3650), so no time-fragility.
        let status = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                cert.to_str().unwrap(),
                "-days",
                "3650",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn openssl req");
        assert!(status.success(), "openssl req must mint the test cert");

        let port = free_loopback_port();
        let child = Command::new("openssl")
            .args([
                "s_server",
                "-accept",
                &port.to_string(),
                "-cert",
                cert.to_str().unwrap(),
                "-key",
                key.to_str().unwrap(),
                "-www",
                "-quiet",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn openssl s_server");

        let server = Self { port, child, dir };
        server.wait_until_listening();
        server
    }

    /// Block until the server accepts loopback connections (bounded).
    fn wait_until_listening(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect_timeout(
                &format!("127.0.0.1:{}", self.port).parse().unwrap(),
                Duration::from_millis(200),
            )
            .is_ok()
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "openssl s_server did not start listening on port {}",
            self.port
        );
    }

    /// The `host:port` target string for `--from-host`.
    fn target(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

impl Drop for OpensslServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The captured result of running the binary.
struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Runs the binary with `args` and captures its output + exit code.
fn run(args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .output()
        .expect("spawn mini-x509-lint");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Extracts the lint-findings portion of stdout (everything from the first
/// `[rfc5280]` source header onward), dropping the `--from-host` chain/verdict
/// preamble so a live-fetch run and a file re-lint can be compared directly.
fn findings_section(stdout: &str) -> &str {
    match stdout.find("[rfc5280]") {
        Some(idx) => &stdout[idx..],
        None => stdout,
    }
}

/// Counts `-----BEGIN CERTIFICATE-----` blocks in a PEM string.
fn count_pem_blocks(pem: &str) -> usize {
    pem.matches("-----BEGIN CERTIFICATE-----").count()
}

mod no_server_needed {
    //! Error-path tests that never touch the network: they exercise the flag
    //! validation that fires before any fetch is attempted.
    use super::*;

    #[test]
    fn save_without_from_host_errors() {
        // `--save` with a file <PATH> input (no --from-host) is an error.
        let dir = temp_dir("save-no-host");
        let out = dir.join("never-written.pem");
        let result = run(&["/etc/hostname", "--save", out.to_str().unwrap()]);
        // Whatever path arg we pass, the flag-conflict must fire and exit nonzero
        // without writing the file.
        assert_ne!(result.code, Some(0), "stderr: {}", result.stderr);
        assert!(
            result.stderr.contains("--save"),
            "error should mention --save, got: {}",
            result.stderr
        );
        assert!(!out.exists(), "no file may be written on the error path");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn force_without_from_host_errors() {
        let result = run(&["/etc/hostname", "--force"]);
        assert_ne!(result.code, Some(0), "stderr: {}", result.stderr);
        assert!(
            result.stderr.contains("--force"),
            "error should mention --force, got: {}",
            result.stderr
        );
    }

    #[test]
    fn save_with_no_input_at_all_errors() {
        let dir = temp_dir("save-no-input");
        let out = dir.join("never-written.pem");
        let result = run(&["--save", out.to_str().unwrap()]);
        assert_ne!(result.code, Some(0), "stderr: {}", result.stderr);
        assert!(!out.exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}

mod server_backed {
    //! Tests that fetch from the local `openssl s_server`. These skip when
    //! `openssl` is unavailable so the suite still runs everywhere.
    use super::*;

    /// Sets up the server + a temp output dir, or returns `None` (test skips)
    /// when openssl is unavailable.
    fn setup(tag: &str) -> Option<(OpensslServer, PathBuf)> {
        if !openssl_available() {
            eprintln!("skipping {tag}: openssl not found on PATH");
            return None;
        }
        Some((OpensslServer::start(), temp_dir(tag)))
    }

    #[test]
    fn fetch_lints_leaf_and_prints_verdict() {
        let Some((server, dir)) = setup("fetch-verdict") else {
            return;
        };

        let result = run(&["--from-host", &server.target(), "--sni", "localhost"]);

        // The presented-chain section + verdict go to stdout, lint findings too.
        assert!(
            result.stdout.contains("presented chain:"),
            "stdout: {}",
            result.stdout
        );
        // The self-signed test cert is untrusted: the verdict must be invalid.
        assert!(
            result.stdout.contains("verification: invalid"),
            "expected an invalid verdict for the self-signed cert, stdout: {}",
            result.stdout
        );
        // The leaf is linted: at least one source section is rendered.
        assert!(
            result.stdout.contains("[rfc5280]"),
            "the leaf must be linted, stdout: {}",
            result.stdout
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_writes_pem_bundle_and_round_trips() {
        let Some((server, dir)) = setup("save-roundtrip") else {
            return;
        };
        let saved = dir.join("chain.pem");

        // Live fetch + save.
        let live = run(&[
            "--from-host",
            &server.target(),
            "--sni",
            "localhost",
            "--save",
            saved.to_str().unwrap(),
        ]);
        assert!(
            saved.exists(),
            "the bundle must be written (stderr: {})",
            live.stderr
        );
        // Confirmation line is on stderr (outside any stdout golden scope).
        assert!(
            live.stderr.contains("saved presented chain to"),
            "stderr: {}",
            live.stderr
        );

        // The written file is valid PEM with at least the leaf block.
        let pem = std::fs::read_to_string(&saved).expect("read saved bundle");
        assert!(
            count_pem_blocks(&pem) >= 1,
            "saved bundle must contain at least the leaf, got:\n{pem}"
        );

        // Round-trip: re-lint the saved file via the normal <PATH> input and
        // assert the leaf findings match the live-fetch run exactly.
        let relinted = run(&[saved.to_str().unwrap()]);
        assert_eq!(
            findings_section(&relinted.stdout),
            findings_section(&live.stdout),
            "re-linting the saved bundle must reproduce the live leaf findings"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_happens_regardless_of_invalid_verdict() {
        let Some((server, dir)) = setup("save-invalid") else {
            return;
        };
        let saved = dir.join("untrusted.pem");

        let live = run(&[
            "--from-host",
            &server.target(),
            "--sni",
            "localhost",
            "--save",
            saved.to_str().unwrap(),
        ]);

        // The verdict is invalid (self-signed) yet the file is still written.
        assert!(
            live.stdout.contains("verification: invalid"),
            "stdout: {}",
            live.stdout
        );
        assert!(
            saved.exists(),
            "save must occur even for an untrusted/invalid chain"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refuses_overwrite_without_force_then_succeeds_with_force() {
        let Some((server, dir)) = setup("save-overwrite") else {
            return;
        };
        let saved = dir.join("existing.pem");

        // Pre-existing file with sentinel content.
        std::fs::write(&saved, b"SENTINEL-DO-NOT-CLOBBER").unwrap();

        // Without --force: refuse, leave the file untouched, exit nonzero.
        let refused = run(&[
            "--from-host",
            &server.target(),
            "--sni",
            "localhost",
            "--save",
            saved.to_str().unwrap(),
        ]);
        assert_ne!(refused.code, Some(0), "stderr: {}", refused.stderr);
        assert!(
            refused.stderr.contains("refusing to overwrite")
                || refused.stderr.to_lowercase().contains("overwrite"),
            "stderr should explain the overwrite refusal, got: {}",
            refused.stderr
        );
        assert_eq!(
            std::fs::read(&saved).unwrap(),
            b"SENTINEL-DO-NOT-CLOBBER",
            "the pre-existing file must be left unchanged"
        );

        // With --force: overwrite succeeds and the file is now a PEM bundle.
        let forced = run(&[
            "--from-host",
            &server.target(),
            "--sni",
            "localhost",
            "--save",
            saved.to_str().unwrap(),
            "--force",
        ]);
        assert!(
            forced.stderr.contains("saved presented chain to"),
            "stderr: {}",
            forced.stderr
        );
        let pem = std::fs::read_to_string(&saved).expect("read overwritten bundle");
        assert!(
            count_pem_blocks(&pem) >= 1,
            "the forced overwrite must replace the sentinel with a PEM bundle"
        );
        assert!(
            !pem.contains("SENTINEL"),
            "the sentinel content must be gone after --force"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_to_missing_parent_dir_is_generic_error_nonzero() {
        let Some((server, dir)) = setup("save-missing-parent") else {
            return;
        };
        // A parent directory that does not exist (we never create it).
        let missing: PathBuf = dir.join("nope").join("chain.pem");
        assert!(!missing.parent().map(Path::exists).unwrap_or(true));

        let result = run(&[
            "--from-host",
            &server.target(),
            "--sni",
            "localhost",
            "--save",
            missing.to_str().unwrap(),
        ]);

        // Generic error, nonzero exit, no panic/stack trace leakage, no file.
        assert_ne!(result.code, Some(0), "stderr: {}", result.stderr);
        assert!(
            result.stderr.starts_with("error:"),
            "errors are single-line and generic, got: {}",
            result.stderr
        );
        assert!(
            !result.stderr.contains("panicked"),
            "no panic should ever reach the user, got: {}",
            result.stderr
        );
        assert!(
            !missing.exists(),
            "nothing may be written under a missing dir"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
