//! CLI-level `--from-host` PRESENTED-CHAIN tests for `mini-x509-lint`
//! (feature 15, Refinement 2).
//!
//! These drive the actual compiled binary's `--from-host` path against a
//! hermetic, in-process loopback TLS server that presents a configured chain, and
//! assert that the additive `Chain checks:` section appears AFTER the leaf report
//! and the connection verdict, with the root-absent `chain_issuer_not_in_chain`
//! Notice (never an Error) and the trust-vs-lint separation.
//!
//! ## Why an `openssl s_server` fixture (not rcgen + rustls here)?
//!
//! The `cli` crate intentionally has *no* TLS/rustls/rcgen dependency (network is
//! opt-in behind the `fetch` feature and stays out of the `cli` dep tree). Rather
//! than add TLS crates to the `cli` test target just for a test, the local server
//! here is a short-lived `openssl s_server` on a loopback port, presenting a
//! REAL leaf → intermediate → root chain minted with openssl (the same
//! "fixtures via openssl" convention as `crates/cli/tests/save.rs`). The
//! handshake-level rcgen+rustls coverage already lives in
//! `crates/fetch/tests/handshake.rs`; this file exercises the CLI surface.
//! If `openssl` is not on `PATH`, the server-backed tests **skip** (printing a
//! notice) so the suite still runs everywhere.
//!
//! The whole file is gated on `#[cfg(feature = "fetch")]`: without that feature
//! the binary has no `--from-host` flag, so there is nothing to test.
//!
//! ## Trust-vs-lint separation (the load-bearing property)
//!
//! The minted chain's root is NOT in any public trust store, so the connection
//! `verification:` verdict is always `invalid` (trust to a root) — while the
//! chain LINTS pass (the presented links are structurally + cryptographically
//! sound). The tests assert both independently, proving the lints do not
//! duplicate trust validation.

#![cfg(feature = "fetch")]

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Absolute path to the compiled `mini-x509-lint` binary under test.
const BIN: &str = env!("CARGO_BIN_EXE_mini-x509-lint");

/// Serializes the server-backed tests. Each picks an ephemeral port and hands it
/// to a separate `openssl s_server` process, which is inherently racy under the
/// parallel test runner (another test can claim the freed port first). Holding
/// this lock for the lifetime of each test's server eliminates the race without
/// adding a dependency. Cheap: there are only a handful of these tests.
static SERVER_LOCK: Mutex<()> = Mutex::new(());

/// Acquires the server lock, recovering from a poisoned mutex (a panicking test
/// must not wedge the others).
fn server_guard() -> MutexGuard<'static, ()> {
    SERVER_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

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
fn free_loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// A unique temp directory for a test's fixtures.
fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("mini-x509-cli-fromhost-{tag}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// The SNI / leaf CN used for every minted chain.
const LEAF_CN: &str = "from-host-leaf.example.com";

/// A minted leaf → intermediate → root chain (PEM files in a temp dir).
struct MintedChain {
    dir: PathBuf,
    leaf: PathBuf,
    leaf_key: PathBuf,
    inter: PathBuf,
    root: PathBuf,
}

impl MintedChain {
    /// Mint a real RSA leaf → intermediate CA → self-signed root with openssl.
    ///
    /// Validity windows are PINNED to explicit, strictly-NESTED absolute dates so
    /// the leaf ⊆ intermediate ⊆ root regardless of the per-second wall-clock
    /// drift between the three sequential `openssl` signings. (The earlier
    /// `-days 3650`-everywhere approach was flaky: when the second ticked over
    /// between the intermediate and leaf signings, the leaf's notAfter landed
    /// ~1s after the intermediate's, so `chain_validity_nested` correctly Warned
    /// and the "no Warn" assertions failed intermittently.) The windows still
    /// straddle "now" with multi-year margins on both sides, so the tests are not
    /// time-fragile for years. `openssl` ≥ 1.1.1 (3.6.2 here) supports
    /// `-not_before` / `-not_after` on both `req -x509` and `x509 -req`.
    ///
    /// Nesting: root `2020 → 2040`, intermediate `2021 → 2039`, leaf
    /// `2022 → 2038` (UTC).
    fn mint() -> Self {
        let dir = temp_dir("chain");
        let p = |n: &str| dir.join(n);

        // Root (self-signed CA): widest window.
        sh(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            p("root.key").to_str().unwrap(),
            "-out",
            p("root.pem").to_str().unwrap(),
            "-not_before",
            "20200101000000Z",
            "-not_after",
            "20400101000000Z",
            "-subj",
            "/CN=from-host test root",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-addext",
            "subjectKeyIdentifier=hash",
            "-addext",
            "authorityKeyIdentifier=keyid",
        ]);

        // Intermediate CSR + sign by root.
        sh(&[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            p("inter.key").to_str().unwrap(),
            "-out",
            p("inter.csr").to_str().unwrap(),
            "-subj",
            "/CN=from-host test intermediate",
        ]);
        std::fs::write(
            p("inter.ext"),
            "basicConstraints=critical,CA:TRUE,pathlen:0\n\
             keyUsage=critical,keyCertSign,cRLSign\n\
             subjectKeyIdentifier=hash\n\
             authorityKeyIdentifier=keyid\n",
        )
        .unwrap();
        sh(&[
            "x509",
            "-req",
            "-in",
            p("inter.csr").to_str().unwrap(),
            "-CA",
            p("root.pem").to_str().unwrap(),
            "-CAkey",
            p("root.key").to_str().unwrap(),
            "-set_serial",
            "2",
            "-not_before",
            "20210101000000Z",
            "-not_after",
            "20390101000000Z",
            "-extfile",
            p("inter.ext").to_str().unwrap(),
            "-out",
            p("inter.pem").to_str().unwrap(),
        ]);

        // Leaf CSR + sign by intermediate.
        sh(&[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            p("leaf.key").to_str().unwrap(),
            "-out",
            p("leaf.csr").to_str().unwrap(),
            "-subj",
            &format!("/CN={LEAF_CN}"),
        ]);
        std::fs::write(
            p("leaf.ext"),
            format!(
                "basicConstraints=critical,CA:FALSE\n\
                 keyUsage=critical,digitalSignature,keyEncipherment\n\
                 extendedKeyUsage=serverAuth\n\
                 subjectAltName=DNS:{LEAF_CN}\n\
                 subjectKeyIdentifier=hash\n\
                 authorityKeyIdentifier=keyid\n"
            ),
        )
        .unwrap();
        sh(&[
            "x509",
            "-req",
            "-in",
            p("leaf.csr").to_str().unwrap(),
            "-CA",
            p("inter.pem").to_str().unwrap(),
            "-CAkey",
            p("inter.key").to_str().unwrap(),
            "-set_serial",
            "3",
            "-not_before",
            "20220101000000Z",
            "-not_after",
            "20380101000000Z",
            "-extfile",
            p("leaf.ext").to_str().unwrap(),
            "-out",
            p("leaf.pem").to_str().unwrap(),
        ]);

        Self {
            leaf: p("leaf.pem"),
            leaf_key: p("leaf.key"),
            inter: p("inter.pem"),
            root: p("root.pem"),
            dir,
        }
    }

    /// Writes a `-cert_chain` file from the given component PEMs (concatenated)
    /// and returns its path.
    fn chain_file(&self, name: &str, parts: &[&Path]) -> PathBuf {
        let mut bundle = Vec::new();
        for part in parts {
            bundle.extend_from_slice(&std::fs::read(part).unwrap());
        }
        let out = self.dir.join(name);
        std::fs::write(&out, bundle).unwrap();
        out
    }
}

impl Drop for MintedChain {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Runs `openssl <args>`, asserting success.
fn sh(args: &[&str]) {
    let status = Command::new("openssl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn openssl");
    assert!(status.success(), "openssl {args:?} must succeed");
}

/// A running `openssl s_server` presenting `leaf` (+ optional `-cert_chain`).
struct Server {
    port: u16,
    child: Child,
}

impl Server {
    /// Start `s_server` with the leaf cert/key and, optionally, a chain file of
    /// the additional certs to present (intermediate, or intermediate+root).
    ///
    /// Picking an ephemeral port and then handing it to a separate `s_server`
    /// process is inherently racy under the parallel test runner (another test can
    /// claim the freed port first). We retry a few times with a fresh port so the
    /// suite is robust without serializing the tests.
    fn start(leaf: &Path, key: &Path, cert_chain: Option<&Path>) -> Self {
        for attempt in 0..5 {
            let port = free_loopback_port();
            let mut args: Vec<String> = vec![
                "s_server".into(),
                "-accept".into(),
                port.to_string(),
                "-cert".into(),
                leaf.to_str().unwrap().into(),
                "-key".into(),
                key.to_str().unwrap().into(),
                "-www".into(),
                "-quiet".into(),
            ];
            if let Some(chain) = cert_chain {
                args.push("-cert_chain".into());
                args.push(chain.to_str().unwrap().into());
            }
            let mut child = Command::new("openssl")
                .args(&args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn openssl s_server");
            if wait_until_listening(port) {
                return Self { port, child };
            }
            // This port did not come up (lost the bind race): kill and retry.
            let _ = child.kill();
            let _ = child.wait();
            let _ = attempt;
        }
        panic!("openssl s_server failed to start after 5 attempts");
    }

    fn target(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Polls `port` until it accepts a loopback connection, returning `true` once it
/// does or `false` after a bounded wait (so the caller can retry a fresh port).
fn wait_until_listening(port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Runs the binary with `args`, capturing stdout + exit code.
struct Run {
    code: Option<i32>,
    stdout: String,
}

/// A reference "now" (2026-12-01 in Unix seconds) inside the minted chain's leaf
/// validity window (2022 → 2038). Pinning `--now` keeps the per-cert lint output
/// (notably `hygiene_not_expired`) wall-clock independent — the minted leaf has a
/// fixed `2038` `notAfter`, so without pinning the per-cert section would start
/// expiring then; `--now` does not affect the `verification:` trust verdict.
const TEST_NOW: &str = "1796083200";

fn run(args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .args(["--now", TEST_NOW])
        .args(args)
        .output()
        .expect("spawn mini-x509-lint");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
    }
}

/// The substring of stdout from `Chain checks:` onward, or `""` if absent.
fn chain_section(stdout: &str) -> &str {
    match stdout.find("Chain checks:") {
        Some(i) => &stdout[i..],
        None => "",
    }
}

mod presented_chain {
    use super::*;

    /// Skips (returns `None`) when openssl is unavailable; otherwise returns the
    /// serializing server lock guard (held for the rest of the test so the
    /// ephemeral-port handoff to `s_server` cannot race a parallel test).
    fn require_openssl(tag: &str) -> Option<MutexGuard<'static, ()>> {
        if !openssl_available() {
            eprintln!("skipping {tag}: openssl not found on PATH");
            return None;
        }
        Some(server_guard())
    }

    /// Server presents leaf + intermediate (NO root). The chain section appears
    /// after the verdict; the present link checks pass; the top intermediate
    /// carries the `chain_issuer_not_in_chain` Notice (root absent), NOT an Error.
    #[test]
    fn leaf_and_intermediate_no_root_fires_issuer_not_in_chain_notice() {
        let Some(_guard) = require_openssl("leaf+inter") else {
            return;
        };
        // Setup: present leaf + intermediate only.
        let chain = MintedChain::mint();
        let cert_chain = chain.chain_file("present_inter.pem", [chain.inter.as_path()].as_slice());
        let server = Server::start(&chain.leaf, &chain.leaf_key, Some(&cert_chain));

        // Invoke.
        let result = run(&["--from-host", &server.target(), "--sni", LEAF_CN]);
        let stdout = &result.stdout;

        // Expect: the leaf report + verdict are present and UNCHANGED in ordering
        // (verdict precedes the chain section).
        assert!(
            stdout.contains("presented chain:"),
            "the presented-chain display must render:\n{stdout}"
        );
        let verdict_pos = stdout
            .find("verification:")
            .unwrap_or_else(|| panic!("missing verification verdict:\n{stdout}"));
        let chain_pos = stdout
            .find("Chain checks:")
            .unwrap_or_else(|| panic!("missing Chain checks section:\n{stdout}"));
        assert!(
            verdict_pos < chain_pos,
            "the chain section must come AFTER the verdict:\n{stdout}"
        );

        // The top intermediate carries the Notice, and there is NO Error/Warn.
        let section = chain_section(stdout);
        assert!(
            section.contains("notice [chain_issuer_not_in_chain]"),
            "a root-absent presented chain must fire the issuer-not-in-chain Notice:\n{stdout}"
        );
        assert!(
            !section.contains("error [") && !section.contains("warn ["),
            "the present link must be sound (no Error/Warn):\n{stdout}"
        );

        // The chain Notice must never trip `--fail-on error`. Isolate the chain
        // pass with `--source chain` so the per-cert leaf findings (the minted
        // leaf uses a long, BR-non-compliant validity window — out of scope for
        // this chain test) do not influence the exit code.
        let chain_only = run(&[
            "--from-host",
            &server.target(),
            "--sni",
            LEAF_CN,
            "--source",
            "chain",
            "--fail-on",
            "error",
        ]);
        assert_eq!(
            chain_only.code,
            Some(0),
            "a lone chain Notice must exit 0 under --fail-on error:\n{}",
            chain_only.stdout
        );
    }

    /// Trust-vs-lint separation: the same root-absent chain yields
    /// `verification: invalid` (untrusted root) WHILE the chain lints pass.
    #[test]
    fn verdict_invalid_while_chain_lints_pass() {
        let Some(_guard) = require_openssl("trust-vs-lint") else {
            return;
        };
        let chain = MintedChain::mint();
        let cert_chain = chain.chain_file("present_inter.pem", [chain.inter.as_path()].as_slice());
        let server = Server::start(&chain.leaf, &chain.leaf_key, Some(&cert_chain));

        let result = run(&["--from-host", &server.target(), "--sni", LEAF_CN]);
        let stdout = &result.stdout;

        // The connection verdict (trust to a root) is invalid (untrusted root)...
        assert!(
            stdout.contains("verification: invalid"),
            "an untrusted root must yield an invalid connection verdict:\n{stdout}"
        );
        // ...while the chain LINTS are sound (only the benign Notice, no Error).
        let section = chain_section(stdout);
        assert!(
            !section.contains("error ["),
            "the present links must lint clean despite the untrusted root:\n{stdout}"
        );
    }

    /// Server presents leaf + intermediate + root. Links pass and there is NO
    /// `chain_issuer_not_in_chain` Notice (the self-signed root is its own anchor).
    #[test]
    fn leaf_intermediate_and_root_has_no_issuer_not_in_chain_notice() {
        let Some(_guard) = require_openssl("leaf+inter+root") else {
            return;
        };
        let chain = MintedChain::mint();
        let cert_chain = chain.chain_file(
            "present_full.pem",
            [chain.inter.as_path(), chain.root.as_path()].as_slice(),
        );
        let server = Server::start(&chain.leaf, &chain.leaf_key, Some(&cert_chain));

        let result = run(&["--from-host", &server.target(), "--sni", LEAF_CN]);
        let stdout = &result.stdout;

        let section = chain_section(stdout);
        assert!(
            !section.is_empty(),
            "a 3-cert presented chain must render the chain section:\n{stdout}"
        );
        assert!(
            !section.contains("chain_issuer_not_in_chain"),
            "a presented chain that includes its root must NOT fire the Notice:\n{stdout}"
        );
        assert!(
            !section.contains("error [") && !section.contains("warn ["),
            "the full presented chain must lint clean:\n{stdout}"
        );
    }

    /// Server presents a single leaf only → NO chain section (no link to lint);
    /// the leaf report + verdict are still rendered.
    #[test]
    fn single_leaf_has_no_chain_section() {
        let Some(_guard) = require_openssl("single-leaf") else {
            return;
        };
        let chain = MintedChain::mint();
        let server = Server::start(&chain.leaf, &chain.leaf_key, None);

        let result = run(&["--from-host", &server.target(), "--sni", LEAF_CN]);
        let stdout = &result.stdout;

        assert!(
            stdout.contains("verification:"),
            "the verdict must still render for a single leaf:\n{stdout}"
        );
        assert!(
            !stdout.contains("Chain checks:"),
            "a single presented leaf has no link to lint → no chain section:\n{stdout}"
        );
    }

    /// JSON (leaf + intermediate, no root): the document gains a sibling `chain`
    /// key alongside the unchanged `presented_chain` / `verification` / `outcomes`
    /// keys; the `chain` carries the link outcome + the issuer-not-in-chain Notice.
    #[test]
    fn json_leaf_and_intermediate_gains_sibling_chain_key() {
        let Some(_guard) = require_openssl("json-leaf+inter") else {
            return;
        };
        let chain = MintedChain::mint();
        let cert_chain = chain.chain_file("present_inter.pem", [chain.inter.as_path()].as_slice());
        let server = Server::start(&chain.leaf, &chain.leaf_key, Some(&cert_chain));

        let result = run(&[
            "--from-host",
            &server.target(),
            "--sni",
            LEAF_CN,
            "--format",
            "json",
        ]);
        let value: serde_json::Value =
            serde_json::from_str(&result.stdout).expect("--from-host JSON must be valid JSON");
        let obj = value.as_object().expect("must be a JSON object");

        // The existing keys are present and untouched...
        for key in ["presented_chain", "verification", "outcomes"] {
            assert!(obj.contains_key(key), "missing existing key {key}");
        }
        // ...and the additive sibling `chain` key carries the link + Notice.
        let links = obj
            .get("chain")
            .and_then(|c| c.as_array())
            .expect("the additive `chain` key must be a JSON array");
        assert_eq!(links.len(), 1, "leaf + intermediate yields one link");
        let outcomes = links[0]["outcomes"].as_array().expect("link outcomes");
        let has_notice = outcomes.iter().any(|o| {
            o["lint_id"] == serde_json::json!("chain_issuer_not_in_chain")
                && o["findings"]
                    .as_array()
                    .map(|f| !f.is_empty())
                    .unwrap_or(false)
        });
        assert!(
            has_notice,
            "the chain JSON must carry the issuer-not-in-chain Notice:\n{}",
            result.stdout
        );
    }

    /// JSON single leaf → NO `chain` key (no link to lint).
    #[test]
    fn json_single_leaf_has_no_chain_key() {
        let Some(_guard) = require_openssl("json-single-leaf") else {
            return;
        };
        let chain = MintedChain::mint();
        let server = Server::start(&chain.leaf, &chain.leaf_key, None);

        let result = run(&[
            "--from-host",
            &server.target(),
            "--sni",
            LEAF_CN,
            "--format",
            "json",
        ]);
        let value: serde_json::Value =
            serde_json::from_str(&result.stdout).expect("--from-host JSON must be valid JSON");
        assert!(
            value.get("chain").is_none(),
            "a single-leaf presented chain must have no `chain` key:\n{}",
            result.stdout
        );
    }
}
