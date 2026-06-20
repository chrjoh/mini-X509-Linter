//! Integration tests for the `--info` certificate inspection mode of the
//! `mini-x509-lint` binary.
//!
//! These drive the *actual* compiled binary (via the Cargo-provided
//! `CARGO_BIN_EXE_mini-x509-lint` env var) over committed `testdata/` fixtures
//! and snapshot stdout with `insta`. They lock the deterministic summary block
//! (field order, KeyUsage-bit display, BasicConstraints, SAN, algorithm display),
//! prove `--info` does NOT suppress linting and does NOT change the exit code,
//! and guard the additive contract (default output unchanged when `--info` is
//! omitted).
//!
//! ## Fixture provenance — `slh_dsa_root_ca.pem` (openssl-generated, NOT cert-bar)
//!
//! `testdata/slh_dsa_root_ca.pem` is a self-signed **SLH-DSA-SHA2-128s
//! (SPHINCS+) post-quantum root CA** generated locally with `openssl` 3.6.2
//! (which supports SLH-DSA natively). It is NOT vendored from the user's external
//! `cert-bar` tool: this linter is meant to be an INDEPENDENT oracle for
//! cert-bar's output, so a cert-bar-derived fixture would create a circular
//! validation dependency. The recipe lives in `testdata/generate.sh`.
//!
//! Generated shape (confirm with `openssl x509 -noout -text`):
//! - `Signature Algorithm: SLH-DSA-SHA2-128s` — algorithm OID
//!   `2.16.840.1.101.3.4.3.20`. The OID is *always* present; the human-readable
//!   name is best-effort. `oid-registry` 0.8 does not itself know this OID, but
//!   the linter enriches it to `SLH-DSA-SHA2-128s` via the feature-13 PQC
//!   parameter-set classification, so the field renders the name AND the OID.
//! - `KeyUsage = Certificate Sign, CRL Sign` (critical).
//! - `BasicConstraints` critical `CA:TRUE`.
//! - `SAN DNS:slh-dsa-test-root`.
//! - `subject == issuer == CN=SLH-DSA Test Root, C=SE, O=mini-x509-linter
//!   testdata` (self-signed root).
//!
//! ## Determinism
//!
//! The summary shows only the certificate's OWN fields (including its own
//! `notBefore` / `notAfter` dates), never wall-clock time, so the snapshots are
//! stable. The lint report appended after the summary is itself deterministic for
//! these all-pass fixtures (no `hygiene_not_expired` timestamp surfaces because
//! both fixtures are currently valid and report no findings).

use std::path::PathBuf;
use std::process::{Command, Output};

/// Absolute path to the compiled `mini-x509-lint` binary under test.
const BIN: &str = env!("CARGO_BIN_EXE_mini-x509-lint");

/// The SLH-DSA-SHA2-128s algorithm OID. Always present in the summary regardless
/// of whether a human-readable name is resolved.
const SLH_DSA_OID: &str = "2.16.840.1.101.3.4.3.20";

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

/// A reference "now" (2026-12-01 in Unix seconds) inside every currently-valid
/// fixture window. Pinning `--now` keeps the `--info` snapshots (which append the
/// lint report) deterministic regardless of the wall clock — without it, the
/// currently-valid fixtures (good.pem, chain_bundle.pem's leaf) would trip
/// `hygiene_not_expired` once the real date passes their `notAfter`. Today the
/// real clock is inside the windows, so pinning produces byte-identical output.
const TEST_NOW: &str = "1796083200";

/// Runs the binary with `args` and returns the captured [`Output`]. Pins `--now`
/// so the appended lint report is wall-clock independent.
fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(["--now", TEST_NOW])
        .args(args)
        .output()
        .expect("failed to spawn mini-x509-lint binary")
}

/// Runs the binary and returns its stdout decoded as UTF-8.
fn stdout(args: &[&str]) -> String {
    let output = run(args);
    String::from_utf8(output.stdout).expect("stdout must be UTF-8")
}

/// Returns the `Certificate Summary` block only (everything up to, but not
/// including, the blank-line separator that precedes the lint report). Used to
/// assert on the summary independently of the appended lint report.
fn summary_block(out: &str) -> &str {
    // `main.rs` emits the summary, then `"\n"`, then the lint report. The summary
    // ends at the first blank line.
    out.split("\n\n")
        .next()
        .expect("output must contain a summary block")
}

mod good_cert_text {
    use super::*;

    #[test]
    fn info_summary_then_lint_report_snapshot() {
        // Setup / Invoke: `--info` prints the summary, then STILL runs the lints.
        let out = stdout(&["--info", &fixture_arg("good.pem")]);

        // Find / Expect: good.pem is an RSA-2048 leaf, CN=good.example.com, SAN
        // present, NO KeyUsage extension (shown as the "(not present)" marker).
        // The whole block (summary + the 5-group lint report) is snapshotted.
        insta::assert_snapshot!("good_info_text", out);
    }

    #[test]
    fn info_does_not_suppress_the_lint_report() {
        // Proves `--info` is purely additive: the lint report still follows the
        // summary block.
        let out = stdout(&["--info", &fixture_arg("good.pem")]);
        assert!(
            out.starts_with("Certificate Summary\n"),
            "output must lead with the summary block"
        );
        assert!(
            out.contains("[rfc5280]"),
            "the lint report must still follow the summary"
        );
        assert!(
            out.contains("OK: no findings"),
            "the lint verdict line must still be printed under --info"
        );
    }

    #[test]
    fn good_pem_has_no_key_usage_extension() {
        // good.pem ships no KeyUsage extension; the summary marks it absent.
        let out = stdout(&["--info", &fixture_arg("good.pem")]);
        assert!(
            out.contains("Key Usage:           (not present)"),
            "good.pem KeyUsage must render the absent marker, got:\n{out}"
        );
    }
}

mod slh_dsa_ca_text {
    use super::*;

    #[test]
    fn info_summary_snapshot() {
        // Setup / Invoke: the openssl-generated SLH-DSA root CA. Its lint report
        // is purpose-resolved to `generic` (no EKU) -> rfc5280/pqc/hygiene only,
        // all passing; deterministic, so the whole block is snapshotted.
        let out = stdout(&["--info", &fixture_arg("slh_dsa_root_ca.pem")]);
        insta::assert_snapshot!("slh_dsa_info_text", out);
    }

    #[test]
    fn signature_algorithm_shows_oid_and_enriched_name() {
        // Load-bearing check: the raw dotted OID is ALWAYS present (the
        // graceful-degradation contract). Best-effort name: task 01 enriches the
        // SLH-DSA OID to `SLH-DSA-SHA2-128s`, so assert the name too — a
        // name-resolution regression that drops it must fail this test.
        let out = stdout(&["--info", &fixture_arg("slh_dsa_root_ca.pem")]);
        let summary = summary_block(&out);

        // OID presence is the always-true assertion.
        assert!(
            summary.contains(SLH_DSA_OID),
            "summary must always show the raw SLH-DSA OID {SLH_DSA_OID}, got:\n{summary}"
        );
        // Best-effort name, populated by the feature-13 classification.
        assert!(
            summary.contains("Signature Algorithm: SLH-DSA-SHA2-128s (2.16.840.1.101.3.4.3.20)"),
            "Signature Algorithm must render the enriched name plus OID, got:\n{summary}"
        );
        // The signature-algorithm field is never empty / never an `(unavailable)`
        // crash marker.
        assert!(
            !summary.contains("Signature Algorithm: (unavailable)"),
            "the signature algorithm field must never degrade to (unavailable)"
        );
    }

    #[test]
    fn public_key_shows_oid_and_enriched_name() {
        // The public-key algorithm is the same PQC OID and is likewise enriched.
        let out = stdout(&["--info", &fixture_arg("slh_dsa_root_ca.pem")]);
        let summary = summary_block(&out);
        assert!(
            summary.contains("Public Key:          SLH-DSA-SHA2-128s (2.16.840.1.101.3.4.3.20)"),
            "Public Key must render the enriched name plus OID, got:\n{summary}"
        );
    }

    #[test]
    fn key_usage_lists_exactly_cert_sign_and_crl_sign_critical() {
        // KeyUsage-bit display correctness: the CA asserts exactly keyCertSign +
        // cRLSign (critical). Assert the full multi-bit set so bit-mapping is
        // genuinely exercised, and assert the UNASSERTED bits are NOT shown.
        let out = stdout(&["--info", &fixture_arg("slh_dsa_root_ca.pem")]);
        let summary = summary_block(&out);
        assert!(
            summary.contains("Key Usage:           Certificate Sign, CRL Sign (critical)"),
            "KeyUsage must list exactly Certificate Sign, CRL Sign (critical), got:\n{summary}"
        );

        // The bits this CA does NOT assert must not leak into the display.
        let ku_line = summary
            .lines()
            .find(|l| l.contains("Key Usage:"))
            .expect("summary must contain a Key Usage line");
        for absent in [
            "Digital Signature",
            "Non Repudiation",
            "Key Encipherment",
            "Data Encipherment",
            "Key Agreement",
            "Encipher Only",
            "Decipher Only",
        ] {
            assert!(
                !ku_line.contains(absent),
                "unasserted KeyUsage bit {absent:?} must not appear in: {ku_line:?}"
            );
        }
    }

    #[test]
    fn basic_constraints_shows_ca_true_critical() {
        let out = stdout(&["--info", &fixture_arg("slh_dsa_root_ca.pem")]);
        let summary = summary_block(&out);
        assert!(
            summary.contains("Basic Constraints:   CA:true (critical)"),
            "BasicConstraints must render CA:true (critical), got:\n{summary}"
        );
    }

    #[test]
    fn san_entry_present() {
        let out = stdout(&["--info", &fixture_arg("slh_dsa_root_ca.pem")]);
        let summary = summary_block(&out);
        assert!(
            summary.contains("Subject Alt Name:    DNS:slh-dsa-test-root (not critical)"),
            "SAN must render DNS:slh-dsa-test-root, got:\n{summary}"
        );
    }

    #[test]
    fn subject_equals_issuer_for_self_signed_root() {
        let out = stdout(&["--info", &fixture_arg("slh_dsa_root_ca.pem")]);
        let summary = summary_block(&out);
        let dn = "CN=SLH-DSA Test Root, C=SE, O=mini-x509-linter testdata";
        assert!(
            summary.contains(&format!("Subject:             {dn}")),
            "subject DN must render as {dn:?}, got:\n{summary}"
        );
        assert!(
            summary.contains(&format!("Issuer:              {dn}")),
            "issuer DN must equal subject for a self-signed root, got:\n{summary}"
        );
    }
}

mod json_envelope {
    use super::*;

    #[test]
    fn info_json_has_summary_and_lints_keys() {
        // `--info --format json` emits a single top-level object
        // `{ "summary": {…}, "lints": [ … ] }`.
        let raw = stdout(&["--info", "--format", "json", &fixture_arg("good.pem")]);
        let value: serde_json::Value =
            serde_json::from_str(&raw).expect("--info JSON output must parse");

        let obj = value.as_object().expect("--info JSON must be an object");
        assert!(
            obj.contains_key("summary"),
            "envelope must have a summary key"
        );
        assert!(obj.contains_key("lints"), "envelope must have a lints key");
        assert!(
            value["summary"].is_object(),
            "summary must be a JSON object"
        );
        assert!(value["lints"].is_array(), "lints must be a JSON array");
    }

    #[test]
    fn lints_array_matches_bare_feature_02_shape() {
        // The `lints` array must equal the bare (feature-02) lint JSON verbatim,
        // so combining `--info` does not alter the per-outcome shape.
        let bare = stdout(&["--format", "json", &fixture_arg("good.pem")]);
        let bare_value: serde_json::Value =
            serde_json::from_str(&bare).expect("bare JSON output must parse");

        let enveloped = stdout(&["--info", "--format", "json", &fixture_arg("good.pem")]);
        let env_value: serde_json::Value =
            serde_json::from_str(&enveloped).expect("--info JSON output must parse");

        assert_eq!(
            env_value["lints"], bare_value,
            "the lints array must match the bare feature-02 JSON verbatim"
        );

        // Spot-check the per-outcome shape (feature 02): one object per lint with
        // these keys.
        let first = env_value["lints"]
            .as_array()
            .and_then(|a| a.first())
            .expect("lints must contain at least one outcome");
        for key in ["lint_id", "source", "applicability", "findings"] {
            assert!(
                first.get(key).is_some(),
                "each lint outcome must carry the {key:?} key (feature-02 shape)"
            );
        }
    }

    #[test]
    fn summary_object_snapshot() {
        // Snapshot the summary object alone (re-serialized) so the JSON summary
        // shape is locked independent of the binary's exact whitespace.
        let raw = stdout(&["--info", "--format", "json", &fixture_arg("good.pem")]);
        let value: serde_json::Value =
            serde_json::from_str(&raw).expect("--info JSON output must parse");
        insta::assert_json_snapshot!("good_info_json_summary", value["summary"]);
    }
}

mod default_unchanged {
    use super::*;

    #[test]
    fn default_text_has_no_summary_block() {
        // Without `--info`, the default text output must not contain the summary.
        let out = stdout(&[&fixture_arg("good.pem")]);
        assert!(
            !out.contains("Certificate Summary"),
            "default text must not print the summary block"
        );
    }

    #[test]
    fn default_json_is_a_bare_lint_array() {
        // Without `--info`, the default JSON output is the bare feature-02 lint
        // array, NOT the `{ summary, lints }` envelope.
        let raw = stdout(&["--format", "json", &fixture_arg("good.pem")]);
        let value: serde_json::Value = serde_json::from_str(&raw).expect("JSON must parse");
        assert!(
            value.is_array(),
            "default JSON must remain a bare lint array, not an envelope object"
        );
    }

    #[test]
    fn info_does_not_change_the_exit_code() {
        // good.pem reports no findings, so both runs exit 0; `--info` must never
        // alter the exit code (it is driven solely by --fail-on / findings).
        let without = run(&[&fixture_arg("good.pem")]);
        let with = run(&["--info", &fixture_arg("good.pem")]);
        assert_eq!(
            without.status.code(),
            with.status.code(),
            "--info must not change the process exit code"
        );
        assert_eq!(
            without.status.code(),
            Some(0),
            "an all-pass fixture must exit 0 with or without --info"
        );
    }
}

mod determinism {
    use super::*;

    #[test]
    fn text_summary_is_byte_identical_across_runs() {
        // The summary contains no timestamps beyond the cert's own dates, so two
        // independent runs must produce byte-identical output.
        let first = stdout(&["--info", &fixture_arg("slh_dsa_root_ca.pem")]);
        let second = stdout(&["--info", &fixture_arg("slh_dsa_root_ca.pem")]);
        assert_eq!(first, second, "--info text output must be deterministic");
    }
}

/// Feature 14: `--chain --info` emits a labelled `Certificate Summary` block per
/// certificate in the bundle (chain/file order, same labels as the chain lint
/// report), followed by the chain lint report — and the JSON envelope folds each
/// cert's `summary` next to its `outcomes`.
///
/// All tests drive the real `mini-x509-lint` binary over the EXISTING 2-cert
/// `testdata/chain_bundle.pem` (leaf `CN=chain-leaf.example.com` first, then
/// `CN=Chain Test Root CA`). No new fixture is added.
///
/// # Feature 15 interaction (chain-aware lints)
///
/// `chain_bundle.pem` is two UNRELATED self-signed certs that do NOT form a
/// chain. Once feature 15 added the chain pass, a `--chain` run over this bundle
/// surfaces a `chain_subject_issuer_dn_match` Error in a `Chain checks:` section
/// (rendered under a `(whole chain)` heading) AND the `--chain` JSON moved to the
/// `{ certificates, chain }` envelope. The per-cert summaries and per-cert
/// outcomes these tests assert on are UNCHANGED; the additive chain section just
/// means the `--chain` exit code is now non-zero and the JSON carries a sibling
/// `chain` key. The assertions below were updated to that reality.
mod chain_info {
    use super::*;

    /// The two chain labels the feature emits, in chain (file) order. They are a
    /// single source of truth (`chain_label`) shared by the summary loop and the
    /// chain lint report, so they must appear identically in BOTH sections.
    const LEAF_LABEL: &str = "Certificate 1 (leaf)";
    const SECOND_LABEL: &str = "Certificate 2";

    /// Counts the number of `Certificate Summary` header lines in `out`.
    fn summary_header_count(out: &str) -> usize {
        out.lines().filter(|l| *l == "Certificate Summary").count()
    }

    #[test]
    fn chain_info_text_snapshot() {
        // Setup / Invoke: `--chain --info` over the 2-cert bundle. The output is
        // deterministic (only the certs' own dates, no wall-clock), and both
        // certs are all-pass, so the appended chain lint report is stable too.
        let out = stdout(&["--chain", "--info", &fixture_arg("chain_bundle.pem")]);

        // Find / Expect: the full stdout locks the exact per-cert layout — each
        // chain label directly above its `Certificate Summary` block, both blocks
        // in chain order, then the chain lint report below.
        insta::assert_snapshot!("chain_bundle_info_text", out);
    }

    #[test]
    fn one_summary_block_per_certificate() {
        // Proves the summary is no longer leaf-only: exactly one
        // `Certificate Summary` header per cert (2 for chain_bundle.pem).
        let out = stdout(&["--chain", "--info", &fixture_arg("chain_bundle.pem")]);
        assert_eq!(
            summary_header_count(&out),
            2,
            "expected one Certificate Summary per cert (2), got:\n{out}"
        );
    }

    #[test]
    fn each_label_sits_directly_above_its_summary_block() {
        // The label line for every cert must be immediately followed by that
        // cert's `Certificate Summary` header, in chain (file) order.
        let out = stdout(&["--chain", "--info", &fixture_arg("chain_bundle.pem")]);

        assert!(
            out.contains(&format!("{LEAF_LABEL}\nCertificate Summary\n")),
            "leaf label must sit directly above its summary, got:\n{out}"
        );
        assert!(
            out.contains(&format!("{SECOND_LABEL}\nCertificate Summary\n")),
            "second label must sit directly above its summary, got:\n{out}"
        );

        // Chain (file) order: the leaf summary precedes the second cert's summary.
        let leaf_at = out
            .find(&format!("{LEAF_LABEL}\nCertificate Summary"))
            .expect("leaf summary block must be present");
        let second_at = out
            .find(&format!("{SECOND_LABEL}\nCertificate Summary"))
            .expect("second summary block must be present");
        assert!(
            leaf_at < second_at,
            "summaries must be in chain order (leaf first), got:\n{out}"
        );
    }

    #[test]
    fn both_subject_dns_appear_in_their_summaries() {
        // Each cert's OWN subject is rendered in its OWN summary block — proving
        // the loop summarizes every cert, not the leaf twice.
        let out = stdout(&["--chain", "--info", &fixture_arg("chain_bundle.pem")]);
        assert!(
            out.contains("Subject:             CN=chain-leaf.example.com"),
            "leaf subject must appear in its summary, got:\n{out}"
        );
        assert!(
            out.contains("Subject:             CN=Chain Test Root CA"),
            "root subject must appear in its summary, got:\n{out}"
        );
    }

    #[test]
    fn chain_lint_report_still_follows_the_summaries() {
        // `--info` is additive: the full chain lint report (per-cert grouped
        // counts + verdicts + trailing `summary:` line) still renders below the
        // summary section, and each label appears AGAIN in the report.
        let out = stdout(&["--chain", "--info", &fixture_arg("chain_bundle.pem")]);

        // Each label appears twice: once heading its summary, once heading its
        // lint report — i.e. summary labels match the chain-report labels.
        assert_eq!(
            out.matches(&format!("{LEAF_LABEL}\n")).count(),
            2,
            "leaf label must head BOTH its summary and its lint report, got:\n{out}"
        );
        assert_eq!(
            out.matches(&format!("{SECOND_LABEL}\n")).count(),
            2,
            "second label must head BOTH its summary and its lint report, got:\n{out}"
        );

        // The lint report markers and the chain summary line are present. (The
        // feature-15 chain section follows the `summary:` line, so the per-cert
        // report's `summary:` trailer is no longer the very last line.) Certificate 2
        // (the CA) is still all-pass, so its `OK: no findings` verdict appears. The
        // combined report trailer is `summary: 1 warn`: under feature-17's broad BR
        // scoping the subscriber leaf, which carries no CertificatePolicies extension,
        // surfaces a single `cabf_br_certificate_policies_present` Warn (no Error).
        assert!(
            out.contains("[rfc5280]") && out.contains("OK: no findings"),
            "the chain lint report must still follow the summaries, got:\n{out}"
        );
        assert!(
            out.contains("summary: 1 warn"),
            "the chain lint report's trailing summary line must be present, got:\n{out}"
        );

        // The lint report sits BELOW both summary blocks.
        let last_summary = out
            .rfind("Certificate Summary")
            .expect("a summary block must exist");
        let report_at = out
            .rfind("summary: 1 warn")
            .expect("the chain report trailer must exist");
        assert!(
            last_summary < report_at,
            "the chain lint report must follow ALL summaries, got:\n{out}"
        );
    }

    #[test]
    fn json_envelope_has_certificates_array_with_summary_and_outcomes() {
        // `--chain --info --format json` emits the option-A envelope:
        // `{ "certificates": [ { certificate, summary, outcomes }, ... ] }`.
        let raw = stdout(&[
            "--chain",
            "--info",
            "--format",
            "json",
            &fixture_arg("chain_bundle.pem"),
        ]);
        let value: serde_json::Value =
            serde_json::from_str(&raw).expect("--chain --info JSON must parse");

        let obj = value
            .as_object()
            .expect("envelope must be a top-level JSON object");
        assert!(
            obj.contains_key("certificates"),
            "envelope must have a certificates key"
        );
        // No single-cert envelope keys leak into the chain envelope.
        assert!(
            !obj.contains_key("summary") && !obj.contains_key("lints"),
            "chain envelope must not carry the single-cert summary/lints keys"
        );

        let certs = value["certificates"]
            .as_array()
            .expect("certificates must be an array");
        assert_eq!(certs.len(), 2, "one entry per cert in the bundle");

        for (idx, entry) in certs.iter().enumerate() {
            assert!(
                entry["certificate"].is_string(),
                "entry {idx} must have a string certificate label"
            );
            assert!(
                entry["summary"].is_object(),
                "entry {idx} summary must be a JSON object"
            );
            assert!(
                entry["outcomes"].is_array(),
                "entry {idx} outcomes must be a JSON array"
            );
        }

        // Labels are the shared chain labels, in chain order.
        assert_eq!(certs[0]["certificate"], LEAF_LABEL);
        assert_eq!(certs[1]["certificate"], SECOND_LABEL);
    }

    #[test]
    fn json_outcomes_match_non_info_chain_verbatim() {
        // The per-cert `outcomes` arrays must equal the non-`--info` `--chain`
        // JSON for the same input — folding in `summary` reshapes nothing.
        let bare = stdout(&[
            "--chain",
            "--format",
            "json",
            &fixture_arg("chain_bundle.pem"),
        ]);
        let bare_value: serde_json::Value =
            serde_json::from_str(&bare).expect("bare --chain JSON must parse");

        let enveloped = stdout(&[
            "--chain",
            "--info",
            "--format",
            "json",
            &fixture_arg("chain_bundle.pem"),
        ]);
        let env_value: serde_json::Value =
            serde_json::from_str(&enveloped).expect("--chain --info JSON must parse");

        // Feature 15: a broken/unrelated bundle moves the non-info `--chain` JSON
        // from a bare array to the `{ certificates, chain }` envelope (the chain
        // pass produced reports). The per-cert outcomes still live under
        // `certificates`, so compare those.
        let bare_arr = bare_value["certificates"]
            .as_array()
            .expect("non-info --chain JSON must carry a certificates array");
        let env_arr = env_value["certificates"]
            .as_array()
            .expect("certificates must be an array");
        assert_eq!(bare_arr.len(), env_arr.len(), "same cert count");

        for (idx, (bare_entry, env_entry)) in bare_arr.iter().zip(env_arr.iter()).enumerate() {
            // The label and the entire outcome shape are preserved verbatim.
            assert_eq!(
                bare_entry["certificate"], env_entry["certificate"],
                "entry {idx} label must be identical"
            );
            assert_eq!(
                bare_entry["outcomes"], env_entry["outcomes"],
                "entry {idx} outcomes must match the non-info chain JSON verbatim"
            );
        }

        // Spot-check the feature-02 per-outcome shape on the first outcome.
        let first = env_arr[0]["outcomes"]
            .as_array()
            .and_then(|a| a.first())
            .expect("first cert must have at least one outcome");
        for key in ["lint_id", "source", "applicability", "findings"] {
            assert!(
                first.get(key).is_some(),
                "each outcome must carry the {key:?} key (feature-02 shape)"
            );
        }
    }

    #[test]
    fn json_per_cert_summary_matches_single_cert_summary_shape() {
        // Each cert's `summary` is the SAME object the single-cert
        // `build_summary_json` emits: same keys/nesting as the single-cert
        // `--info --format json` summary. Compare the key sets.
        let single = stdout(&["--info", "--format", "json", &fixture_arg("good.pem")]);
        let single_value: serde_json::Value =
            serde_json::from_str(&single).expect("single-cert --info JSON must parse");
        let single_keys: Vec<&String> = single_value["summary"]
            .as_object()
            .expect("single-cert summary must be an object")
            .keys()
            .collect();

        let chain = stdout(&[
            "--chain",
            "--info",
            "--format",
            "json",
            &fixture_arg("chain_bundle.pem"),
        ]);
        let chain_value: serde_json::Value =
            serde_json::from_str(&chain).expect("--chain --info JSON must parse");

        for entry in chain_value["certificates"]
            .as_array()
            .expect("certificates array")
        {
            let entry_keys: Vec<&String> = entry["summary"]
                .as_object()
                .expect("per-cert summary must be an object")
                .keys()
                .collect();
            assert_eq!(
                single_keys, entry_keys,
                "per-cert summary must have the same shape as the single-cert summary"
            );
        }
    }

    #[test]
    fn json_summaries_snapshot() {
        // Snapshot only the per-cert summary objects (label -> summary), so the
        // JSON summary shape is locked independent of the binary's whitespace and
        // of the large (separately guarded) outcomes arrays.
        let raw = stdout(&[
            "--chain",
            "--info",
            "--format",
            "json",
            &fixture_arg("chain_bundle.pem"),
        ]);
        let value: serde_json::Value =
            serde_json::from_str(&raw).expect("--chain --info JSON must parse");
        let summaries: Vec<serde_json::Value> = value["certificates"]
            .as_array()
            .expect("certificates array")
            .iter()
            .map(
                |e| serde_json::json!({ "certificate": e["certificate"], "summary": e["summary"] }),
            )
            .collect();
        insta::assert_json_snapshot!("chain_bundle_info_json_summaries", summaries);
    }

    #[test]
    fn single_cert_info_is_unchanged_by_this_feature() {
        // Guard: single-cert `--info` (no `--chain`) still emits exactly ONE
        // `Certificate Summary` and the `{ summary, lints }` envelope — never the
        // chain `certificates` key.
        let text = stdout(&["--info", &fixture_arg("good.pem")]);
        assert_eq!(
            summary_header_count(&text),
            1,
            "single-cert --info must emit exactly one summary block, got:\n{text}"
        );
        assert!(
            text.starts_with("Certificate Summary\n"),
            "single-cert --info must lead with the summary block (no chain label)"
        );

        let raw = stdout(&["--info", "--format", "json", &fixture_arg("good.pem")]);
        let value: serde_json::Value =
            serde_json::from_str(&raw).expect("single-cert --info JSON must parse");
        let obj = value
            .as_object()
            .expect("single-cert --info JSON must be an object");
        assert!(
            obj.contains_key("summary") && obj.contains_key("lints"),
            "single-cert envelope must keep the summary + lints keys"
        );
        assert!(
            !obj.contains_key("certificates"),
            "single-cert envelope must NOT carry the chain certificates key"
        );
    }

    #[test]
    fn chain_without_info_emits_no_summary_block() {
        // Guard: `--chain` WITHOUT `--info` must not print any summary block; the
        // chain lint report shape is intact. (The golden `chain_bundle_text`
        // snapshot guards the exact bytes; this just confirms the invariant from
        // the new tests' vantage point.)
        let out = stdout(&["--chain", &fixture_arg("chain_bundle.pem")]);
        assert_eq!(
            summary_header_count(&out),
            0,
            "default --chain output must not print any summary block, got:\n{out}"
        );
        assert!(
            out.starts_with("Certificate 1 (leaf)\n[rfc5280]"),
            "default --chain report must lead straight into the lint groups, got:\n{out}"
        );
        // JSON: NOT the `--info` envelope. Feature 15 wraps a chain-pass run in the
        // `{ certificates, chain }` envelope (this bundle is two unrelated certs →
        // a chain-level structural finding), but it must still carry NO per-cert
        // `summary` key (that is the `--info`-only addition).
        let raw = stdout(&[
            "--chain",
            "--format",
            "json",
            &fixture_arg("chain_bundle.pem"),
        ]);
        let value: serde_json::Value = serde_json::from_str(&raw).expect("--chain JSON must parse");
        let certs = value["certificates"]
            .as_array()
            .expect("default --chain JSON must carry a certificates array");
        assert!(
            certs.iter().all(|c| c.get("summary").is_none()),
            "default --chain JSON (no --info) must not fold in per-cert summaries"
        );
    }

    #[test]
    fn info_does_not_change_the_chain_exit_code() {
        // `--info` is additive over `--chain`: the exit code is identical with and
        // without it. (Feature 15: chain_bundle.pem is two unrelated self-signed
        // certs, so the chain pass surfaces a structural Error → the default
        // --fail-on error exits 1 either way. The invariant under test is that
        // --info does not CHANGE the exit code, not its specific value.)
        let without = run(&["--chain", &fixture_arg("chain_bundle.pem")]);
        let with = run(&["--chain", "--info", &fixture_arg("chain_bundle.pem")]);
        assert_eq!(
            without.status.code(),
            with.status.code(),
            "--info must not change the --chain exit code"
        );
        assert_eq!(
            without.status.code(),
            Some(1),
            "the unrelated-cert bundle surfaces a chain Error → exit 1 with or without --info"
        );
    }

    #[test]
    fn chain_info_text_is_byte_identical_across_runs() {
        // No wall-clock content beyond the certs' own dates, so two independent
        // runs are byte-identical.
        let first = stdout(&["--chain", "--info", &fixture_arg("chain_bundle.pem")]);
        let second = stdout(&["--chain", "--info", &fixture_arg("chain_bundle.pem")]);
        assert_eq!(
            first, second,
            "--chain --info text output must be deterministic"
        );
    }

    #[test]
    fn absent_extensions_render_per_cert_markers_without_dropping_certs() {
        // Graceful-degradation contract at the per-cert level, exercised through
        // the binary (the renderer/loop is not a public API reachable from an
        // integration test, so we drive the real `--chain --info` path over the
        // existing bundle whose two certs each have a DIFFERENT absent extension):
        //   - the LEAF has NO KeyUsage     -> `Key Usage:           (not present)`
        //   - the ROOT (non-leaf) has NO SAN -> `Subject Alt Name:    (not present)`
        // Both `(not present)` ABSENT markers must render in the SAME run, on
        // DIFFERENT certs (not just the leaf), AND the full chain lint report must
        // still follow — proving the loop never short-circuits / drops a later
        // cert's summary when an accessor degrades. No PEM fixture is added.
        let out = stdout(&["--chain", "--info", &fixture_arg("chain_bundle.pem")]);

        // The leaf block carries the absent-KeyUsage marker.
        assert!(
            out.contains("Key Usage:           (not present)"),
            "leaf's absent KeyUsage must render the marker, got:\n{out}"
        );
        // The non-leaf (root) block carries the absent-SAN marker.
        assert!(
            out.contains("Subject Alt Name:    (not present)"),
            "root's absent SAN must render the marker, got:\n{out}"
        );
        // The marker on the non-leaf cert proves degradation is handled past the
        // leaf: the root summary (with its absent SAN) appears AFTER the leaf one.
        let ku_absent_at = out
            .find("Key Usage:           (not present)")
            .expect("leaf KeyUsage marker present");
        let san_absent_at = out
            .find("Subject Alt Name:    (not present)")
            .expect("root SAN marker present");
        assert!(
            ku_absent_at < san_absent_at,
            "the root's (later) absent-SAN marker must render after the leaf block, got:\n{out}"
        );
        // And the full chain lint report still renders below both summaries.
        // (Feature 15 appends a `Chain checks:` section after `summary:`, so the
        // per-cert report's trailer is present but no longer the final line. The
        // trailer reads `summary: 1 warn` under feature-17 broad BR scoping: the
        // subscriber leaf surfaces a single `cabf_br_certificate_policies_present`
        // Warn for its absent CertificatePolicies extension.)
        assert!(
            out.contains("summary: 1 warn"),
            "the full chain lint report must still render after degraded blocks, got:\n{out}"
        );
        // Both certs were summarized: exactly two summary blocks.
        assert_eq!(
            summary_header_count(&out),
            2,
            "every cert must still be summarized despite absent extensions, got:\n{out}"
        );
    }
}
