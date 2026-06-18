//! End-to-end CLI tests for the `mini-x509-lint` binary.
//!
//! These run the *actual* compiled binary (located via the Cargo-provided
//! `CARGO_BIN_EXE_mini-x509-lint` env var) with `std::process::Command` against
//! the committed `testdata/` fixtures, then assert on stdout, stderr, and the
//! process exit code. This proves the wiring the in-crate unit tests cannot: the
//! flag plumbing, the registry run, the formatters, and the exit behaviour.
//!
//! ## Determinism
//!
//! The `hygiene_not_expired` finding embeds the *current* Unix time (`now is
//! <unix time>`), which changes every run. Tests therefore assert on stable
//! prefixes / structural facts (a `warn` line exists, a group header is present,
//! the JSON keys are correct) and never on the volatile `now is ...` value.
//!
//! The two fully-stable invocations are exercised:
//! - `--source rfc5280` on `expired.pem` -> the rfc5280 group renders with a
//!   passed/not-applicable summary and `OK: no findings` (no time-dependent
//!   hygiene lint runs, so nothing volatile surfaces).
//! - `--min-severity error` on `good.pem` -> `OK: no findings` (the good cert has
//!   no error-or-above findings).

use std::path::PathBuf;
use std::process::{Command, Output};

/// Absolute path to the compiled `mini-x509-lint` binary under test.
const BIN: &str = env!("CARGO_BIN_EXE_mini-x509-lint");

/// The `notAfter` of `testdata/expired.pem` in Unix seconds (2024-06-01); the
/// stable, time-independent part of the expiry message.
///
/// Feature 05 reshaped `expired.pem` to a BR-compliant-but-past leaf
/// (`2024-01-01 -> 2024-06-01`), so `notAfter` is `1_717_200_000` (2024-06-01),
/// not the old `1_293_840_000` (2011-01-01).
const EXPIRED_NOT_AFTER: i64 = 1_717_200_000;

/// Resolves a fixture path under the workspace-root `testdata/` directory.
///
/// `CARGO_MANIFEST_DIR` for this test points at `crates/cli`; `../../testdata`
/// reaches the workspace root.
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

/// Decodes captured stdout as UTF-8 (the formatters only emit UTF-8).
fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout must be UTF-8")
}

mod text_output {
    use super::*;

    /// Default (text) run over the expired fixture groups under the hygiene
    /// header and shows the expired finding as a `warn` line for the
    /// `hygiene_not_expired` lint. The full message is volatile, so only the
    /// structural facts + stable prefix are asserted.
    #[test]
    fn groups_expired_finding_under_hygiene_header() {
        // Setup + Invoke: default format is text, default sources are all.
        let output = run(&[fixture("expired.pem").to_str().unwrap()]);

        // Find
        let stdout = stdout_of(&output);

        // Expect: success, hygiene group header, a warn line for the lint with the
        // stable message prefix, and the per-group summary footer.
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );
        assert!(
            stdout.contains("[hygiene]"),
            "missing hygiene header:\n{stdout}"
        );
        let prefix = format!(
            "  warn [hygiene_not_expired] certificate expired: notAfter is {EXPIRED_NOT_AFTER}"
        );
        assert!(
            stdout.contains(&prefix),
            "missing stable warn line prefix {prefix:?}:\n{stdout}"
        );
        assert!(
            stdout.contains("not applicable)"),
            "missing per-group summary footer:\n{stdout}"
        );
        assert!(!stdout.contains("OK: no findings"));
    }

    /// `--source rfc5280` on the expired fixture is fully stable: the rfc5280
    /// lints are all either applicable-and-passing or not-applicable (no
    /// time-dependent hygiene lint runs), so the source group renders with a
    /// passed/not-applicable summary and zero findings surface.
    #[test]
    fn source_rfc5280_on_expired_reports_no_findings() {
        // Setup + Invoke
        let output = run(&[
            "--source",
            "rfc5280",
            fixture("expired.pem").to_str().unwrap(),
        ]);

        // Find
        let stdout = stdout_of(&output);

        // Expect: clean exit, the rfc5280 group header and its passed/not-applicable
        // summary, and the explicit no-findings line. (Counts asserted via stable
        // substrings rather than exact equality so the test tracks the renderer's
        // by-design non-empty-group output.)
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );
        assert!(
            stdout.contains("[rfc5280]"),
            "missing rfc5280 group header:\n{stdout}"
        );
        assert!(
            stdout.contains("(7 passed, 9 not applicable)"),
            "missing passed/not-applicable summary:\n{stdout}"
        );
        assert!(
            stdout.contains("OK: no findings"),
            "missing no-findings line:\n{stdout}"
        );
    }

    /// `--min-severity error` on the good fixture is fully stable: the good cert
    /// produces no error-or-above findings, so the no-findings line prints.
    #[test]
    fn min_severity_error_on_good_reports_no_findings() {
        // Setup + Invoke
        let output = run(&[
            "--min-severity",
            "error",
            fixture("good.pem").to_str().unwrap(),
        ]);

        // Find
        let stdout = stdout_of(&output);

        // Expect
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );
        assert!(stdout.contains("OK: no findings"));
    }

    /// `--min-severity error` on the *expired* fixture filters out the lone `warn`
    /// finding, leaving the no-findings line (proves reporting-boundary filtering).
    #[test]
    fn min_severity_error_filters_the_warn_finding_on_expired() {
        // Setup + Invoke
        let output = run(&[
            "--min-severity",
            "error",
            fixture("expired.pem").to_str().unwrap(),
        ]);

        // Find
        let stdout = stdout_of(&output);

        // Expect: the warn finding is hidden; the no-findings line surfaces.
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );
        assert!(
            !stdout.contains("hygiene_not_expired"),
            "warn finding should be filtered:\n{stdout}"
        );
        assert!(stdout.contains("OK: no findings"));
    }
}

mod json_output {
    use super::*;

    /// `--format json` over the expired fixture emits the nested wire shape: one
    /// object per outcome carrying `lint_id`, `source`, `applicability`, and its
    /// own `findings` array, with snake_case tokens. Asserted via the
    /// pretty-printed key strings (no JSON parser / extra dev-dependency needed).
    #[test]
    fn emits_nested_shape_with_snake_case_tokens() {
        // Setup + Invoke
        let output = run(&["--format", "json", fixture("expired.pem").to_str().unwrap()]);

        // Find
        let stdout = stdout_of(&output);

        // Expect: success and the documented pretty-printed keys/values. `to_string_pretty`
        // renders object keys as `"key": value`, so these substrings are exact.
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );
        assert!(
            stdout.contains("\"lint_id\": \"hygiene_not_expired\""),
            "missing lint_id key:\n{stdout}"
        );
        assert!(
            stdout.contains("\"source\": \"hygiene\""),
            "missing snake_case source token:\n{stdout}"
        );
        assert!(
            stdout.contains("\"applicability\": \"applies\""),
            "missing applicability key:\n{stdout}"
        );
        assert!(
            stdout.contains("\"findings\":"),
            "missing nested findings array:\n{stdout}"
        );
        assert!(
            stdout.contains("\"severity\": \"warn\""),
            "missing snake_case severity token:\n{stdout}"
        );
        // Stable prefix of the (otherwise volatile) message.
        assert!(
            stdout.contains(&format!(
                "certificate expired: notAfter is {EXPIRED_NOT_AFTER}"
            )),
            "missing stable message prefix:\n{stdout}"
        );
        // The pretty output is a top-level array and the binary appends a
        // trailing newline after the closing `]`.
        assert!(
            stdout.ends_with("]\n"),
            "JSON output must end with `]` + newline"
        );
    }

    /// Parser-backed proof of the nested wire shape. `serde_json` is already a
    /// (non-dev) dependency of the `cli` crate, so it is available to this
    /// integration target without a manifest change. This parses the real binary
    /// output into a `serde_json::Value` and inspects the structure directly,
    /// matching the test-plan's "parse with `serde_json::Value` and inspect
    /// `lint_id`/`source`/`findings`" requirement.
    #[test]
    fn parsed_json_has_nested_outcome_shape() {
        // Setup + Invoke
        let output = run(&["--format", "json", fixture("expired.pem").to_str().unwrap()]);
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );

        // Find: parse the entire document; it must be valid JSON.
        let stdout = stdout_of(&output);
        let value: serde_json::Value =
            serde_json::from_str(&stdout).expect("CLI JSON output must be valid JSON");

        // Expect: a top-level array of outcome objects.
        let outcomes = value
            .as_array()
            .expect("top-level JSON must be an array of outcomes");
        assert!(
            !outcomes.is_empty(),
            "the expired fixture must yield at least one outcome"
        );

        // Find the hygiene_not_expired outcome and verify the nested shape.
        let outcome = outcomes
            .iter()
            .find(|o| o["lint_id"] == serde_json::json!("hygiene_not_expired"))
            .expect("hygiene_not_expired outcome must be present");

        // Each outcome carries lint_id, source, applicability, and its own
        // findings array (the nested, not flat, representation), with snake_case
        // tokens.
        assert_eq!(outcome["source"], serde_json::json!("hygiene"));
        assert_eq!(outcome["applicability"], serde_json::json!("applies"));

        let findings = outcome["findings"]
            .as_array()
            .expect("findings must be a JSON array nested inside the outcome");
        assert_eq!(findings.len(), 1, "expired fixture yields one finding");

        let finding = &findings[0];
        assert_eq!(finding["severity"], serde_json::json!("warn"));
        let message = finding["message"]
            .as_str()
            .expect("finding message must be a string");
        assert!(
            message.starts_with(&format!(
                "certificate expired: notAfter is {EXPIRED_NOT_AFTER}"
            )),
            "unexpected finding message: {message}"
        );
    }

    /// `serde_json::Value`-backed proof that reporting-boundary filtering empties
    /// the nested `findings` array while keeping the outcome object intact.
    #[test]
    fn parsed_json_keeps_outcome_with_empty_findings_when_filtered() {
        // Setup + Invoke: filter out the lone warn finding.
        let output = run(&[
            "--format",
            "json",
            "--min-severity",
            "error",
            fixture("expired.pem").to_str().unwrap(),
        ]);
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );

        // Find
        let stdout = stdout_of(&output);
        let value: serde_json::Value =
            serde_json::from_str(&stdout).expect("CLI JSON output must be valid JSON");
        let outcomes = value.as_array().expect("top-level JSON must be an array");
        let outcome = outcomes
            .iter()
            .find(|o| o["lint_id"] == serde_json::json!("hygiene_not_expired"))
            .expect("outcome must remain present after filtering");

        // Expect: the outcome stays, but its findings array is now empty (raw
        // outcomes are filtered only at the reporting boundary, not dropped).
        let findings = outcome["findings"]
            .as_array()
            .expect("findings must still be an array");
        assert!(
            findings.is_empty(),
            "warn finding should be filtered out below error threshold"
        );
    }

    /// JSON output is structurally valid: balanced braces/brackets and an outer
    /// array wrapper. This is a parser-free integrity check that avoids adding a
    /// `serde_json` dev-dependency to the `cli` test target.
    #[test]
    fn output_is_well_formed_json_array() {
        // Setup + Invoke
        let output = run(&["--format", "json", fixture("good.pem").to_str().unwrap()]);

        // Find
        let stdout = stdout_of(&output);
        let trimmed = stdout.trim();

        // Expect: an array at the top level with balanced delimiters.
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );
        assert!(
            trimmed.starts_with('['),
            "JSON must be a top-level array:\n{stdout}"
        );
        assert!(
            trimmed.ends_with(']'),
            "JSON must close its array:\n{stdout}"
        );
        let opens = stdout.matches('{').count();
        let closes = stdout.matches('}').count();
        assert_eq!(opens, closes, "unbalanced braces in JSON:\n{stdout}");
        let open_brackets = stdout.matches('[').count();
        let close_brackets = stdout.matches(']').count();
        assert_eq!(
            open_brackets, close_brackets,
            "unbalanced brackets in JSON:\n{stdout}"
        );
    }

    /// `--format json --min-severity error` on the expired fixture keeps the
    /// outcome object but drops the lone `warn` finding from its `findings` array,
    /// proving reporting-boundary filtering in the JSON renderer.
    #[test]
    fn min_severity_error_empties_findings_but_keeps_outcome() {
        // Setup + Invoke
        let output = run(&[
            "--format",
            "json",
            "--min-severity",
            "error",
            fixture("expired.pem").to_str().unwrap(),
        ]);

        // Find
        let stdout = stdout_of(&output);

        // Expect: the outcome still appears, but its findings array is empty and no
        // warn severity survives.
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );
        assert!(stdout.contains("\"lint_id\": \"hygiene_not_expired\""));
        assert!(
            stdout.contains("\"findings\": []"),
            "findings should be empty:\n{stdout}"
        );
        assert!(
            !stdout.contains("\"severity\": \"warn\""),
            "warn finding should be filtered:\n{stdout}"
        );
    }
}

mod code_signing_output {
    use super::*;

    /// The eight `cabf_cs` lint ids the code-signing group must list.
    const CS_LINT_IDS: [&str; 8] = [
        "cabf_cs_eku_required",
        "cabf_cs_key_usage_required",
        "cabf_cs_rsa_key_size",
        "cabf_cs_ecdsa_curve_params",
        "cabf_cs_validity_period_longer_than_39_months",
        "cabf_cs_validity_period_longer_than_460_days",
        "cabf_cs_authority_information_access",
        "cabf_cs_crl_distribution_points",
    ];

    /// `--purpose code-signing --verbose` on the clean code-signing leaf renders
    /// the `[cabf_cs]` group with all eight CS lints (passed/applicable), the
    /// `purpose: code-signing` header, and NO `[cabf_br]` group (the code-signing
    /// purpose runs Rfc5280 + Hygiene + CabfCs, not CabfBr — so the broad
    /// serverAuth false positive cannot surface). Exits 0 with no findings.
    #[test]
    fn purpose_code_signing_renders_cabf_cs_group_and_header() {
        // Setup + Invoke.
        let output = run(&[
            "--purpose",
            "code-signing",
            "--verbose",
            fixture("cabf_cs_good.pem").to_str().unwrap(),
        ]);

        // Find.
        let stdout = stdout_of(&output);

        // Expect: clean exit, the verbose purpose header, the cabf_cs group, all
        // eight CS lints listed and passing, no cabf_br group, no findings.
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );
        assert!(
            stdout.contains("purpose: code-signing"),
            "verbose header must render the code-signing purpose:\n{stdout}"
        );
        assert!(
            stdout.contains("[cabf_cs]"),
            "missing cabf_cs group header:\n{stdout}"
        );
        for id in CS_LINT_IDS {
            assert!(
                stdout.contains(&format!("pass  {id}")),
                "CS lint {id} should be listed as passed:\n{stdout}"
            );
        }
        assert!(
            !stdout.contains("[cabf_br]"),
            "the code-signing purpose must not run the cabf_br group:\n{stdout}"
        );
        assert!(
            stdout.contains("OK: no findings"),
            "the clean CS leaf must report no findings:\n{stdout}"
        );
    }

    /// `--source cabf_cs` on the clean code-signing leaf restricts the report to
    /// the eight CS lints (the only group present), all passing. Proves the
    /// `--source cabf_cs` token plumbing end-to-end.
    #[test]
    fn source_cabf_cs_runs_only_the_cs_group() {
        // Setup + Invoke.
        let output = run(&[
            "--source",
            "cabf_cs",
            "--verbose",
            fixture("cabf_cs_good.pem").to_str().unwrap(),
        ]);

        // Find.
        let stdout = stdout_of(&output);

        // Expect: success, the cabf_cs group present with all eight lints, and no
        // other source group rendered.
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );
        assert!(
            stdout.contains("[cabf_cs]"),
            "missing cabf_cs group header:\n{stdout}"
        );
        for id in CS_LINT_IDS {
            assert!(
                stdout.contains(&format!("pass  {id}")),
                "CS lint {id} should be listed as passed under --source cabf_cs:\n{stdout}"
            );
        }
        assert!(
            !stdout.contains("[rfc5280]"),
            "--source cabf_cs must exclude rfc5280:\n{stdout}"
        );
        assert!(
            !stdout.contains("[hygiene]"),
            "--source cabf_cs must exclude hygiene:\n{stdout}"
        );
        assert!(
            !stdout.contains("[cabf_br]"),
            "--source cabf_cs must exclude cabf_br:\n{stdout}"
        );
    }

    /// JSON proof: `--source cabf_cs --format json` emits exactly eight outcomes,
    /// all carrying the `cabf_cs` source token.
    #[test]
    fn source_cabf_cs_json_emits_eight_cabf_cs_outcomes() {
        // Setup + Invoke.
        let output = run(&[
            "--source",
            "cabf_cs",
            "--format",
            "json",
            fixture("cabf_cs_good.pem").to_str().unwrap(),
        ]);
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );

        // Find: parse the document.
        let stdout = stdout_of(&output);
        let value: serde_json::Value =
            serde_json::from_str(&stdout).expect("CLI JSON output must be valid JSON");
        let outcomes = value.as_array().expect("top-level JSON must be an array");

        // Expect: exactly eight outcomes, all `cabf_cs`.
        assert_eq!(
            outcomes.len(),
            8,
            "--source cabf_cs must yield exactly 8 outcomes"
        );
        for o in outcomes {
            assert_eq!(
                o["source"],
                serde_json::json!("cabf_cs"),
                "every outcome must carry the cabf_cs source token"
            );
        }
    }
}

mod pqc_output {
    use super::*;

    /// The five `pqc` lint ids the post-quantum group must list (feature 13).
    const PQC_LINT_IDS: [&str; 5] = [
        "pqc_algorithm_known",
        "pqc_spki_parameters_absent",
        "pqc_signature_parameters_absent",
        "pqc_public_key_length",
        "pqc_key_usage_consistency",
    ];

    /// `--source pqc --verbose` on the clean ML-DSA leaf renders the `[pqc]`
    /// group with all five PQC lints applying and passing, and no other source
    /// group. Proves the `--source pqc` token plumbing end-to-end on a PQC cert.
    #[test]
    fn source_pqc_on_mldsa_good_runs_only_the_pqc_group() {
        // Setup + Invoke.
        let output = run(&[
            "--source",
            "pqc",
            "--verbose",
            fixture("pqc_mldsa_good.pem").to_str().unwrap(),
        ]);

        // Find.
        let stdout = stdout_of(&output);

        // Expect: clean exit, the pqc group present with all five lints passing,
        // and no other source group rendered.
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );
        assert!(
            stdout.contains("[pqc]"),
            "missing pqc group header:\n{stdout}"
        );
        for id in PQC_LINT_IDS {
            assert!(
                stdout.contains(&format!("pass  {id}")),
                "pqc lint {id} should be listed as passed:\n{stdout}"
            );
        }
        assert!(
            !stdout.contains("[rfc5280]"),
            "--source pqc must exclude rfc5280:\n{stdout}"
        );
        assert!(
            !stdout.contains("[hygiene]"),
            "--source pqc must exclude hygiene:\n{stdout}"
        );
        assert!(
            stdout.contains("OK: no findings"),
            "the clean ML-DSA leaf must report no findings:\n{stdout}"
        );
    }

    /// A default (all-source) run on the clean ML-DSA leaf renders the `[pqc]`
    /// group immediately after `[rfc5280]` (the documented SOURCE_ORDER
    /// position), with the five PQC lints all passing.
    #[test]
    fn default_run_on_mldsa_good_renders_pqc_group_after_rfc5280() {
        // Setup + Invoke.
        let output = run(&[fixture("pqc_mldsa_good.pem").to_str().unwrap()]);

        // Find.
        let stdout = stdout_of(&output);

        // Expect: success, both group headers present, [pqc] after [rfc5280].
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );
        let rfc_pos = stdout
            .find("[rfc5280]")
            .unwrap_or_else(|| panic!("missing [rfc5280] header:\n{stdout}"));
        let pqc_pos = stdout
            .find("[pqc]")
            .unwrap_or_else(|| panic!("missing [pqc] header:\n{stdout}"));
        assert!(
            rfc_pos < pqc_pos,
            "[pqc] must render after [rfc5280] (SOURCE_ORDER):\n{stdout}"
        );
        assert!(
            stdout.contains("OK: no findings"),
            "clean ML-DSA leaf must report no findings:\n{stdout}"
        );
    }

    /// `--source pqc` on the bad-KU ML-DSA leaf surfaces the
    /// `pqc_key_usage_consistency` error and exits non-zero (a finding at Error).
    #[test]
    fn source_pqc_on_bad_key_usage_reports_the_error() {
        // Setup + Invoke.
        let output = run(&[
            "--source",
            "pqc",
            fixture("pqc_bad_key_usage.pem").to_str().unwrap(),
        ]);

        // Find.
        let stdout = stdout_of(&output);

        // Expect: the keyEncipherment error from pqc_key_usage_consistency.
        assert!(
            stdout.contains("pqc_key_usage_consistency"),
            "missing pqc_key_usage_consistency finding:\n{stdout}"
        );
        assert!(
            stdout.contains("keyEncipherment"),
            "finding should name the offending KU bit:\n{stdout}"
        );
        assert!(
            stdout.contains("error"),
            "finding should render at error severity:\n{stdout}"
        );
    }

    /// `--source pqc --verbose` on a NON-PQC cert (`good.pem`) still renders the
    /// `[pqc]` group (the universal source is filtered in), but every PQC lint is
    /// listed as `n/a` — the per-lint SPKI gate self-excludes on a classical key.
    /// Forcing the source does NOT bypass the gate (mirrors `--source cabf_cs`).
    #[test]
    fn source_pqc_on_non_pqc_cert_lists_all_lints_not_applicable() {
        // Setup + Invoke.
        let output = run(&[
            "--source",
            "pqc",
            "--verbose",
            fixture("good.pem").to_str().unwrap(),
        ]);

        // Find.
        let stdout = stdout_of(&output);

        // Expect: success, the pqc group present, every PQC lint listed as n/a.
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );
        assert!(
            stdout.contains("[pqc]"),
            "the universal pqc source must still render its group:\n{stdout}"
        );
        for id in PQC_LINT_IDS {
            assert!(
                stdout.contains(&format!("n/a   {id}")),
                "pqc lint {id} must be n/a on a non-PQC cert:\n{stdout}"
            );
        }
        assert!(
            stdout.contains("OK: no findings"),
            "no PQC finding fires on a non-PQC cert:\n{stdout}"
        );
    }

    /// JSON proof: `--source pqc --format json` on the ML-DSA leaf emits exactly
    /// five outcomes, all carrying the `pqc` source token and all `applies`.
    #[test]
    fn source_pqc_json_emits_five_applying_pqc_outcomes() {
        // Setup + Invoke.
        let output = run(&[
            "--source",
            "pqc",
            "--format",
            "json",
            fixture("pqc_mldsa_good.pem").to_str().unwrap(),
        ]);
        assert!(
            output.status.success(),
            "expected exit 0, stderr: {:?}",
            output.stderr
        );

        // Find: parse the document.
        let stdout = stdout_of(&output);
        let value: serde_json::Value =
            serde_json::from_str(&stdout).expect("CLI JSON output must be valid JSON");
        let outcomes = value.as_array().expect("top-level JSON must be an array");

        // Expect: exactly five outcomes, all `pqc` and `applies`.
        assert_eq!(
            outcomes.len(),
            5,
            "--source pqc must yield exactly 5 outcomes"
        );
        for o in outcomes {
            assert_eq!(
                o["source"],
                serde_json::json!("pqc"),
                "every outcome must carry the pqc source token"
            );
            assert_eq!(
                o["applicability"],
                serde_json::json!("applies"),
                "every pqc lint must Apply on a PQC leaf"
            );
        }
    }
}

mod error_behaviour {
    use super::*;

    /// A missing input file exits non-zero (the file cannot be read).
    #[test]
    fn missing_file_exits_non_zero() {
        // Setup + Invoke: a path that does not exist.
        let output = run(&["/no/such/certificate/file.pem"]);

        // Expect: non-zero exit, and nothing printed to stdout.
        assert!(
            !output.status.success(),
            "expected non-zero exit for a missing file"
        );
        assert!(
            stdout_of(&output).is_empty(),
            "no report should be printed when the file is missing"
        );
    }

    /// An unknown `--source` token is rejected with a non-zero exit (clap/engine
    /// validation), never a panic.
    #[test]
    fn unknown_source_token_exits_non_zero() {
        // Setup + Invoke
        let output = run(&["--source", "bogus", fixture("good.pem").to_str().unwrap()]);

        // Expect
        assert!(
            !output.status.success(),
            "expected non-zero exit for an unknown --source token"
        );
    }

    /// An unknown `--format` value is rejected by clap with a non-zero exit.
    #[test]
    fn unknown_format_value_exits_non_zero() {
        // Setup + Invoke
        let output = run(&["--format", "yaml", fixture("good.pem").to_str().unwrap()]);

        // Expect
        assert!(
            !output.status.success(),
            "expected non-zero exit for an unknown --format value"
        );
    }
}
