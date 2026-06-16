//! Formatters that turn the engine's `Vec<LintOutcome>` into displayable output.
//!
//! Two formats are offered:
//!
//! - [`render_text`] — a human-readable report grouped by [`RuleSource`].
//! - [`render_json`] — the nested JSON shape (one object per outcome).
//!
//! Both apply `--min-severity` at the **reporting boundary**: findings below the
//! threshold are hidden for display only; the raw outcomes the engine produced
//! are never mutated. Ordering is deterministic so downstream golden tests are
//! viable.

use anyhow::{Context, Result};
use linter::{Applicability, Finding, LintOutcome, RuleSource, Severity};

/// The fixed group order used by the text formatter.
///
/// Listing the sources explicitly (rather than deriving order from the input)
/// keeps text output stable regardless of registry ordering.
const SOURCE_ORDER: [RuleSource; 3] =
    [RuleSource::Rfc5280, RuleSource::CabfBr, RuleSource::Hygiene];

/// The on-wire / display label for a [`RuleSource`], matching the `--source`
/// vocabulary and the serde `snake_case` rendering.
fn source_label(source: RuleSource) -> &'static str {
    match source {
        RuleSource::Rfc5280 => "rfc5280",
        RuleSource::CabfBr => "cabf_br",
        RuleSource::Hygiene => "hygiene",
    }
}

/// The lowercase label for a [`Severity`], matching the serde rendering.
fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Notice => "notice",
        Severity::Warn => "warn",
        Severity::Error => "error",
        Severity::Fatal => "fatal",
    }
}

/// Returns the findings of `outcome` that meet or exceed `min`.
fn findings_at_or_above(outcome: &LintOutcome, min: Severity) -> Vec<&Finding> {
    outcome
        .findings
        .iter()
        .filter(|f| f.severity >= min)
        .collect()
}

/// Renders `outcomes` as a human-readable report grouped by [`RuleSource`].
///
/// Findings below `min` are hidden. Within each source group, applicable lints
/// with surviving findings are listed (one line per finding). Lints that passed
/// (applicable, no surviving findings) and lints that did not apply are
/// summarized compactly as counts rather than printed verbosely. A clear "no
/// findings" line is emitted when nothing surfaced.
pub fn render_text(outcomes: &[LintOutcome], min: Severity) -> String {
    let mut out = String::new();
    let mut total_findings = 0usize;

    for &source in &SOURCE_ORDER {
        let group: Vec<&LintOutcome> = outcomes.iter().filter(|o| o.source == source).collect();
        if group.is_empty() {
            continue;
        }

        let mut lines: Vec<String> = Vec::new();
        let mut passed = 0usize;
        let mut not_applicable = 0usize;

        for outcome in &group {
            match outcome.applicability {
                Applicability::NotApplicable => {
                    not_applicable += 1;
                    continue;
                }
                Applicability::Applies => {}
            }

            let kept = findings_at_or_above(outcome, min);
            if kept.is_empty() {
                passed += 1;
                continue;
            }
            for finding in kept {
                total_findings += 1;
                lines.push(format!(
                    "  {} [{}] {}",
                    severity_label(finding.severity),
                    outcome.lint_id,
                    finding.message
                ));
            }
        }

        out.push_str(&format!("[{}]\n", source_label(source)));
        for line in &lines {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str(&format!(
            "  ({passed} passed, {not_applicable} not applicable)\n",
        ));
    }

    if total_findings == 0 {
        out.push_str("OK: no findings\n");
    }

    out
}

/// Renders `outcomes` as pretty-printed JSON in the nested shape: one object per
/// outcome carrying `lint_id`, `source`, `applicability`, and its own `findings`
/// array (filtered to `min` and above).
///
/// All outcomes are retained (so passing and not-applicable lints stay visible);
/// only individual findings below the threshold are removed. Outcome order is
/// preserved from the engine, keeping output deterministic.
///
/// # Errors
///
/// Returns an error if serialization fails (which `serde_json` does not do for
/// these in-memory types in practice, but the fallible API is honoured rather
/// than panicking).
pub fn render_json(outcomes: &[LintOutcome], min: Severity) -> Result<String> {
    let filtered: Vec<LintOutcome> = outcomes
        .iter()
        .map(|o| LintOutcome {
            lint_id: o.lint_id,
            source: o.source,
            applicability: o.applicability,
            findings: o
                .findings
                .iter()
                .filter(|f| f.severity >= min)
                .cloned()
                .collect(),
        })
        .collect();

    serde_json::to_string_pretty(&filtered).context("failed to serialize lint outcomes to JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity, message: &str) -> Finding {
        Finding {
            severity,
            message: message.to_string(),
        }
    }

    fn outcome(
        lint_id: &'static str,
        source: RuleSource,
        applicability: Applicability,
        findings: Vec<Finding>,
    ) -> LintOutcome {
        LintOutcome {
            lint_id,
            source,
            applicability,
            findings,
        }
    }

    mod render_text {
        use super::*;

        #[test]
        fn reports_no_findings_when_all_pass() {
            let outcomes = vec![outcome(
                "hygiene_not_expired",
                RuleSource::Hygiene,
                Applicability::Applies,
                vec![],
            )];

            let text = render_text(&outcomes, Severity::Notice);

            assert!(text.contains("OK: no findings"));
            assert!(text.contains("[hygiene]"));
            assert!(text.contains("(1 passed, 0 not applicable)"));
        }

        #[test]
        fn lists_findings_under_their_source_group() {
            let outcomes = vec![outcome(
                "hygiene_not_expired",
                RuleSource::Hygiene,
                Applicability::Applies,
                vec![finding(Severity::Error, "certificate has expired")],
            )];

            let text = render_text(&outcomes, Severity::Notice);

            assert!(text.contains("[hygiene]"));
            assert!(text.contains("error [hygiene_not_expired] certificate has expired"));
            assert!(!text.contains("OK: no findings"));
        }

        #[test]
        fn groups_are_in_fixed_order() {
            let outcomes = vec![
                outcome(
                    "h",
                    RuleSource::Hygiene,
                    Applicability::Applies,
                    vec![finding(Severity::Warn, "h-msg")],
                ),
                outcome(
                    "r",
                    RuleSource::Rfc5280,
                    Applicability::Applies,
                    vec![finding(Severity::Warn, "r-msg")],
                ),
            ];

            let text = render_text(&outcomes, Severity::Notice);
            let rfc_pos = text.find("[rfc5280]").unwrap();
            let hyg_pos = text.find("[hygiene]").unwrap();
            assert!(rfc_pos < hyg_pos, "rfc5280 group must come before hygiene");
        }

        #[test]
        fn hides_findings_below_min_severity() {
            let outcomes = vec![outcome(
                "noisy",
                RuleSource::Hygiene,
                Applicability::Applies,
                vec![
                    finding(Severity::Notice, "just a note"),
                    finding(Severity::Error, "real problem"),
                ],
            )];

            let text = render_text(&outcomes, Severity::Warn);

            assert!(!text.contains("just a note"));
            assert!(text.contains("real problem"));
        }

        #[test]
        fn counts_not_applicable_compactly() {
            let outcomes = vec![outcome(
                "skipped",
                RuleSource::Rfc5280,
                Applicability::NotApplicable,
                vec![],
            )];

            let text = render_text(&outcomes, Severity::Notice);

            assert!(text.contains("(0 passed, 1 not applicable)"));
            assert!(!text.contains("skipped"));
        }
    }

    mod render_json {
        use super::*;

        #[test]
        fn emits_nested_shape_with_snake_case_source() {
            let outcomes = vec![outcome(
                "hygiene_not_expired",
                RuleSource::Hygiene,
                Applicability::Applies,
                vec![finding(Severity::Error, "expired")],
            )];

            let json = render_json(&outcomes, Severity::Notice).unwrap();

            assert!(json.contains("\"lint_id\": \"hygiene_not_expired\""));
            assert!(json.contains("\"source\": \"hygiene\""));
            assert!(json.contains("\"applicability\": \"applies\""));
            assert!(json.contains("\"severity\": \"error\""));
            assert!(json.contains("\"message\": \"expired\""));
        }

        #[test]
        fn filters_findings_below_min_severity() {
            let outcomes = vec![outcome(
                "noisy",
                RuleSource::Hygiene,
                Applicability::Applies,
                vec![
                    finding(Severity::Notice, "note"),
                    finding(Severity::Fatal, "boom"),
                ],
            )];

            let json = render_json(&outcomes, Severity::Error).unwrap();

            assert!(!json.contains("note"));
            assert!(json.contains("boom"));
        }

        #[test]
        fn is_deterministic_for_same_input() {
            let outcomes = vec![outcome(
                "a",
                RuleSource::Rfc5280,
                Applicability::Applies,
                vec![finding(Severity::Warn, "m")],
            )];

            let first = render_json(&outcomes, Severity::Notice).unwrap();
            let second = render_json(&outcomes, Severity::Notice).unwrap();
            assert_eq!(first, second);
        }
    }
}
