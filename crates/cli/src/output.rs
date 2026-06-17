//! Formatters that turn the engine's `Vec<LintOutcome>` into displayable output.
//!
//! Two formats are offered:
//!
//! - [`render_text`] / [`render_text_opts`] — a human-readable report grouped by
//!   [`RuleSource`].
//! - [`render_json`] — the nested JSON shape (one object per outcome).
//! - [`render_text_chain`] — a multi-certificate (chain / bundle) text report.
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

/// Controls how passing / not-applicable lints are rendered in text output.
///
/// The selection is presentation-only: the same `&[LintOutcome]` drives both
/// layouts. Failing-lint rendering is identical in both modes.
// NOTE: `#[allow(dead_code)]` here (and on the other new public items below) is
// temporary: `output.rs` is a binary module, so `pub` does not suppress
// dead-code warnings. The `--verbose` / `--chain` / `--purpose` call sites in
// main.rs are added by feature-06 task 02; once it lands these attributes can be
// removed.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verbosity {
    /// Default, terse layout: passing and not-applicable lints are collapsed into
    /// a single `(N passed, M not applicable)` line per source group.
    #[default]
    Summary,
    /// Verbose layout: every lint is listed on its own line with a status token
    /// (`pass` / `n/a`) and its `lint_id`, sorted by `lint_id` within the group.
    /// The collapsed summary line is omitted.
    PerLint,
}

/// A resolved certificate purpose, rendered as a verbose-only header line.
///
/// `output.rs` does not resolve purpose itself; the caller passes the already
/// resolved label (e.g. `"generic"`, `"tls-server"`) and whether it was derived
/// from the `auto` heuristic. The header is emitted only in [`Verbosity::PerLint`]
/// mode and is kept deterministic for golden snapshots.
#[allow(dead_code)] // Consumed by feature-06 task 02 (main.rs --purpose wiring).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurposeHeader {
    /// The resolved purpose label, e.g. `"generic"` or `"tls-server"`.
    pub resolved: String,
    /// Whether the resolved purpose came from the `auto` heuristic.
    pub from_auto: bool,
}

impl PurposeHeader {
    /// Renders the header line body, e.g. `generic (auto)` or `tls-server`.
    #[allow(dead_code)] // Used via render_text_opts/render_text_chain (task 02).
    fn line(&self) -> String {
        if self.from_auto {
            format!("purpose: {} (auto)", self.resolved)
        } else {
            format!("purpose: {}", self.resolved)
        }
    }
}

/// Per-severity totals over the findings that survived `--min-severity`.
///
/// Derived from the already-filtered outcomes; reused by the exit-code logic.
#[allow(dead_code)] // Consumed by feature-06 task 02 (summary line + exit code).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeverityCounts {
    /// Number of surfaced `fatal` findings.
    pub fatal: usize,
    /// Number of surfaced `error` findings.
    pub error: usize,
    /// Number of surfaced `warn` findings.
    pub warn: usize,
    /// Number of surfaced `notice` findings.
    pub notice: usize,
}

#[allow(dead_code)] // Consumed by feature-06 task 02 (summary line + exit code).
impl SeverityCounts {
    /// The total number of surfaced findings across all severities.
    pub fn total(&self) -> usize {
        self.fatal + self.error + self.warn + self.notice
    }

    /// Renders the summary line, e.g. `2 error, 1 warn, 3 notice`.
    ///
    /// Only non-zero severities are listed, in descending severity order. When no
    /// findings surfaced, returns `no findings`.
    pub fn summary_line(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.fatal > 0 {
            parts.push(format!("{} fatal", self.fatal));
        }
        if self.error > 0 {
            parts.push(format!("{} error", self.error));
        }
        if self.warn > 0 {
            parts.push(format!("{} warn", self.warn));
        }
        if self.notice > 0 {
            parts.push(format!("{} notice", self.notice));
        }
        if parts.is_empty() {
            "no findings".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// Counts the findings that meet or exceed `min`, grouped by severity.
///
/// The counts reflect what the text/JSON formatters would surface, so they can
/// drive both the summary line and the process exit code without re-running any
/// lints.
#[allow(dead_code)] // Consumed by feature-06 task 02 (summary line + exit code).
pub fn severity_counts(outcomes: &[LintOutcome], min: Severity) -> SeverityCounts {
    let mut counts = SeverityCounts::default();
    for outcome in outcomes {
        for finding in &outcome.findings {
            if finding.severity < min {
                continue;
            }
            match finding.severity {
                Severity::Fatal => counts.fatal += 1,
                Severity::Error => counts.error += 1,
                Severity::Warn => counts.warn += 1,
                Severity::Notice => counts.notice += 1,
            }
        }
    }
    counts
}

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

/// Pushes the verbose-only `purpose:` header line into `out`, when applicable.
///
/// The line is emitted only in [`Verbosity::PerLint`] mode and only when a
/// purpose was supplied, keeping default (non-verbose) output byte-for-byte
/// unchanged.
fn push_purpose_header(out: &mut String, verbosity: Verbosity, purpose: Option<&PurposeHeader>) {
    if let (Verbosity::PerLint, Some(purpose)) = (verbosity, purpose) {
        out.push_str(&purpose.line());
        out.push('\n');
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
/// This is the back-compatible entry point: it renders the default
/// [`Verbosity::Summary`] layout with no purpose header, byte-for-byte identical
/// to feature 02's output. For per-severity counts, verbose listings, or a
/// purpose header, use [`render_text_opts`].
///
/// Findings below `min` are hidden. Within each source group, applicable lints
/// with surviving findings are listed (one line per finding). Lints that passed
/// (applicable, no surviving findings) and lints that did not apply are
/// summarized compactly as counts rather than printed verbosely. A clear "no
/// findings" line is emitted when nothing surfaced.
// NOTE: feature-06 task 02 switched the binary to `render_text_opts`, so this
// back-compat entry point is no longer called from `main.rs`. It stays as part
// of the module's public surface and is exercised by its own unit tests; the
// `#[allow(dead_code)]` mirrors the temporary allows on the other new public
// items above (binary modules do not suppress dead-code for `pub` items).
#[allow(dead_code)]
pub fn render_text(outcomes: &[LintOutcome], min: Severity) -> String {
    render_group_block(outcomes, min, Verbosity::Summary)
}

/// Renders `outcomes` as a human-readable report with full control over
/// verbosity and an optional verbose-only purpose header.
///
/// - In [`Verbosity::Summary`] (default) the group bodies are byte-for-byte
///   identical to [`render_text`]: passing / not-applicable lints collapse into a
///   single `(N passed, M not applicable)` line.
/// - In [`Verbosity::PerLint`] every lint is listed on its own line with a
///   `pass` / `n/a` status token and its `lint_id`, sorted by `lint_id` within
///   each source group; the collapsed summary line is omitted.
///
/// A per-severity summary line (`2 error, 1 warn, 3 notice`) is appended after
/// the groups regardless of verbosity. When `purpose` is `Some` **and** verbosity
/// is [`Verbosity::PerLint`], a deterministic `purpose: <resolved> (<auto?>)`
/// header line is emitted first; otherwise no purpose line appears.
#[allow(dead_code)] // Consumed by feature-06 task 02 (--verbose / --purpose).
pub fn render_text_opts(
    outcomes: &[LintOutcome],
    min: Severity,
    verbosity: Verbosity,
    purpose: Option<&PurposeHeader>,
) -> String {
    let mut out = String::new();

    push_purpose_header(&mut out, verbosity, purpose);

    out.push_str(&render_group_block(outcomes, min, verbosity));

    let counts = severity_counts(outcomes, min);
    out.push_str(&format!("summary: {}\n", counts.summary_line()));

    out
}

/// Renders the grouped source blocks (without counts or purpose header).
///
/// Shared by [`render_text`], [`render_text_opts`], and [`render_text_chain`].
fn render_group_block(outcomes: &[LintOutcome], min: Severity, verbosity: Verbosity) -> String {
    let mut out = String::new();
    let mut total_findings = 0usize;

    for &source in &SOURCE_ORDER {
        let group: Vec<&LintOutcome> = outcomes.iter().filter(|o| o.source == source).collect();
        if group.is_empty() {
            continue;
        }

        match verbosity {
            Verbosity::Summary => {
                render_group_summary(&mut out, source, &group, min, &mut total_findings);
            }
            Verbosity::PerLint => {
                render_group_per_lint(&mut out, source, &group, min, &mut total_findings);
            }
        }
    }

    if total_findings == 0 {
        out.push_str("OK: no findings\n");
    }

    out
}

/// Renders a single source group in the collapsed (`Summary`) layout.
fn render_group_summary(
    out: &mut String,
    source: RuleSource,
    group: &[&LintOutcome],
    min: Severity,
    total_findings: &mut usize,
) {
    let mut lines: Vec<String> = Vec::new();
    let mut passed = 0usize;
    let mut not_applicable = 0usize;

    for outcome in group {
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
            *total_findings += 1;
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

/// Renders a single source group in the per-lint (`PerLint`) verbose layout.
///
/// Every lint is listed, sorted by `lint_id`. Failing lints render their finding
/// lines exactly as in summary mode; passing / not-applicable lints render a
/// status token (`pass` / `n/a`) followed by their `lint_id`.
fn render_group_per_lint(
    out: &mut String,
    source: RuleSource,
    group: &[&LintOutcome],
    min: Severity,
    total_findings: &mut usize,
) {
    let mut sorted: Vec<&&LintOutcome> = group.iter().collect();
    sorted.sort_by(|a, b| a.lint_id.cmp(b.lint_id));

    out.push_str(&format!("[{}]\n", source_label(source)));

    for outcome in sorted {
        match outcome.applicability {
            Applicability::NotApplicable => {
                out.push_str(&format!("  n/a   {}\n", outcome.lint_id));
                continue;
            }
            Applicability::Applies => {}
        }

        let kept = findings_at_or_above(outcome, min);
        if kept.is_empty() {
            out.push_str(&format!("  pass  {}\n", outcome.lint_id));
            continue;
        }
        for finding in kept {
            *total_findings += 1;
            out.push_str(&format!(
                "  {} [{}] {}\n",
                severity_label(finding.severity),
                outcome.lint_id,
                finding.message
            ));
        }
    }
}

/// A single certificate's report within a chain / bundle.
///
/// Each entry carries a human-readable `label` (e.g. `"Certificate 1 (leaf)"`)
/// and a borrowed slice of the outcomes the engine produced for that cert. In v1
/// only the leaf carries lint findings; other entries are chain context and may
/// have an empty `outcomes` slice.
#[allow(dead_code)] // Consumed by feature-06 task 02 (--chain rendering).
#[derive(Debug, Clone, Copy)]
pub struct CertReport<'a> {
    /// Human-readable label for this certificate in the chain.
    pub label: &'a str,
    /// The outcomes the engine produced for this certificate.
    pub outcomes: &'a [LintOutcome],
}

impl<'a> CertReport<'a> {
    /// Creates a new chain entry from a label and its outcomes.
    #[allow(dead_code)] // Consumed by feature-06 task 02 (--chain rendering).
    pub fn new(label: &'a str, outcomes: &'a [LintOutcome]) -> Self {
        Self { label, outcomes }
    }
}

/// Renders a multi-certificate (chain / bundle) text report.
///
/// Each entry is rendered under its `label` header, followed by that
/// certificate's grouped source blocks (respecting `verbosity`). After all
/// certificates, a single aggregate per-severity summary line is appended,
/// covering every finding across the chain. When `purpose` is `Some` and
/// `verbosity` is [`Verbosity::PerLint`], the deterministic purpose header is
/// emitted once at the top.
///
/// Output is deterministic: certificate order follows `certs`, and within each
/// certificate the source-group order and per-lint sort are fixed.
#[allow(dead_code)] // Consumed by feature-06 task 02 (--chain rendering).
pub fn render_text_chain(
    certs: &[CertReport<'_>],
    min: Severity,
    verbosity: Verbosity,
    purpose: Option<&PurposeHeader>,
) -> String {
    let mut out = String::new();

    push_purpose_header(&mut out, verbosity, purpose);

    for (idx, cert) in certs.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(&format!("{}\n", cert.label));
        out.push_str(&render_group_block(cert.outcomes, min, verbosity));
    }

    // Aggregate counts across every certificate in the chain.
    let mut counts = SeverityCounts::default();
    for cert in certs {
        let c = severity_counts(cert.outcomes, min);
        counts.fatal += c.fatal;
        counts.error += c.error;
        counts.warn += c.warn;
        counts.notice += c.notice;
    }
    out.push_str(&format!("summary: {}\n", counts.summary_line()));

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

        #[test]
        fn default_path_has_no_summary_or_purpose_line() {
            // render_text is the back-compat entry point: feature-02 byte-for-byte.
            let outcomes = vec![outcome(
                "hygiene_not_expired",
                RuleSource::Hygiene,
                Applicability::Applies,
                vec![],
            )];

            let text = render_text(&outcomes, Severity::Notice);

            assert!(!text.contains("summary:"));
            assert!(!text.contains("purpose:"));
        }
    }

    mod severity_counts {
        use super::*;

        #[test]
        fn counts_each_severity_over_threshold() {
            let outcomes = vec![
                outcome(
                    "a",
                    RuleSource::Rfc5280,
                    Applicability::Applies,
                    vec![
                        finding(Severity::Error, "e1"),
                        finding(Severity::Error, "e2"),
                    ],
                ),
                outcome(
                    "b",
                    RuleSource::Hygiene,
                    Applicability::Applies,
                    vec![
                        finding(Severity::Warn, "w"),
                        finding(Severity::Notice, "n1"),
                        finding(Severity::Notice, "n2"),
                        finding(Severity::Notice, "n3"),
                    ],
                ),
            ];

            let counts = severity_counts(&outcomes, Severity::Notice);

            assert_eq!(counts.error, 2);
            assert_eq!(counts.warn, 1);
            assert_eq!(counts.notice, 3);
            assert_eq!(counts.fatal, 0);
            assert_eq!(counts.total(), 6);
        }

        #[test]
        fn respects_min_severity() {
            let outcomes = vec![outcome(
                "a",
                RuleSource::Rfc5280,
                Applicability::Applies,
                vec![
                    finding(Severity::Notice, "n"),
                    finding(Severity::Error, "e"),
                ],
            )];

            let counts = severity_counts(&outcomes, Severity::Warn);

            assert_eq!(counts.notice, 0);
            assert_eq!(counts.error, 1);
        }

        #[test]
        fn summary_line_lists_nonzero_descending() {
            let counts = SeverityCounts {
                fatal: 0,
                error: 2,
                warn: 1,
                notice: 3,
            };
            assert_eq!(counts.summary_line(), "2 error, 1 warn, 3 notice");
        }

        #[test]
        fn summary_line_reports_no_findings_when_empty() {
            let counts = SeverityCounts::default();
            assert_eq!(counts.summary_line(), "no findings");
        }
    }

    mod render_text_opts {
        use super::*;

        #[test]
        fn appends_summary_line() {
            let outcomes = vec![outcome(
                "a",
                RuleSource::Rfc5280,
                Applicability::Applies,
                vec![finding(Severity::Error, "boom")],
            )];

            let text = render_text_opts(&outcomes, Severity::Notice, Verbosity::Summary, None);

            assert!(text.contains("summary: 1 error"));
        }

        #[test]
        fn summary_mode_group_body_matches_render_text() {
            let outcomes = vec![outcome(
                "a",
                RuleSource::Rfc5280,
                Applicability::Applies,
                vec![finding(Severity::Error, "boom")],
            )];

            let legacy = render_text(&outcomes, Severity::Notice);
            let opts = render_text_opts(&outcomes, Severity::Notice, Verbosity::Summary, None);

            // The opts output is the legacy block plus a trailing summary line.
            assert!(opts.starts_with(&legacy));
            assert_eq!(opts, format!("{legacy}summary: 1 error\n"));
        }

        #[test]
        fn verbose_lists_every_lint_sorted() {
            let outcomes = vec![
                outcome(
                    "rfc5280_zebra",
                    RuleSource::Rfc5280,
                    Applicability::Applies,
                    vec![],
                ),
                outcome(
                    "rfc5280_alpha",
                    RuleSource::Rfc5280,
                    Applicability::NotApplicable,
                    vec![],
                ),
            ];

            let text = render_text_opts(&outcomes, Severity::Notice, Verbosity::PerLint, None);

            assert!(text.contains("  n/a   rfc5280_alpha\n"));
            assert!(text.contains("  pass  rfc5280_zebra\n"));
            let alpha = text.find("rfc5280_alpha").unwrap();
            let zebra = text.find("rfc5280_zebra").unwrap();
            assert!(alpha < zebra, "lints must be sorted by lint_id");
            assert!(!text.contains("passed,"), "no collapsed summary in verbose");
        }

        #[test]
        fn verbose_keeps_failing_finding_lines() {
            let outcomes = vec![outcome(
                "rfc5280_bad",
                RuleSource::Rfc5280,
                Applicability::Applies,
                vec![finding(Severity::Error, "broken")],
            )];

            let text = render_text_opts(&outcomes, Severity::Notice, Verbosity::PerLint, None);

            assert!(text.contains("  error [rfc5280_bad] broken\n"));
            assert!(!text.contains("pass  rfc5280_bad"));
        }

        #[test]
        fn purpose_header_only_in_verbose() {
            let outcomes = vec![outcome(
                "a",
                RuleSource::Rfc5280,
                Applicability::Applies,
                vec![],
            )];
            let purpose = PurposeHeader {
                resolved: "generic".to_string(),
                from_auto: true,
            };

            let summary = render_text_opts(
                &outcomes,
                Severity::Notice,
                Verbosity::Summary,
                Some(&purpose),
            );
            assert!(!summary.contains("purpose:"));

            let verbose = render_text_opts(
                &outcomes,
                Severity::Notice,
                Verbosity::PerLint,
                Some(&purpose),
            );
            assert!(verbose.starts_with("purpose: generic (auto)\n"));
        }

        #[test]
        fn explicit_purpose_omits_auto_marker() {
            let outcomes: Vec<LintOutcome> = vec![];
            let purpose = PurposeHeader {
                resolved: "tls-server".to_string(),
                from_auto: false,
            };

            let verbose = render_text_opts(
                &outcomes,
                Severity::Notice,
                Verbosity::PerLint,
                Some(&purpose),
            );
            assert!(verbose.starts_with("purpose: tls-server\n"));
            assert!(!verbose.contains("(auto)"));
        }
    }

    mod render_text_chain {
        use super::*;

        #[test]
        fn labels_each_cert_and_aggregates_summary() {
            let leaf = vec![outcome(
                "rfc5280_bad",
                RuleSource::Rfc5280,
                Applicability::Applies,
                vec![finding(Severity::Error, "broken")],
            )];
            let intermediate = vec![outcome(
                "hygiene_warn",
                RuleSource::Hygiene,
                Applicability::Applies,
                vec![finding(Severity::Warn, "weak")],
            )];

            let certs = [
                CertReport::new("Certificate 1 (leaf)", &leaf),
                CertReport::new("Certificate 2", &intermediate),
            ];

            let text = render_text_chain(&certs, Severity::Notice, Verbosity::Summary, None);

            let leaf_pos = text.find("Certificate 1 (leaf)").unwrap();
            let int_pos = text.find("Certificate 2").unwrap();
            assert!(leaf_pos < int_pos, "certs render in order");
            assert!(text.contains("  error [rfc5280_bad] broken"));
            assert!(text.contains("  warn [hygiene_warn] weak"));
            // Aggregate over the whole chain.
            assert!(text.contains("summary: 1 error, 1 warn"));
        }

        #[test]
        fn deterministic_for_same_input() {
            let leaf = vec![outcome(
                "a",
                RuleSource::Rfc5280,
                Applicability::Applies,
                vec![finding(Severity::Warn, "m")],
            )];
            let certs = [CertReport::new("Certificate 1 (leaf)", &leaf)];

            let first = render_text_chain(&certs, Severity::Notice, Verbosity::PerLint, None);
            let second = render_text_chain(&certs, Severity::Notice, Verbosity::PerLint, None);
            assert_eq!(first, second);
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
