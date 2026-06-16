//! Core result types produced when a [`Lint`](crate::Lint) inspects a certificate.

use crate::source::RuleSource;

/// How serious a [`Finding`] is.
///
/// There is deliberately no `Pass` variant: a lint that found nothing wrong
/// returns an empty `Vec<Finding>` rather than a "pass" severity.
///
/// The variants are ordered `Notice < Warn < Error < Fatal`, which lets callers
/// implement threshold flags such as `--min-severity` and `--fail-on` via simple
/// comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational; not a problem on its own.
    Notice,
    /// A likely problem or discouraged practice.
    Warn,
    /// A clear violation of the rule.
    Error,
    /// A violation severe enough that the certificate is effectively unusable.
    Fatal,
}

/// Whether a [`Lint`](crate::Lint) is relevant to a given certificate.
///
/// The engine only calls [`Lint::check`](crate::Lint::check) when a lint reports
/// [`Applicability::Applies`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applicability {
    /// The lint's rule is relevant to this certificate and should be checked.
    Applies,
    /// The lint's rule does not apply to this certificate; it should be skipped.
    NotApplicable,
}

/// A single, specific problem detected by a lint.
///
/// A lint may return several findings from one [`check`](crate::Lint::check) call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// How serious this problem is.
    pub severity: Severity,
    /// A human-readable description of the problem.
    pub message: String,
}

/// The full result of running one lint against one certificate.
///
/// The engine attaches the lint's identity ([`lint_id`](LintOutcome::lint_id) and
/// [`source`](LintOutcome::source)) alongside the outcome. An empty
/// [`findings`](LintOutcome::findings) list together with
/// [`Applicability::Applies`] means the certificate passed that lint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintOutcome {
    /// Stable identifier of the lint that produced this outcome.
    pub lint_id: &'static str,
    /// The authority the lint enforces.
    pub source: RuleSource,
    /// Whether the lint applied to the certificate.
    pub applicability: Applicability,
    /// Problems found; empty when the certificate passed.
    pub findings: Vec<Finding>,
}
