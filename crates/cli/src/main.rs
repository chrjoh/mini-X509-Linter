//! The `mini-x509-lint` binary.
//!
//! Reads a certificate file, loads it via the [`Cert`] facade (auto-detecting
//! PEM vs DER), runs every applicable lint from the [`default_registry`] against
//! the leaf certificate (or, with `--chain`, against every certificate in the
//! input), and reports the outcomes as text (grouped by [`RuleSource`]) or
//! nested JSON.
//!
//! Flags that shape the report:
//!
//! - `--format <text|json>` — output format (default `text`).
//! - `--source <list>` — comma-separated subset of
//!   `rfc5280,cabf_br,cabf_cs,hygiene` (default: all sources).
//! - `--min-severity <notice|warn|error|fatal>` — hide findings below the given
//!   level (default `notice`).
//! - `--fail-on <notice|warn|error|fatal>` — exit non-zero if any surfaced
//!   finding (after `--min-severity` filtering) is at or above this level
//!   (default `error`). This drives the process exit code so the tool is usable
//!   in CI / pre-commit hooks.
//! - `--chain` — treat the input as a chain / bundle: every certificate is
//!   linted and reported under its own label (full chain-aware lints are a
//!   post-v1 stretch). Without it, only the leaf (first certificate) is linted.
//! - `--verbose` / `-v` — opt-in per-lint text listing. Affects `--format text`
//!   only; `--format json` already emits every lint and is unchanged. Does not
//!   affect the exit code.
//! - `--purpose <auto|tls-server|code-signing|generic>` — scopes which lint
//!   **sources** apply based on the certificate's intended purpose (default
//!   `auto`). It maps to a [`linter::CertPurpose`] whose allowed-source set is
//!   intersected with `--source`; the engine then runs only the resulting
//!   sources. `auto` resolves per certificate from its EKU (codeSigning →
//!   code-signing, else serverAuth → tls-server, else generic).
//!
//! Exit code: `0` when no surfaced finding reaches `--fail-on`; `1` when one
//! does. A load/parse/usage error exits non-zero via the process error path.

mod output;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use linter::{Cert, CertPurpose, RuleSource, Severity, default_registry};

use output::{CertReport, PurposeHeader, Verbosity};

/// Output format for the lint report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable text grouped by rule source.
    Text,
    /// Nested JSON, one object per lint outcome.
    Json,
}

/// `--min-severity` / `--fail-on` levels, mirroring [`linter::Severity`].
///
/// A dedicated CLI enum keeps the on-wire flag vocabulary owned by the binary
/// and decoupled from the library type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SeverityLevel {
    /// Notice and above.
    Notice,
    /// Warn and above.
    Warn,
    /// Error and above.
    Error,
    /// Fatal only.
    Fatal,
}

impl From<SeverityLevel> for Severity {
    fn from(value: SeverityLevel) -> Self {
        match value {
            SeverityLevel::Notice => Severity::Notice,
            SeverityLevel::Warn => Severity::Warn,
            SeverityLevel::Error => Severity::Error,
            SeverityLevel::Fatal => Severity::Fatal,
        }
    }
}

/// `--purpose` values, mirroring [`linter::CertPurpose`].
///
/// A dedicated CLI enum keeps the flag vocabulary owned by the binary; the
/// purpose → source mapping itself lives in the linter crate
/// ([`CertPurpose::allowed_sources`]) so it is unit-testable and not duplicated
/// here.
///
/// # Future variants
///
/// `client` and `smime` are reserved as planned future values but are **not
/// implemented**: until dedicated rule sets exist they would behave like
/// [`generic`](CliPurpose::Generic). Adding them later is purely additive (no
/// rename of the shipped variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliPurpose {
    /// Resolve per certificate from its EKU: codeSigning → code-signing, else
    /// serverAuth → tls-server, otherwise → generic.
    Auto,
    /// A publicly-trusted TLS server certificate: standard, hygiene, and the
    /// TLS-server-specific `cabf_br` set.
    TlsServer,
    /// A code-signing certificate: standard, hygiene, and the code-signing
    /// `cabf_cs` set.
    CodeSigning,
    /// A certificate with no TLS-server or code-signing profile: `rfc5280` +
    /// `hygiene` only, skipping the `cabf_br` / `cabf_cs` sets.
    Generic,
}

impl From<CliPurpose> for CertPurpose {
    fn from(value: CliPurpose) -> Self {
        match value {
            CliPurpose::Auto => CertPurpose::Auto,
            CliPurpose::TlsServer => CertPurpose::TlsServer,
            CliPurpose::CodeSigning => CertPurpose::CodeSigning,
            CliPurpose::Generic => CertPurpose::Generic,
        }
    }
}

/// Command-line arguments for `mini-x509-lint`.
#[derive(Debug, Parser)]
#[command(
    name = "mini-x509-lint",
    about = "Lint an X.509 certificate (PEM or DER)."
)]
struct Args {
    /// Path to a certificate file (PEM or DER; format is auto-detected).
    path: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Comma-separated lint sources to run: `rfc5280`, `cabf_br`, `cabf_cs`,
    /// `hygiene`.
    ///
    /// Defaults to all sources when omitted.
    #[arg(long)]
    source: Option<String>,

    /// Only surface findings at or above this severity.
    #[arg(long, value_enum, default_value_t = SeverityLevel::Notice)]
    min_severity: SeverityLevel,

    /// Exit non-zero if any surfaced finding is at or above this severity.
    #[arg(long, value_enum, default_value_t = SeverityLevel::Error)]
    fail_on: SeverityLevel,

    /// Treat the input as a chain / bundle: lint and report every certificate.
    #[arg(long)]
    chain: bool,

    /// List every lint individually in text output (instead of a collapsed
    /// summary). Affects `--format text` only.
    #[arg(long, short = 'v')]
    verbose: bool,

    /// Scope which lint sources apply to the certificate's intended purpose.
    #[arg(long, value_enum, default_value_t = CliPurpose::Auto)]
    purpose: CliPurpose,
}

/// The full set of sources, used when `--source` is omitted. Order matches the
/// text formatter's `SOURCE_ORDER` for deterministic output.
const ALL_SOURCES: [RuleSource; 4] = [
    RuleSource::Rfc5280,
    RuleSource::CabfBr,
    RuleSource::CabfCs,
    RuleSource::Hygiene,
];

/// Process exit code returned when a surfaced finding reaches `--fail-on`.
const EXIT_FINDINGS: u8 = 1;

/// Parses a single `--source` token into a [`RuleSource`].
fn parse_source_token(token: &str) -> Result<RuleSource> {
    match token.trim() {
        "rfc5280" => Ok(RuleSource::Rfc5280),
        "cabf_br" => Ok(RuleSource::CabfBr),
        "cabf_cs" => Ok(RuleSource::CabfCs),
        "hygiene" => Ok(RuleSource::Hygiene),
        other => bail!(
            "unknown --source value '{other}' (expected rfc5280, cabf_br, cabf_cs, or hygiene)"
        ),
    }
}

/// Parses the `--source` flag into the list of selected sources.
///
/// A missing flag selects all sources. An empty/whitespace-only value is
/// rejected so the user does not silently get a no-op run.
///
/// # Errors
///
/// Returns an error if the value contains an unknown or empty token.
fn select_sources(source: Option<&str>) -> Result<Vec<RuleSource>> {
    let Some(raw) = source else {
        return Ok(ALL_SOURCES.to_vec());
    };

    let mut sources = Vec::new();
    for token in raw.split(',') {
        if token.trim().is_empty() {
            bail!("empty --source value (expected a comma-separated list)");
        }
        sources.push(parse_source_token(token)?);
    }

    if sources.is_empty() {
        bail!("empty --source value (expected a comma-separated list)");
    }
    Ok(sources)
}

/// Computes the effective source set for `cert`: the purpose-allowed sources
/// intersected with the user's `--source` selection.
///
/// Ordering follows the purpose-allowed set (which is itself stable), so the
/// engine output stays deterministic. An empty intersection is valid and simply
/// runs nothing from the excluded sources.
fn effective_sources(
    purpose: CertPurpose,
    cert: &Cert,
    selected: &[RuleSource],
) -> Vec<RuleSource> {
    purpose
        .allowed_sources(cert)
        .into_iter()
        .filter(|source| selected.contains(source))
        .collect()
}

/// The stable label for a resolved [`CertPurpose`], used by the verbose header.
fn purpose_label(purpose: CertPurpose) -> &'static str {
    match purpose {
        CertPurpose::TlsServer => "tls-server",
        CertPurpose::CodeSigning => "code-signing",
        CertPurpose::Generic => "generic",
        // `Auto` is always resolved before labelling; treat defensively.
        CertPurpose::Auto => "auto",
    }
}

/// Builds the verbose-only purpose header for `cert`.
///
/// `resolved` is the concrete purpose `--purpose` landed on (resolving `auto`
/// per cert); `from_auto` records whether the user supplied `auto`.
fn build_purpose_header(
    cli_purpose: CliPurpose,
    purpose: CertPurpose,
    cert: &Cert,
) -> PurposeHeader {
    PurposeHeader {
        resolved: purpose_label(purpose.resolve(cert)).to_string(),
        from_auto: cli_purpose == CliPurpose::Auto,
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => code,
        Err(err) => {
            // Generic, single-line error (no stack trace). The `{:#}` form
            // chains the anyhow context messages.
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Loads the certificate(s), runs the selected lints, prints the report, and
/// returns the process exit code derived from `--fail-on`.
///
/// # Errors
///
/// Returns an error if the file cannot be read, its contents cannot be parsed as
/// one or more X.509 certificates, the `--source` value is invalid, or the
/// report cannot be serialized.
fn run(args: &Args) -> Result<ExitCode> {
    let selected = select_sources(args.source.as_deref())?;
    let purpose: CertPurpose = args.purpose.into();
    let min: Severity = args.min_severity.into();
    let fail_on: Severity = args.fail_on.into();
    let verbosity = if args.verbose {
        Verbosity::PerLint
    } else {
        Verbosity::Summary
    };

    let certs = load_certs(&args.path)?;
    let registry = default_registry();

    // The purpose header is resolved against the leaf (the cert that anchors the
    // run); in chain mode each cert is still filtered against its own resolution.
    let leaf = &certs[0];
    let header = build_purpose_header(args.purpose, purpose, leaf);

    if args.chain {
        run_chain(
            &certs,
            &registry,
            purpose,
            &selected,
            min,
            fail_on,
            verbosity,
            &header,
            args.format,
        )
    } else {
        let effective = effective_sources(purpose, leaf, &selected);
        let outcomes = registry.run_filtered(leaf, &effective);

        let report = match args.format {
            Format::Text => output::render_text_opts(&outcomes, min, verbosity, Some(&header)),
            Format::Json => {
                let mut json = output::render_json(&outcomes, min)?;
                json.push('\n');
                json
            }
        };
        print!("{report}");

        let counts = output::severity_counts(&outcomes, min);
        Ok(exit_code(counts, fail_on))
    }
}

/// Lints and renders every certificate in the input as a chain.
#[allow(clippy::too_many_arguments)]
fn run_chain(
    certs: &[Cert],
    registry: &linter::Registry,
    purpose: CertPurpose,
    selected: &[RuleSource],
    min: Severity,
    fail_on: Severity,
    verbosity: Verbosity,
    header: &PurposeHeader,
    format: Format,
) -> Result<ExitCode> {
    // Lint every cert, resolving `auto` against each cert in turn.
    let per_cert: Vec<(String, Vec<linter::LintOutcome>)> = certs
        .iter()
        .enumerate()
        .map(|(idx, cert)| {
            let label = if idx == 0 {
                "Certificate 1 (leaf)".to_string()
            } else {
                format!("Certificate {}", idx + 1)
            };
            let effective = effective_sources(purpose, cert, selected);
            (label, registry.run_filtered(cert, &effective))
        })
        .collect();

    match format {
        Format::Text => {
            let reports: Vec<CertReport<'_>> = per_cert
                .iter()
                .map(|(label, outcomes)| CertReport::new(label, outcomes))
                .collect();
            let report = output::render_text_chain(&reports, min, verbosity, Some(header));
            print!("{report}");
        }
        Format::Json => {
            let json = render_chain_json(&per_cert, min)?;
            println!("{json}");
        }
    }

    // Exit code: fail if any cert has a surfaced finding at/above `fail_on`.
    let mut worst_triggers = false;
    for (_, outcomes) in &per_cert {
        let counts = output::severity_counts(outcomes, min);
        if exit_code(counts, fail_on) != ExitCode::SUCCESS {
            worst_triggers = true;
        }
    }
    Ok(if worst_triggers {
        ExitCode::from(EXIT_FINDINGS)
    } else {
        ExitCode::SUCCESS
    })
}

/// Renders the chain as a JSON array of `{ "certificate": <label>, "outcomes":
/// [...] }` objects, one per certificate, in chain order. The `outcomes` array
/// uses the same nested shape as the single-cert JSON output.
///
/// # Errors
///
/// Returns an error if serialization fails.
fn render_chain_json(
    per_cert: &[(String, Vec<linter::LintOutcome>)],
    min: Severity,
) -> Result<String> {
    let mut entries: Vec<serde_json::Value> = Vec::with_capacity(per_cert.len());
    for (label, outcomes) in per_cert {
        // Reuse the single-cert renderer for the per-cert outcomes shape, then
        // re-parse so the whole document is one valid JSON array.
        let outcomes_json = output::render_json(outcomes, min)?;
        let outcomes_value: serde_json::Value = serde_json::from_str(&outcomes_json)
            .context("failed to re-parse per-cert outcomes JSON")?;
        entries.push(serde_json::json!({
            "certificate": label,
            "outcomes": outcomes_value,
        }));
    }
    serde_json::to_string_pretty(&entries).context("failed to serialize chain JSON")
}

/// Maps the surfaced severity counts to a process exit code given `--fail-on`.
///
/// Returns [`ExitCode::FAILURE`]-equivalent ([`EXIT_FINDINGS`]) when any count
/// at or above `fail_on` is non-zero, otherwise [`ExitCode::SUCCESS`].
fn exit_code(counts: output::SeverityCounts, fail_on: Severity) -> ExitCode {
    let triggered = match fail_on {
        Severity::Fatal => counts.fatal > 0,
        Severity::Error => counts.fatal > 0 || counts.error > 0,
        Severity::Warn => counts.fatal > 0 || counts.error > 0 || counts.warn > 0,
        Severity::Notice => counts.total() > 0,
    };
    if triggered {
        ExitCode::from(EXIT_FINDINGS)
    } else {
        ExitCode::SUCCESS
    }
}

/// Reads `path` and returns every certificate it contains, in input order.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed, or if it contains no
/// certificates.
fn load_certs(path: &Path) -> Result<Vec<Cert>> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read certificate file: {}", path.display()))?;

    let certs = Cert::load(&bytes)
        .with_context(|| format!("failed to parse certificate(s) from: {}", path.display()))?;

    if certs.is_empty() {
        bail!("no certificates found in the input file");
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod select_sources {
        use super::*;

        #[test]
        fn defaults_to_all_sources_when_omitted() {
            let sources = select_sources(None).unwrap();
            assert_eq!(sources, ALL_SOURCES.to_vec());
        }

        #[test]
        fn parses_a_single_source() {
            let sources = select_sources(Some("rfc5280")).unwrap();
            assert_eq!(sources, vec![RuleSource::Rfc5280]);
        }

        #[test]
        fn parses_a_comma_list_with_whitespace() {
            let sources = select_sources(Some("rfc5280, hygiene")).unwrap();
            assert_eq!(sources, vec![RuleSource::Rfc5280, RuleSource::Hygiene]);
        }

        #[test]
        fn rejects_unknown_token() {
            select_sources(Some("rfc5280,bogus")).unwrap_err();
        }

        #[test]
        fn rejects_empty_token() {
            select_sources(Some("rfc5280,,hygiene")).unwrap_err();
        }
    }

    mod severity_level_conversion {
        use super::*;

        #[test]
        fn maps_each_variant() {
            assert_eq!(Severity::from(SeverityLevel::Notice), Severity::Notice);
            assert_eq!(Severity::from(SeverityLevel::Warn), Severity::Warn);
            assert_eq!(Severity::from(SeverityLevel::Error), Severity::Error);
            assert_eq!(Severity::from(SeverityLevel::Fatal), Severity::Fatal);
        }
    }

    mod cli_purpose_conversion {
        use super::*;

        #[test]
        fn maps_each_variant() {
            assert_eq!(CertPurpose::from(CliPurpose::Auto), CertPurpose::Auto);
            assert_eq!(
                CertPurpose::from(CliPurpose::TlsServer),
                CertPurpose::TlsServer
            );
            assert_eq!(
                CertPurpose::from(CliPurpose::CodeSigning),
                CertPurpose::CodeSigning
            );
            assert_eq!(CertPurpose::from(CliPurpose::Generic), CertPurpose::Generic);
        }
    }

    mod effective_sources {
        use super::*;

        fn good_cert() -> Cert {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
            let bytes = std::fs::read(path).expect("good.pem fixture must exist");
            let mut certs = Cert::load(&bytes).expect("good.pem must parse");
            certs.remove(0)
        }

        #[test]
        fn tls_server_with_all_sources_keeps_all() {
            let cert = good_cert();
            let eff = effective_sources(CertPurpose::TlsServer, &cert, &ALL_SOURCES);
            assert_eq!(
                eff,
                vec![RuleSource::Rfc5280, RuleSource::Hygiene, RuleSource::CabfBr]
            );
        }

        #[test]
        fn generic_drops_cabf_br() {
            let cert = good_cert();
            let eff = effective_sources(CertPurpose::Generic, &cert, &ALL_SOURCES);
            assert!(!eff.contains(&RuleSource::CabfBr));
            assert_eq!(eff, vec![RuleSource::Rfc5280, RuleSource::Hygiene]);
        }

        #[test]
        fn intersection_with_source_selection() {
            let cert = good_cert();
            // tls-server allows all, but the user asked only for rfc5280.
            let eff = effective_sources(CertPurpose::TlsServer, &cert, &[RuleSource::Rfc5280]);
            assert_eq!(eff, vec![RuleSource::Rfc5280]);
        }

        #[test]
        fn empty_intersection_is_allowed() {
            let cert = good_cert();
            // generic omits cabf_br; selecting only cabf_br yields nothing.
            let eff = effective_sources(CertPurpose::Generic, &cert, &[RuleSource::CabfBr]);
            assert!(eff.is_empty());
        }
    }

    mod exit_code {
        use super::*;
        use output::SeverityCounts;

        fn counts(fatal: usize, error: usize, warn: usize, notice: usize) -> SeverityCounts {
            SeverityCounts {
                fatal,
                error,
                warn,
                notice,
            }
        }

        #[test]
        fn fail_on_error_passes_on_warn_only() {
            assert_eq!(
                exit_code(counts(0, 0, 1, 3), Severity::Error),
                ExitCode::SUCCESS
            );
        }

        #[test]
        fn fail_on_error_triggers_on_error() {
            assert_eq!(
                exit_code(counts(0, 1, 0, 0), Severity::Error),
                ExitCode::from(EXIT_FINDINGS)
            );
        }

        #[test]
        fn fail_on_error_triggers_on_fatal() {
            assert_eq!(
                exit_code(counts(1, 0, 0, 0), Severity::Error),
                ExitCode::from(EXIT_FINDINGS)
            );
        }

        #[test]
        fn fail_on_notice_triggers_on_any_finding() {
            assert_eq!(
                exit_code(counts(0, 0, 0, 1), Severity::Notice),
                ExitCode::from(EXIT_FINDINGS)
            );
        }

        #[test]
        fn no_findings_is_success() {
            assert_eq!(
                exit_code(SeverityCounts::default(), Severity::Notice),
                ExitCode::SUCCESS
            );
        }
    }

    mod purpose_header {
        use super::*;

        fn good_cert() -> Cert {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
            let bytes = std::fs::read(path).expect("good.pem fixture must exist");
            let mut certs = Cert::load(&bytes).expect("good.pem must parse");
            certs.remove(0)
        }

        #[test]
        fn auto_resolves_and_marks_from_auto() {
            let cert = good_cert();
            let header = build_purpose_header(CliPurpose::Auto, CertPurpose::Auto, &cert);
            // good.pem asserts serverAuth -> tls-server.
            assert_eq!(header.resolved, "tls-server");
            assert!(header.from_auto);
        }

        #[test]
        fn explicit_purpose_not_from_auto() {
            let cert = good_cert();
            let header = build_purpose_header(CliPurpose::Generic, CertPurpose::Generic, &cert);
            assert_eq!(header.resolved, "generic");
            assert!(!header.from_auto);
        }
    }
}
