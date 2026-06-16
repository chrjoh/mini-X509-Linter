//! The `mini-x509-lint` binary.
//!
//! Reads a certificate file, loads it via the [`Cert`] facade (auto-detecting
//! PEM vs DER), runs every applicable lint from the [`default_registry`] against
//! the leaf certificate, and reports the outcomes as text (grouped by
//! [`RuleSource`]) or nested JSON.
//!
//! Three flags shape the report:
//!
//! - `--format <text|json>` — output format (default `text`).
//! - `--source <list>` — comma-separated subset of `rfc5280,cabf_br,hygiene`
//!   (default: all sources).
//! - `--min-severity <notice|warn|error|fatal>` — hide findings below the given
//!   level (default `notice`).
//!
//! Exit codes by severity are a later feature (06); this binary returns success
//! once the certificate loads and lints run.

mod output;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use linter::{Cert, RuleSource, Severity, default_registry};

/// Output format for the lint report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable text grouped by rule source.
    Text,
    /// Nested JSON, one object per lint outcome.
    Json,
}

/// `--min-severity` levels, mirroring [`linter::Severity`].
///
/// A dedicated CLI enum keeps the on-wire flag vocabulary owned by the binary
/// and decoupled from the library type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum MinSeverity {
    /// Show everything (notice and above).
    Notice,
    /// Show warn and above.
    Warn,
    /// Show error and above.
    Error,
    /// Show fatal only.
    Fatal,
}

impl From<MinSeverity> for Severity {
    fn from(value: MinSeverity) -> Self {
        match value {
            MinSeverity::Notice => Severity::Notice,
            MinSeverity::Warn => Severity::Warn,
            MinSeverity::Error => Severity::Error,
            MinSeverity::Fatal => Severity::Fatal,
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

    /// Comma-separated lint sources to run: `rfc5280`, `cabf_br`, `hygiene`.
    ///
    /// Defaults to all sources when omitted.
    #[arg(long)]
    source: Option<String>,

    /// Only surface findings at or above this severity.
    #[arg(long, value_enum, default_value_t = MinSeverity::Notice)]
    min_severity: MinSeverity,
}

/// The full set of sources, used when `--source` is omitted.
const ALL_SOURCES: [RuleSource; 3] = [RuleSource::Rfc5280, RuleSource::CabfBr, RuleSource::Hygiene];

/// Parses a single `--source` token into a [`RuleSource`].
fn parse_source_token(token: &str) -> Result<RuleSource> {
    match token.trim() {
        "rfc5280" => Ok(RuleSource::Rfc5280),
        "cabf_br" => Ok(RuleSource::CabfBr),
        "hygiene" => Ok(RuleSource::Hygiene),
        other => bail!("unknown --source value '{other}' (expected rfc5280, cabf_br, or hygiene)"),
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

fn main() -> Result<()> {
    let args = Args::parse();
    run(&args)
}

/// Loads the certificate, runs the selected lints, and prints the report.
///
/// # Errors
///
/// Returns an error if the file cannot be read, its contents cannot be parsed as
/// one or more X.509 certificates, the `--source` value is invalid, or the
/// report cannot be serialized.
fn run(args: &Args) -> Result<()> {
    let sources = select_sources(args.source.as_deref())?;

    let leaf = load_leaf(&args.path)?;

    let registry = default_registry();
    let outcomes = registry.run_filtered(&leaf, &sources);

    let min: Severity = args.min_severity.into();
    let report = match args.format {
        Format::Text => output::render_text(&outcomes, min),
        Format::Json => {
            let mut json = output::render_json(&outcomes, min)?;
            json.push('\n');
            json
        }
    };

    print!("{report}");
    Ok(())
}

/// Reads `path` and returns the leaf (first) certificate.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed, or if it contains no
/// certificates.
fn load_leaf(path: &Path) -> Result<Cert> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read certificate file: {}", path.display()))?;

    let mut certs = Cert::load(&bytes)
        .with_context(|| format!("failed to parse certificate(s) from: {}", path.display()))?;

    if certs.is_empty() {
        bail!("no certificates found in the input file");
    }
    // The leaf is the first certificate in the input. Remove and return it to
    // hand back an owned `Cert` without cloning.
    Ok(certs.remove(0))
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

    mod min_severity_conversion {
        use super::*;

        #[test]
        fn maps_each_variant() {
            assert_eq!(Severity::from(MinSeverity::Notice), Severity::Notice);
            assert_eq!(Severity::from(MinSeverity::Warn), Severity::Warn);
            assert_eq!(Severity::from(MinSeverity::Error), Severity::Error);
            assert_eq!(Severity::from(MinSeverity::Fatal), Severity::Fatal);
        }
    }
}
