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
//!   `rfc5280,pqc,cabf_br,cabf_ev,cabf_cs,cabf_smime,hygiene` (default: all
//!   sources).
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
//! - `--purpose <auto|tls-server|code-signing|smime|generic>` — scopes which
//!   lint **sources** apply based on the certificate's intended purpose (default
//!   `auto`). It maps to a [`linter::CertPurpose`] whose allowed-source set is
//!   intersected with `--source`; the engine then runs only the resulting
//!   sources. `auto` resolves per certificate from its EKU (codeSigning →
//!   code-signing, else serverAuth → tls-server, else emailProtection → smime,
//!   else generic).
//!
//! Exit code: `0` when no surfaced finding reaches `--fail-on`; `1` when one
//! does. A load/parse/usage error exits non-zero via the process error path.

mod output;
#[cfg(feature = "fetch")]
mod save;

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
/// `client` is reserved as a planned future value but is **not implemented**:
/// until a dedicated rule set exists it would behave like
/// [`generic`](CliPurpose::Generic). Adding it later is purely additive (no
/// rename of the shipped variants). `smime` is now shipped (feature 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliPurpose {
    /// Resolve per certificate from its EKU: codeSigning → code-signing, else
    /// serverAuth → tls-server, else emailProtection → smime, otherwise →
    /// generic.
    Auto,
    /// A publicly-trusted TLS server certificate: standard, hygiene, and the
    /// TLS-server-specific `cabf_br` set.
    TlsServer,
    /// A code-signing certificate: standard, hygiene, and the code-signing
    /// `cabf_cs` set.
    CodeSigning,
    /// An S/MIME (email-protection) certificate: standard, hygiene, and the
    /// S/MIME-specific `cabf_smime` set.
    Smime,
    /// A certificate with no TLS-server, code-signing, or S/MIME profile:
    /// `rfc5280` + `hygiene` only, skipping the `cabf_br` / `cabf_cs` /
    /// `cabf_smime` sets.
    Generic,
}

impl From<CliPurpose> for CertPurpose {
    fn from(value: CliPurpose) -> Self {
        match value {
            CliPurpose::Auto => CertPurpose::Auto,
            CliPurpose::TlsServer => CertPurpose::TlsServer,
            CliPurpose::CodeSigning => CertPurpose::CodeSigning,
            CliPurpose::Smime => CertPurpose::Smime,
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
    ///
    /// Mutually exclusive with `--from-host`. Exactly one input source must be
    /// given.
    path: Option<PathBuf>,

    /// Fetch the certificate from a live host over TLS instead of reading a
    /// file (`host[:port]`, default port 443). Only the leaf is linted; the
    /// presented intermediates and the chain verification verdict are shown.
    ///
    /// Mutually exclusive with the positional `<PATH>`.
    #[cfg(feature = "fetch")]
    #[arg(long, value_name = "HOST")]
    from_host: Option<String>,

    /// Override/supply the SNI sent in the TLS handshake. Required when
    /// `--from-host` is an IP address (SNI cannot be derived from an IP); for a
    /// hostname it overrides the SNI derived from the host.
    #[cfg(feature = "fetch")]
    #[arg(long, value_name = "NAME")]
    sni: Option<String>,

    /// Connection + handshake timeout in seconds for `--from-host`.
    #[cfg(feature = "fetch")]
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    timeout: u64,

    /// Refuse to connect to private / loopback / link-local addresses with
    /// `--from-host` (SSRF guard). Off by default: this is a local user-run CLI
    /// intended for validating your own/internal/localhost hosts.
    #[cfg(feature = "fetch")]
    #[arg(long)]
    block_private: bool,

    /// Also write the full presented chain (leaf + intermediates, in
    /// presentation order) to `<path>` as a PEM bundle. Only valid with
    /// `--from-host`. Refuses to overwrite an existing file unless `--force`.
    #[cfg(feature = "fetch")]
    #[arg(long, value_name = "PATH")]
    save: Option<PathBuf>,

    /// Allow `--save` to overwrite an existing file.
    #[cfg(feature = "fetch")]
    #[arg(long)]
    force: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Comma-separated lint sources to run: `rfc5280`, `pqc`, `cabf_br`,
    /// `cabf_ev`, `cabf_cs`, `cabf_smime`, `hygiene`.
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
const ALL_SOURCES: [RuleSource; 7] = [
    RuleSource::Rfc5280,
    RuleSource::Pqc,
    RuleSource::CabfBr,
    RuleSource::CabfEv,
    RuleSource::CabfCs,
    RuleSource::CabfSmime,
    RuleSource::Hygiene,
];

/// Process exit code returned when a surfaced finding reaches `--fail-on`.
const EXIT_FINDINGS: u8 = 1;

/// Parses a single `--source` token into a [`RuleSource`].
fn parse_source_token(token: &str) -> Result<RuleSource> {
    match token.trim() {
        "rfc5280" => Ok(RuleSource::Rfc5280),
        "pqc" => Ok(RuleSource::Pqc),
        "cabf_br" => Ok(RuleSource::CabfBr),
        "cabf_ev" => Ok(RuleSource::CabfEv),
        "cabf_cs" => Ok(RuleSource::CabfCs),
        "cabf_smime" => Ok(RuleSource::CabfSmime),
        "hygiene" => Ok(RuleSource::Hygiene),
        other => bail!(
            "unknown --source value '{other}' (expected rfc5280, pqc, cabf_br, cabf_ev, cabf_cs, cabf_smime, or hygiene)"
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
        CertPurpose::Smime => "smime",
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

    // The `--from-host` path is its own pipeline: fetch → save → lint leaf →
    // render chain + verdict + findings. It is gated entirely behind the
    // `fetch` feature; the file path below is unchanged.
    #[cfg(feature = "fetch")]
    if args.from_host.is_some() {
        return run_from_host(args, &selected, purpose, min, fail_on, verbosity);
    }

    // `--from-host`-only flags must not be used without `--from-host`.
    #[cfg(feature = "fetch")]
    {
        if args.save.is_some() {
            bail!("--save is only valid with --from-host");
        }
        if args.force {
            bail!("--force is only valid with --save (which requires --from-host)");
        }
    }

    let certs = load_input_certs(args)?;
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

/// The `--from-host` pipeline: validate the target, fetch the chain, optionally
/// save it, lint the leaf, and render the chain + verdict + findings.
///
/// Only the leaf is linted; the presented intermediates are display context.
///
/// # Errors
///
/// Returns an error if the input flags conflict, the target/SNI rules are not
/// met, the fetch (connect/handshake/timeout) fails, the optional `--save`
/// write fails, the leaf DER cannot be parsed, or the report cannot be
/// serialized.
#[cfg(feature = "fetch")]
fn run_from_host(
    args: &Args,
    selected: &[RuleSource],
    purpose: CertPurpose,
    min: Severity,
    fail_on: Severity,
    verbosity: Verbosity,
) -> Result<ExitCode> {
    use std::time::Duration;

    // `--from-host` and the positional `<PATH>` are mutually exclusive sources.
    if args.path.is_some() {
        bail!("--from-host and a positional <PATH> are mutually exclusive (choose one input)");
    }
    // `--force` is only meaningful alongside `--save`.
    if args.force && args.save.is_none() {
        bail!("--force is only valid with --save");
    }

    let Some(host) = args.from_host.as_deref() else {
        // Unreachable: callers gate on `from_host.is_some()`.
        bail!("--from-host requires a host value");
    };

    let target = fetch::Target::parse(host)
        .map_err(|e| anyhow::anyhow!("invalid --from-host target: {e}"))?;

    // SNI rules: hostname derives SNI by default; an IP requires an explicit
    // --sni. We surface a clear message up front (fetch_chain enforces it too).
    if let fetch::HostKind::Ip(_) = target.host()
        && args.sni.is_none()
    {
        bail!("--sni is required when --from-host is an IP address (SNI cannot be derived)");
    }

    // SSRF default: this is a local user-run CLI for validating your own /
    // internal / localhost hosts, so private addresses are ALLOWED by default.
    // `--block-private` opts into the SSRF guard.
    let block_private = args.block_private;

    let chain = fetch::fetch_chain(
        &target,
        args.sni.as_deref(),
        Duration::from_secs(args.timeout),
        block_private,
    )
    .map_err(|e| anyhow::anyhow!("failed to fetch certificate from host: {e}"))?;

    // Save sits between capture and lint and does not gate linting. It runs
    // regardless of the verification verdict.
    if let Some(save_path) = args.save.as_deref() {
        save::save_chain(
            save_path,
            &chain.leaf_der,
            &chain.intermediates_der,
            args.force,
        )?;
        // Confirmation on stderr so it never pollutes stdout golden output.
        eprintln!("saved presented chain to {}", save_path.display());
    }

    // Only the leaf is linted.
    let leaf = Cert::from_der(&chain.leaf_der)
        .context("failed to parse the leaf certificate presented by the host")?;
    let registry = default_registry();

    let header = build_purpose_header(args.purpose, purpose, &leaf);
    let effective = effective_sources(purpose, &leaf, selected);
    let outcomes = registry.run_filtered(&leaf, &effective);

    // Build the presented-chain display entries (leaf + intermediates).
    let entries = build_chain_entries(&leaf, &chain.intermediates_der);

    match args.format {
        Format::Text => {
            let mut report = output::render_chain_section_text(&entries, &chain.verdict);
            report.push_str(&output::render_text_opts(
                &outcomes,
                min,
                verbosity,
                Some(&header),
            ));
            print!("{report}");
        }
        Format::Json => {
            let outcomes_json = output::render_json(&outcomes, min)?;
            let outcomes_value: serde_json::Value = serde_json::from_str(&outcomes_json)
                .context("failed to re-parse leaf outcomes JSON")?;
            let section = output::chain_section_json(&entries, &chain.verdict);
            let document = serde_json::json!({
                "presented_chain": section["presented_chain"],
                "verification": section["verification"],
                "outcomes": outcomes_value,
            });
            let json = serde_json::to_string_pretty(&document)
                .context("failed to serialize --from-host report to JSON")?;
            println!("{json}");
        }
    }

    let counts = output::severity_counts(&outcomes, min);
    Ok(exit_code(counts, fail_on))
}

/// Builds the presented-chain display entries: the leaf plus each intermediate,
/// each with a best-effort subject line.
///
/// Intermediate DER that fails to parse is still listed (with a placeholder
/// subject) so the displayed chain mirrors what the server actually presented.
#[cfg(feature = "fetch")]
fn build_chain_entries(leaf: &Cert, intermediates_der: &[Vec<u8>]) -> Vec<output::ChainEntry> {
    let mut entries = Vec::with_capacity(1 + intermediates_der.len());
    entries.push(output::ChainEntry {
        label: "Certificate 1 (leaf)".to_string(),
        subject: subject_description(leaf),
    });
    for (idx, der) in intermediates_der.iter().enumerate() {
        let subject = match Cert::from_der(der) {
            Ok(cert) => subject_description(&cert),
            Err(_) => "(unparseable certificate)".to_string(),
        };
        entries.push(output::ChainEntry {
            label: format!("Certificate {}", idx + 2),
            subject,
        });
    }
    entries
}

/// A best-effort, deterministic subject description for chain display.
///
/// Uses the subject common name(s) when present, falling back to a placeholder.
#[cfg(feature = "fetch")]
fn subject_description(cert: &Cert) -> String {
    match cert.subject_common_names() {
        Ok(cns) if !cns.is_empty() => format!("CN={}", cns.join(", ")),
        _ => "(no common name)".to_string(),
    }
}

/// Resolves the file input source and loads its certificate(s).
///
/// Enforces input-source rules shared with `--from-host`:
///
/// - With the `fetch` feature, a positional `<PATH>` and `--from-host` are
///   mutually exclusive, and at least one must be given. (The `--from-host`
///   branch is handled before this is reached, so here `from_host` must be
///   absent.)
/// - Without the `fetch` feature, only `<PATH>` exists and is required.
///
/// # Errors
///
/// Returns an error if no input was given, if both a path and `--from-host`
/// were supplied, or if the file cannot be read / parsed.
fn load_input_certs(args: &Args) -> Result<Vec<Cert>> {
    let Some(path) = args.path.as_deref() else {
        #[cfg(feature = "fetch")]
        {
            bail!("no input given (provide a <PATH> or --from-host <host>)");
        }
        #[cfg(not(feature = "fetch"))]
        {
            bail!(
                "no input given (provide a <PATH>; this build has no --from-host support — rebuild with --features fetch)"
            );
        }
    };
    load_certs(path)
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
        fn parses_cabf_smime_source() {
            let sources = select_sources(Some("cabf_smime")).unwrap();
            assert_eq!(sources, vec![RuleSource::CabfSmime]);
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
            assert_eq!(CertPurpose::from(CliPurpose::Smime), CertPurpose::Smime);
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
                vec![
                    RuleSource::Rfc5280,
                    RuleSource::Pqc,
                    RuleSource::Hygiene,
                    RuleSource::CabfBr,
                    RuleSource::CabfEv
                ]
            );
        }

        #[test]
        fn generic_drops_cabf_br() {
            let cert = good_cert();
            let eff = effective_sources(CertPurpose::Generic, &cert, &ALL_SOURCES);
            assert!(!eff.contains(&RuleSource::CabfBr));
            assert_eq!(
                eff,
                vec![RuleSource::Rfc5280, RuleSource::Pqc, RuleSource::Hygiene]
            );
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
