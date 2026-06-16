//! The `mini-x509-lint` binary.
//!
//! A thin end-to-end shell over the `linter` crate: it reads a certificate file,
//! loads it via the [`Cert`] facade (auto-detecting PEM vs DER), runs the single
//! `hygiene_not_expired` lint against the leaf certificate, and prints the
//! findings as plain text.
//!
//! This is deliberately minimal (Milestone 1): the lint set is a hard-coded list
//! of one. A lint registry and richer flags arrive in later features.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use linter::lints::hygiene::NotExpired;
use linter::{Applicability, Cert, Finding, Lint};

/// Command-line arguments for `mini-x509-lint`.
#[derive(Debug, Parser)]
#[command(
    name = "mini-x509-lint",
    about = "Lint an X.509 certificate (PEM or DER)."
)]
struct Args {
    /// Path to a certificate file (PEM or DER; format is auto-detected).
    path: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    run(&args.path)
}

/// Loads the certificate at `path`, runs the lints, and prints findings.
///
/// # Errors
///
/// Returns an error if the file cannot be read or if its contents cannot be
/// parsed as one or more X.509 certificates.
fn run(path: &std::path::Path) -> Result<()> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read certificate file: {}", path.display()))?;

    let certs = Cert::load(&bytes)
        .with_context(|| format!("failed to parse certificate(s) from: {}", path.display()))?;

    // The leaf is the first certificate in the input. `Cert::load` guarantees a
    // non-empty vec on success, but we avoid `unwrap`/`expect` defensively.
    let leaf = certs
        .first()
        .context("no certificates found in the input file")?;

    // Hard-coded list of one lint; the registry arrives in feature 02.
    let lints: Vec<Box<dyn Lint>> = vec![Box::new(NotExpired::new())];

    let mut findings: Vec<(&'static str, Finding)> = Vec::new();
    for lint in &lints {
        if lint.applies(leaf) == Applicability::Applies {
            for finding in lint.check(leaf) {
                findings.push((lint.id(), finding));
            }
        }
    }

    if findings.is_empty() {
        println!("OK: no findings");
    } else {
        for (lint_id, finding) in &findings {
            println!("{:?} [{lint_id}] {}", finding.severity, finding.message);
        }
    }

    Ok(())
}
