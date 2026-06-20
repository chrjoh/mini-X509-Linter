//! Integration tests for the lint engine ([`Registry`]).
//!
//! These exercise the engine through the public crate API only, driving it with
//! small synthetic stub lints defined in this file. They pin the engine's three
//! load-bearing guarantees:
//!
//! 1. **No short-circuit** — every applicable lint runs and every finding is
//!    collected, even when an earlier lint emits `Error`/`Fatal` findings.
//! 2. **The applies-gate** — `check()` is never called for a lint that reports
//!    [`Applicability::NotApplicable`] (proven with an interior-mutability
//!    sentinel that the test asserts was never flipped).
//! 3. **Source filtering** — [`Registry::run_filtered`] runs only the selected
//!    sources, leaves the surviving outcomes complete, and treats an empty slice
//!    as "select nothing".
//!
//! It also confirms the shipped [`default_registry`] actually wires up the
//! `hygiene_not_expired` lint and that running it over the expired fixture yields
//! a `Warn` finding (matched by a stable message prefix so the assertion does not
//! depend on the volatile `now is <unix time>` suffix).
//!
//! The serde/JSON wire shape is intentionally *not* asserted here (it would need
//! a `serde_json` linter dev-dependency, out of this task's file scope); it is
//! proven end-to-end in `crates/cli/tests/output.rs` instead. See the note at the
//! end of this file.

use std::cell::Cell;
use std::rc::Rc;

use linter::{
    Applicability, Cert, Finding, Lint, Registry, RuleSource, Severity, default_registry_with_now,
};

/// A reference "now" inside every currently-valid fixture window (2026-12-01 in
/// Unix seconds) and after `expired.pem`'s past `notAfter` (2024-06-01). Pinning
/// the clock for full-registry / hygiene-inclusive runs makes them deterministic
/// regardless of the real wall clock — without this, leaf fixtures would trip
/// `hygiene_not_expired` once the real date passes their `notAfter`.
const TEST_NOW: i64 = 1_796_083_200;

// `include_bytes!` resolves relative to this source file
// (crates/linter/tests/registry.rs); `../../../testdata` reaches the
// workspace-root `testdata/` directory.
const EXPIRED_PEM: &[u8] = include_bytes!("../../../testdata/expired.pem");

/// The `notAfter` of `testdata/expired.pem` in Unix seconds (2024-06-01).
///
/// Feature 05 reshaped `expired.pem` to a BR-compliant-but-past leaf with a
/// `2024-01-01 -> 2024-06-01` window (so it isolates ONLY `hygiene_not_expired`
/// under broad BR scoping); `notAfter` is therefore `1_717_200_000` rather than
/// the old `1_293_840_000` (2011-01-01).
///
/// The full expiry message embeds the *current* time (`now is <unix time>`),
/// which changes every run, so tests match only this stable prefix.
const EXPIRED_NOT_AFTER: i64 = 1_717_200_000;

/// Loads the single leaf certificate from a PEM fixture; `unwrap` surfaces the
/// `CertError` if the fixture is malformed.
fn load_leaf(pem: &[u8]) -> Cert {
    let mut certs = Cert::load(pem).unwrap();
    certs.remove(0)
}

/// A stub lint that always [`Applies`](Applicability::Applies) and emits a fixed
/// set of findings on every `check`.
struct AlwaysFinds {
    id: &'static str,
    source: RuleSource,
    findings: Vec<Finding>,
}

impl Lint for AlwaysFinds {
    fn id(&self) -> &'static str {
        self.id
    }
    fn source(&self) -> RuleSource {
        self.source
    }
    fn applies(&self, _cert: &Cert) -> Applicability {
        Applicability::Applies
    }
    fn check(&self, _cert: &Cert) -> Vec<Finding> {
        self.findings.clone()
    }
}

/// A stub lint that reports [`NotApplicable`](Applicability::NotApplicable).
///
/// Its `check` flips a shared `Rc<Cell<bool>>` sentinel; a test asserts the flag
/// is never set, proving the engine respected the applies-gate. `Rc` is used
/// because `Box<dyn Lint>` requires a `'static` lint (no borrows of test locals).
struct NeverApplies {
    id: &'static str,
    source: RuleSource,
    check_called: Rc<Cell<bool>>,
}

impl Lint for NeverApplies {
    fn id(&self) -> &'static str {
        self.id
    }
    fn source(&self) -> RuleSource {
        self.source
    }
    fn applies(&self, _cert: &Cert) -> Applicability {
        Applicability::NotApplicable
    }
    fn check(&self, _cert: &Cert) -> Vec<Finding> {
        // Sentinel: any call here means the engine violated the applies-gate.
        self.check_called.set(true);
        vec![Finding {
            severity: Severity::Fatal,
            message: "check() must not be called for NotApplicable".to_string(),
        }]
    }
}

/// Builds a finding at the given severity with a short message.
fn finding(severity: Severity, message: &str) -> Finding {
    Finding {
        severity,
        message: message.to_string(),
    }
}

mod run {
    use super::*;

    /// (a) No short-circuit: a high-severity finding in an early lint must not
    /// suppress later lints — all outcomes and findings are collected.
    #[test]
    fn collects_every_finding_without_short_circuiting_on_severity() {
        // Setup: the first lint emits Fatal, the second Error; neither may stop
        // the third (a Notice) from running.
        let registry = Registry::with_lints(vec![
            Box::new(AlwaysFinds {
                id: "fatal_first",
                source: RuleSource::Hygiene,
                findings: vec![finding(Severity::Fatal, "fatal problem")],
            }),
            Box::new(AlwaysFinds {
                id: "error_second",
                source: RuleSource::Hygiene,
                findings: vec![finding(Severity::Error, "error problem")],
            }),
            Box::new(AlwaysFinds {
                id: "notice_third",
                source: RuleSource::Hygiene,
                findings: vec![finding(Severity::Notice, "notice problem")],
            }),
        ]);
        let cert = load_leaf(EXPIRED_PEM);

        // Invoke.
        let outcomes = registry.run(&cert);

        // Find + Expect: all three lints produced an outcome, in registry order,
        // each carrying its own finding.
        assert_eq!(outcomes.len(), 3);
        assert_eq!(outcomes[0].lint_id, "fatal_first");
        assert_eq!(
            outcomes[0].findings,
            vec![finding(Severity::Fatal, "fatal problem")]
        );
        assert_eq!(outcomes[1].lint_id, "error_second");
        assert_eq!(
            outcomes[1].findings,
            vec![finding(Severity::Error, "error problem")]
        );
        assert_eq!(outcomes[2].lint_id, "notice_third");
        assert_eq!(
            outcomes[2].findings,
            vec![finding(Severity::Notice, "notice problem")]
        );
    }

    /// Every lint considered yields exactly one outcome with the correct
    /// applicability, regardless of whether it found anything.
    #[test]
    fn yields_one_outcome_per_lint_with_correct_applicability() {
        // Setup
        let called = Rc::new(Cell::new(false));
        let registry = Registry::with_lints(vec![
            Box::new(AlwaysFinds {
                id: "applies_clean",
                source: RuleSource::Rfc5280,
                findings: vec![],
            }),
            Box::new(NeverApplies {
                id: "skipped",
                source: RuleSource::Hygiene,
                check_called: Rc::clone(&called),
            }),
        ]);
        let cert = load_leaf(EXPIRED_PEM);

        // Invoke
        let outcomes = registry.run(&cert);

        // Find + Expect
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].applicability, Applicability::Applies);
        assert_eq!(outcomes[1].applicability, Applicability::NotApplicable);
    }

    /// (b) The applies-gate: a NotApplicable lint is recorded with empty findings
    /// and its `check()` is never called (the sentinel stays false).
    #[test]
    fn records_not_applicable_without_calling_check() {
        // Setup
        let called = Rc::new(Cell::new(false));
        let registry = Registry::with_lints(vec![Box::new(NeverApplies {
            id: "skip_me",
            source: RuleSource::Hygiene,
            check_called: Rc::clone(&called),
        })]);
        let cert = load_leaf(EXPIRED_PEM);

        // Invoke
        let outcomes = registry.run(&cert);

        // Find + Expect
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].applicability, Applicability::NotApplicable);
        assert!(outcomes[0].findings.is_empty());
        assert!(
            !called.get(),
            "check() must not be called for a NotApplicable lint"
        );
    }

    /// A NotApplicable lint in the middle of the registry must not stop the lints
    /// after it from running.
    #[test]
    fn keeps_running_after_a_not_applicable_lint() {
        // Setup
        let called = Rc::new(Cell::new(false));
        let registry = Registry::with_lints(vec![
            Box::new(AlwaysFinds {
                id: "before",
                source: RuleSource::Hygiene,
                findings: vec![finding(Severity::Warn, "before")],
            }),
            Box::new(NeverApplies {
                id: "middle",
                source: RuleSource::Hygiene,
                check_called: Rc::clone(&called),
            }),
            Box::new(AlwaysFinds {
                id: "after",
                source: RuleSource::Hygiene,
                findings: vec![finding(Severity::Warn, "after")],
            }),
        ]);
        let cert = load_leaf(EXPIRED_PEM);

        // Invoke
        let outcomes = registry.run(&cert);

        // Find + Expect
        assert_eq!(outcomes.len(), 3);
        assert_eq!(
            outcomes[0].findings,
            vec![finding(Severity::Warn, "before")]
        );
        assert_eq!(outcomes[1].applicability, Applicability::NotApplicable);
        assert_eq!(outcomes[2].findings, vec![finding(Severity::Warn, "after")]);
        assert!(!called.get());
    }
}

mod run_filtered {
    use super::*;

    /// A registry with one lint per source, so filtering is easy to observe.
    fn three_source_registry() -> Registry {
        Registry::with_lints(vec![
            Box::new(AlwaysFinds {
                id: "hygiene_lint",
                source: RuleSource::Hygiene,
                findings: vec![finding(Severity::Warn, "h")],
            }),
            Box::new(AlwaysFinds {
                id: "rfc_lint",
                source: RuleSource::Rfc5280,
                findings: vec![finding(Severity::Warn, "r")],
            }),
            Box::new(AlwaysFinds {
                id: "cabf_lint",
                source: RuleSource::CabfBr,
                findings: vec![finding(Severity::Warn, "c")],
            }),
        ])
    }

    /// (c) Only the selected source runs; the surviving outcome is complete
    /// (carries its source and findings).
    #[test]
    fn includes_only_the_selected_source() {
        // Setup
        let registry = three_source_registry();
        let cert = load_leaf(EXPIRED_PEM);

        // Invoke: select only RFC 5280.
        let outcomes = registry.run_filtered(&cert, &[RuleSource::Rfc5280]);

        // Find + Expect: exactly the RFC lint, intact.
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].lint_id, "rfc_lint");
        assert_eq!(outcomes[0].source, RuleSource::Rfc5280);
        assert_eq!(outcomes[0].findings, vec![finding(Severity::Warn, "r")]);
    }

    /// Multiple selected sources are all included; an unselected one is excluded.
    #[test]
    fn includes_multiple_selected_sources_and_excludes_the_rest() {
        // Setup
        let registry = three_source_registry();
        let cert = load_leaf(EXPIRED_PEM);

        // Invoke
        let outcomes = registry.run_filtered(&cert, &[RuleSource::Hygiene, RuleSource::CabfBr]);

        // Find + Expect: both selected sources present, RFC excluded.
        let ids: Vec<&str> = outcomes.iter().map(|o| o.lint_id).collect();
        assert_eq!(ids, vec!["hygiene_lint", "cabf_lint"]);
    }

    /// An excluded NotApplicable lint must not even be asked, and must not appear
    /// in the result.
    #[test]
    fn never_evaluates_excluded_lints() {
        // Setup
        let called = Rc::new(Cell::new(false));
        let registry = Registry::with_lints(vec![
            Box::new(AlwaysFinds {
                id: "hygiene_lint",
                source: RuleSource::Hygiene,
                findings: vec![finding(Severity::Warn, "h")],
            }),
            Box::new(NeverApplies {
                id: "rfc_lint",
                source: RuleSource::Rfc5280,
                check_called: Rc::clone(&called),
            }),
        ]);
        let cert = load_leaf(EXPIRED_PEM);

        // Invoke: select only Hygiene.
        let outcomes = registry.run_filtered(&cert, &[RuleSource::Hygiene]);

        // Find + Expect: the RFC lint is excluded entirely and never touched.
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].lint_id, "hygiene_lint");
        assert!(!called.get());
    }

    /// An empty source slice selects nothing.
    #[test]
    fn empty_slice_selects_nothing() {
        // Setup
        let registry = three_source_registry();
        let cert = load_leaf(EXPIRED_PEM);

        // Invoke
        let outcomes = registry.run_filtered(&cert, &[]);

        // Find + Expect
        assert!(outcomes.is_empty());
    }
}

mod default_registry_engine {
    use super::*;

    /// The shipped default registry wires up the full lint set across all seven
    /// sources. The authoritative count is **70** (4 hygiene + 16 rfc5280 +
    /// 12 cabf_br + 9 cabf_ev + 8 cabf_cs + 12 cabf_smime + 9 pqc), the
    /// cross-feature reconciliation point with siblings 09/10/11/12. Feature 13
    /// added the five universal `pqc_*` *signature* lints; feature 16 added the
    /// four `pqc_mlkem_*` *key-establishment* lints (9 pqc total), verified
    /// against the in-file count in `src/registry.rs`. (Feature-16 part 3 added
    /// zero lints — it only extends `pqc_key_usage_consistency`.) Bump this (and
    /// the in-file count) when a new rule set lands.
    #[test]
    fn default_registry_has_the_expected_total_lint_count() {
        // Setup & Invoke
        let registry = default_registry_with_now(Some(TEST_NOW));
        let cert = load_leaf(EXPIRED_PEM);
        let outcomes = registry.run(&cert);

        // Expect: one outcome per registered lint, 82 in total (feature 17 added
        // twelve new cabf_br lints, growing the registry 70 -> 82).
        assert_eq!(registry.len(), 82);
        assert_eq!(outcomes.len(), 82);
    }

    /// (d) The shipped default registry contains the `hygiene_not_expired` lint,
    /// and running it over the expired fixture yields a `Warn` finding.
    ///
    /// The message is matched by its stable prefix only — the full message embeds
    /// the current Unix time (`now is ...`), which changes every run.
    #[test]
    fn default_registry_flags_expired_fixture_with_warn() {
        // Setup
        let registry = default_registry_with_now(Some(TEST_NOW));
        let cert = load_leaf(EXPIRED_PEM);

        // Invoke
        let outcomes = registry.run(&cert);

        // Find: the not_expired outcome.
        let outcome = outcomes
            .iter()
            .find(|o| o.lint_id == "hygiene_not_expired")
            .expect("default registry must contain the hygiene_not_expired lint");

        // Expect: applicable, with one Warn finding whose message starts with the
        // stable, time-independent prefix.
        assert_eq!(outcome.source, RuleSource::Hygiene);
        assert_eq!(outcome.applicability, Applicability::Applies);
        assert_eq!(outcome.findings.len(), 1);
        let only = &outcome.findings[0];
        assert_eq!(only.severity, Severity::Warn);
        let expected_prefix = format!("certificate expired: notAfter is {EXPIRED_NOT_AFTER}");
        assert!(
            only.message.starts_with(&expected_prefix),
            "expected message to start with {expected_prefix:?}, got {:?}",
            only.message
        );
    }

    /// Isolation guard for `expired.pem`: run over the FULL shipped registry it
    /// must produce NO Error/Fatal, and the ONLY expiry-related finding must be
    /// `hygiene_not_expired` (a Warn). This proves the expired fixture isolates
    /// exactly the `not_expired` rule end-to-end across rfc5280 + hygiene + cabf_br.
    ///
    /// Feature-17 reconciliation (documented, NO fixture regeneration): under broad
    /// BR scoping every non-CA leaf without a CertificatePolicies extension gains an
    /// additive `cabf_br_certificate_policies_present` Warn. expired.pem is such a
    /// leaf (only good.pem was regenerated to carry policies), so it now surfaces
    /// EXACTLY two Warns — its target `hygiene_not_expired` plus that one additive
    /// BR Warn — and still NO Error. The plan (Cascade-Management §B) explicitly
    /// predicts this additive Warn on expired.pem and mandates it is not regenerated.
    #[test]
    fn expired_fixture_isolates_only_the_not_expired_finding() {
        // Setup.
        let registry = default_registry_with_now(Some(TEST_NOW));
        let cert = load_leaf(EXPIRED_PEM);

        // Invoke.
        let outcomes = registry.run(&cert);

        // Find: every (lint_id, finding) pair across the whole registry.
        let all_findings: Vec<(&str, &Finding)> = outcomes
            .iter()
            .flat_map(|o| o.findings.iter().map(move |f| (o.lint_id, f)))
            .collect();

        // Expect: no Error/Fatal anywhere — expired.pem deviates only by expiry.
        assert!(
            all_findings
                .iter()
                .all(|(_, f)| f.severity < Severity::Error),
            "expired.pem must surface no Error/Fatal finding; got {all_findings:?}"
        );

        // Expect: exactly the two documented Warns (target expiry + additive BR
        // policies Warn), sorted by lint_id for a stable assertion.
        let mut warn_ids: Vec<&str> = all_findings
            .iter()
            .filter(|(_, f)| f.severity == Severity::Warn)
            .map(|(id, _)| *id)
            .collect();
        warn_ids.sort_unstable();
        assert_eq!(
            warn_ids,
            vec![
                "cabf_br_certificate_policies_present",
                "hygiene_not_expired"
            ],
            "expired.pem must surface exactly the expiry Warn plus the additive BR \
             policies Warn; got {all_findings:?}"
        );

        // The expiry finding itself is the not_expired lint at Warn.
        let expiry = all_findings
            .iter()
            .find(|(id, _)| *id == "hygiene_not_expired")
            .expect("expired.pem must trip hygiene_not_expired");
        assert_eq!(expiry.1.severity, Severity::Warn);
    }
}

// NOTE on the serde/JSON wire shape at the linter level:
//
// The task allows gating a serde-shape assertion behind `#[cfg(feature =
// "serde")]`, but serializing a `LintOutcome` to a concrete JSON string requires
// a serde *format* crate (`serde_json`) as a linter dev-dependency. The linter
// `Cargo.toml` is not in this task's `touches` list, so adding that dependency
// here is out of scope. The nested JSON wire shape (one object per outcome with
// snake_case `lint_id`/`source`/`applicability`/`findings`) is instead proven
// end-to-end by `crates/cli/tests/output.rs`, where `serde_json` is already a
// dependency of the `cli` crate.
