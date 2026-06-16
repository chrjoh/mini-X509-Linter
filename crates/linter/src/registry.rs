//! The lint [`Registry`] and the run engine.
//!
//! A [`Registry`] is the single place every lint is wired up. Its
//! [`run`](Registry::run) method is the engine: it asks each lint whether it
//! [`applies`](crate::Lint::applies), calls [`check`](crate::Lint::check) only
//! for the ones that do, and collects one [`LintOutcome`] per lint considered.
//!
//! The engine **never short-circuits**: every lint runs regardless of what any
//! other lint reported, so a single [`run`](Registry::run) yields the complete
//! picture. [`run_filtered`](Registry::run_filtered) restricts which lints run
//! by their [`RuleSource`] *before* executing them, so excluded lints are never
//! evaluated.

use crate::cert::Cert;
use crate::{Applicability, Lint, LintOutcome, RuleSource};

/// A collection of lints and the engine that runs them against a [`Cert`].
///
/// Build the standard set with [`default_registry`] (or
/// [`Registry::default`]), or assemble a custom set with [`Registry::new`] and
/// [`Registry::with_lints`].
pub struct Registry {
    lints: Vec<Box<dyn Lint>>,
}

impl Registry {
    /// Creates an empty registry with no lints.
    pub fn new() -> Registry {
        Registry { lints: Vec::new() }
    }

    /// Creates a registry from an explicit set of lints.
    ///
    /// This is the building block the [`default_registry`] constructor uses and
    /// is handy for tests that want a known, minimal set of lints.
    pub fn with_lints(lints: Vec<Box<dyn Lint>>) -> Registry {
        Registry { lints }
    }

    /// The number of lints registered.
    pub fn len(&self) -> usize {
        self.lints.len()
    }

    /// Whether the registry holds no lints.
    pub fn is_empty(&self) -> bool {
        self.lints.is_empty()
    }

    /// Runs every registered lint against `cert`, returning one
    /// [`LintOutcome`] per lint.
    ///
    /// For each lint:
    ///
    /// - [`applies`](crate::Lint::applies) is called first. If it returns
    ///   [`Applicability::NotApplicable`], an outcome with that applicability and
    ///   an empty `findings` list is recorded **without** calling
    ///   [`check`](crate::Lint::check).
    /// - If it returns [`Applicability::Applies`],
    ///   [`check`](crate::Lint::check) is called and its findings are stored
    ///   (an empty list means the certificate passed that lint).
    ///
    /// The engine **never short-circuits**: every lint in the registry is
    /// visited in order, no matter what previous lints returned.
    pub fn run(&self, cert: &Cert) -> Vec<LintOutcome> {
        let mut outcomes = Vec::with_capacity(self.lints.len());
        // INVARIANT: no short-circuit — visit every lint regardless of any
        // previous outcome. Nothing in this loop returns early.
        for lint in &self.lints {
            outcomes.push(evaluate(lint.as_ref(), cert));
        }
        outcomes
    }

    /// Runs only the lints whose [`RuleSource`] is in `sources`, returning one
    /// [`LintOutcome`] per *selected* lint.
    ///
    /// Filtering happens *before* execution: lints whose source is not in
    /// `sources` are never asked [`applies`](crate::Lint::applies) and never
    /// have [`check`](crate::Lint::check) called. As with [`run`](Registry::run),
    /// the engine never short-circuits across the selected lints.
    ///
    /// An empty `sources` slice selects no lints and yields an empty result.
    pub fn run_filtered(&self, cert: &Cert, sources: &[RuleSource]) -> Vec<LintOutcome> {
        let mut outcomes = Vec::new();
        // INVARIANT: no short-circuit — visit every selected lint regardless of
        // any previous outcome.
        for lint in &self.lints {
            if !sources.contains(&lint.source()) {
                continue;
            }
            outcomes.push(evaluate(lint.as_ref(), cert));
        }
        outcomes
    }
}

impl Default for Registry {
    fn default() -> Self {
        default_registry()
    }
}

/// Evaluates a single lint against `cert`, honouring the applicability gate.
///
/// Kept as a free function so both [`Registry::run`] and
/// [`Registry::run_filtered`] share exactly one definition of "how to run one
/// lint" — including the guarantee that `check` is skipped for
/// [`Applicability::NotApplicable`].
fn evaluate(lint: &dyn Lint, cert: &Cert) -> LintOutcome {
    let applicability = lint.applies(cert);
    let findings = match applicability {
        Applicability::Applies => lint.check(cert),
        // Do NOT call check() when the lint does not apply.
        Applicability::NotApplicable => Vec::new(),
    };
    LintOutcome {
        lint_id: lint.id(),
        source: lint.source(),
        applicability,
        findings,
    }
}

/// Builds the default registry containing every lint shipped today.
///
/// This is the single, obvious place lints are wired up. Later features append
/// their lints here.
pub fn default_registry() -> Registry {
    Registry::with_lints(vec![
        // --- add new lints here ---
        Box::new(crate::lints::hygiene::NotExpired::new()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Finding, Severity};
    use std::cell::Cell;
    use std::rc::Rc;

    /// A self-signed certificate used purely to drive the engine; the stub lints
    /// below ignore its contents, so any valid certificate works. (Same fixture
    /// as the `not_expired` in-file test.)
    const SAMPLE_PEM: &[u8] = b"\
-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUeWeLHyFvBAMODfZXwoesZL4xC7AwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMZXhwaXJlZC10ZXN0MB4XDTEwMDEwMTAwMDAwMFoXDTEx
MDEwMTAwMDAwMFowFzEVMBMGA1UEAwwMZXhwaXJlZC10ZXN0MIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAorzvJg1NvSFsWEZlbkpddK1Urk4NqrYIV51c
jd1EBowjH5e0SoaWw0fvHSGgOVP9ocar2jDQpEd9lJs2Iyz4hroJg5rtWdPGzEPc
uGWh0FYwcOeSEga7AzkzDP9Doyx0+JtBPHOiLucXLZeyzgrZeWAwjObPYuKV+i/A
VTnJlcOzQzTsX/wkm1rBoq9dsRdB1WCrEkq3Hd6D0Dnf5OtdNmNNa9SE6iyHzK7T
pseONr1FgDTBflQhFWHXwrbD5lwQJCbkED4zdXzS1TpRJk02+xeISnO3ogRJc7Pm
/Ycu+BSTZDhbcRMK9tjVegJ4Yz2OVssEPyKkKEBkDlw6z73FQQIDAQABo1MwUTAd
BgNVHQ4EFgQU6C8tTXG3VaJuOU11s8TTPtDlP8swHwYDVR0jBBgwFoAU6C8tTXG3
VaJuOU11s8TTPtDlP8swDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEAbEioK7JL38AKQqgK3T5MWuP5GmkODkF5Puk0t7tKhCafS1AqtQT3mwZR+ZQG
tlzg9wk9wLGZO/OWe5CWvqHMlSLQAOyEt2jc4TrJwZix+aHLUcHGxJOXub1k4U3m
H1l7q7EFKBVB6HnNkiTCNFFUWuVp2WzTO+XdSU1Rfxp2wOTzDsVxaf1U+hRj5aN9
dsLIaxsCQ3FTB9YPiQJmfTNDbH7P/Aj35OiZr535/0ZwsXQGJkUqbT7cCFKaSJU1
ZCXRdlqcDgdCY7FZVJ55WFUgrwV+0oIuaAKW1YT/HipSivUfisQK5XfLV3GI50/3
Ik5TwbV8Htq6fEgstPgecyX8Pw==
-----END CERTIFICATE-----
";

    fn sample_cert() -> Cert {
        let mut certs = Cert::from_pem(SAMPLE_PEM).expect("fixture must parse");
        certs.pop().expect("fixture must contain one cert")
    }

    /// A stub lint that always applies and emits a fixed set of findings.
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

    /// A stub lint that reports `NotApplicable`. Its `check` flips a shared flag
    /// so a test can assert the engine never called it. The flag is shared via
    /// `Rc` because `Box<dyn Lint>` requires a `'static` lint (no borrows).
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
            // Sentinel: if the engine ever calls this, the test fails.
            self.check_called.set(true);
            vec![Finding {
                severity: Severity::Fatal,
                message: "check() must not be called for NotApplicable".to_string(),
            }]
        }
    }

    fn finding(message: &str) -> Finding {
        Finding {
            severity: Severity::Warn,
            message: message.to_string(),
        }
    }

    mod run {
        use super::*;

        #[test]
        fn returns_one_outcome_per_lint() {
            // Setup
            let registry = Registry::with_lints(vec![
                Box::new(AlwaysFinds {
                    id: "a",
                    source: RuleSource::Hygiene,
                    findings: vec![],
                }),
                Box::new(AlwaysFinds {
                    id: "b",
                    source: RuleSource::Rfc5280,
                    findings: vec![],
                }),
            ]);
            let cert = sample_cert();

            // Invoke
            let outcomes = registry.run(&cert);

            // Expect
            assert_eq!(outcomes.len(), 2);
            assert_eq!(outcomes[0].lint_id, "a");
            assert_eq!(outcomes[1].lint_id, "b");
        }

        #[test]
        fn does_not_short_circuit_when_a_lint_finds_problems() {
            // Setup: first lint reports findings; the engine must still run the
            // rest and collect everything.
            let registry = Registry::with_lints(vec![
                Box::new(AlwaysFinds {
                    id: "first",
                    source: RuleSource::Hygiene,
                    findings: vec![finding("first problem")],
                }),
                Box::new(AlwaysFinds {
                    id: "second",
                    source: RuleSource::Hygiene,
                    findings: vec![finding("second problem")],
                }),
                Box::new(AlwaysFinds {
                    id: "third",
                    source: RuleSource::Hygiene,
                    findings: vec![finding("third problem")],
                }),
            ]);
            let cert = sample_cert();

            // Invoke
            let outcomes = registry.run(&cert);

            // Expect: all three ran, each with its own finding.
            assert_eq!(outcomes.len(), 3);
            assert_eq!(outcomes[0].findings, vec![finding("first problem")]);
            assert_eq!(outcomes[1].findings, vec![finding("second problem")]);
            assert_eq!(outcomes[2].findings, vec![finding("third problem")]);
        }

        #[test]
        fn records_not_applicable_without_calling_check() {
            // Setup
            let called = Rc::new(Cell::new(false));
            let registry = Registry::with_lints(vec![Box::new(NeverApplies {
                id: "skip_me",
                source: RuleSource::Hygiene,
                check_called: Rc::clone(&called),
            })]);
            let cert = sample_cert();

            // Invoke
            let outcomes = registry.run(&cert);

            // Expect: outcome recorded as NotApplicable with empty findings, and
            // check() was never called.
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].applicability, Applicability::NotApplicable);
            assert!(outcomes[0].findings.is_empty());
            assert!(
                !called.get(),
                "check() must not be called for NotApplicable"
            );
        }

        #[test]
        fn keeps_running_applicable_lints_after_a_not_applicable_one() {
            // Setup: NotApplicable in the middle must not stop the later lint.
            let called = Rc::new(Cell::new(false));
            let registry = Registry::with_lints(vec![
                Box::new(AlwaysFinds {
                    id: "before",
                    source: RuleSource::Hygiene,
                    findings: vec![finding("before")],
                }),
                Box::new(NeverApplies {
                    id: "middle",
                    source: RuleSource::Hygiene,
                    check_called: Rc::clone(&called),
                }),
                Box::new(AlwaysFinds {
                    id: "after",
                    source: RuleSource::Hygiene,
                    findings: vec![finding("after")],
                }),
            ]);
            let cert = sample_cert();

            // Invoke
            let outcomes = registry.run(&cert);

            // Expect
            assert_eq!(outcomes.len(), 3);
            assert_eq!(outcomes[0].findings, vec![finding("before")]);
            assert_eq!(outcomes[1].applicability, Applicability::NotApplicable);
            assert_eq!(outcomes[2].findings, vec![finding("after")]);
            assert!(!called.get());
        }
    }

    mod run_filtered {
        use super::*;

        fn three_source_registry() -> Registry {
            Registry::with_lints(vec![
                Box::new(AlwaysFinds {
                    id: "hygiene_lint",
                    source: RuleSource::Hygiene,
                    findings: vec![],
                }),
                Box::new(AlwaysFinds {
                    id: "rfc_lint",
                    source: RuleSource::Rfc5280,
                    findings: vec![],
                }),
                Box::new(AlwaysFinds {
                    id: "cabf_lint",
                    source: RuleSource::CabfBr,
                    findings: vec![],
                }),
            ])
        }

        #[test]
        fn includes_only_selected_sources() {
            // Setup
            let registry = three_source_registry();
            let cert = sample_cert();

            // Invoke: only RFC 5280 lints.
            let outcomes = registry.run_filtered(&cert, &[RuleSource::Rfc5280]);

            // Expect
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].lint_id, "rfc_lint");
            assert_eq!(outcomes[0].source, RuleSource::Rfc5280);
        }

        #[test]
        fn includes_multiple_selected_sources() {
            // Setup
            let registry = three_source_registry();
            let cert = sample_cert();

            // Invoke
            let outcomes = registry.run_filtered(&cert, &[RuleSource::Hygiene, RuleSource::CabfBr]);

            // Expect: both selected sources present, the unselected one excluded.
            let ids: Vec<&str> = outcomes.iter().map(|o| o.lint_id).collect();
            assert_eq!(ids, vec!["hygiene_lint", "cabf_lint"]);
        }

        #[test]
        fn excludes_lints_whose_check_is_never_run() {
            // Setup: a NotApplicable stub in an excluded source must not even be
            // asked — its check() flag stays false either way, but more
            // importantly it must not appear in the output.
            let called = Rc::new(Cell::new(false));
            let registry = Registry::with_lints(vec![
                Box::new(AlwaysFinds {
                    id: "hygiene_lint",
                    source: RuleSource::Hygiene,
                    findings: vec![finding("hygiene")],
                }),
                Box::new(NeverApplies {
                    id: "rfc_lint",
                    source: RuleSource::Rfc5280,
                    check_called: Rc::clone(&called),
                }),
            ]);
            let cert = sample_cert();

            // Invoke: select only Hygiene.
            let outcomes = registry.run_filtered(&cert, &[RuleSource::Hygiene]);

            // Expect: the RFC lint is excluded entirely.
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].lint_id, "hygiene_lint");
            assert!(!called.get());
        }

        #[test]
        fn empty_sources_selects_nothing() {
            // Setup
            let registry = three_source_registry();
            let cert = sample_cert();

            // Invoke
            let outcomes = registry.run_filtered(&cert, &[]);

            // Expect
            assert!(outcomes.is_empty());
        }
    }

    mod default_registry {
        use super::*;

        #[test]
        fn contains_the_known_lints() {
            // Setup & Invoke
            let registry = default_registry();
            let cert = sample_cert();
            let outcomes = registry.run(&cert);

            // Expect: the one shipped lint runs and is reported.
            assert!(!registry.is_empty());
            assert!(outcomes.iter().any(|o| o.lint_id == "hygiene_not_expired"));
        }

        #[test]
        fn default_trait_matches_default_registry() {
            assert_eq!(Registry::default().len(), default_registry().len());
        }
    }
}
