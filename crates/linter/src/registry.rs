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

/// The intended purpose of a certificate, used to scope which lint
/// [`RuleSource`]s apply to it.
///
/// The CA/Browser Forum Baseline Requirements ([`RuleSource::CabfBr`]) are
/// TLS-server-specific. Running them against a certificate that is not a TLS
/// server (for example a clientAuth- or keyEncipherment-only leaf) produces
/// false positives. A `CertPurpose` resolves to an allowed set of sources via
/// [`allowed_sources`](CertPurpose::allowed_sources); the engine then runs only
/// those sources through [`Registry::run_filtered`].
///
/// This is a *filtering* abstraction only: it changes which sources run, never
/// any lint's logic or [`applies`](crate::Lint::applies) rule.
///
/// # Future variants
///
/// `Client`, `Smime`, and `CodeSigning` are planned but **not yet implemented**.
/// Until dedicated rule sets exist for them they would resolve to the same set
/// as [`Generic`](CertPurpose::Generic) (RFC 5280 + Hygiene, skipping
/// `CabfBr`). They are documented here so that adding them later is purely
/// additive — no rename of the three shipped variants is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertPurpose {
    /// Resolve the purpose per certificate from a heuristic: if the leaf asserts
    /// the serverAuth EKU it is treated as [`TlsServer`](CertPurpose::TlsServer),
    /// otherwise as [`Generic`](CertPurpose::Generic). See
    /// [`allowed_sources`](CertPurpose::allowed_sources) for the fail-closed
    /// behaviour on a parse error.
    Auto,
    /// A publicly-trusted TLS server certificate: all current sources apply,
    /// including the TLS-server-specific [`RuleSource::CabfBr`] set. Forcing this
    /// purpose runs `CabfBr` even when the serverAuth EKU is absent.
    TlsServer,
    /// A certificate with no TLS-server profile: only the
    /// standard-and-hygiene sources apply ([`RuleSource::Rfc5280`] and
    /// [`RuleSource::Hygiene`]); the TLS-server-specific [`RuleSource::CabfBr`]
    /// set is skipped.
    Generic,
}

/// The allowed-source set for a TLS-server certificate: every current source.
///
/// Both [`CertPurpose::TlsServer`] and an `Auto` purpose that resolves to
/// tls-server return this exact set, so the two paths stay in sync. Ordering is
/// fixed (`Rfc5280, Hygiene, CabfBr`) for deterministic downstream output.
fn tls_server_sources() -> Vec<RuleSource> {
    vec![RuleSource::Rfc5280, RuleSource::Hygiene, RuleSource::CabfBr]
}

/// The allowed-source set for a non-TLS-server certificate: standard and
/// hygiene only, skipping the TLS-server-specific [`RuleSource::CabfBr`].
///
/// Both [`CertPurpose::Generic`] and an `Auto` purpose that resolves to generic
/// (including the fail-closed error path) return this exact set. Ordering is
/// fixed (`Rfc5280, Hygiene`) for deterministic downstream output.
fn generic_sources() -> Vec<RuleSource> {
    vec![RuleSource::Rfc5280, RuleSource::Hygiene]
}

/// Maps the result of [`Cert::has_server_auth`] to an allowed-source set.
///
/// This is the pure decision behind [`CertPurpose::Auto`], factored out so the
/// `Ok(false)` and `Err(..)` branches are unit-testable without a fixture:
///
/// - `Ok(true)`  → [`tls_server_sources`] (includes `CabfBr`).
/// - `Ok(false)` → [`generic_sources`] (skips `CabfBr`).
/// - `Err(..)`   → [`generic_sources`] — **fail closed**: a defensive parse
///   failure must never manufacture a Baseline Requirements false positive, so
///   the TLS-server-specific source is dropped.
fn auto_sources_from(has_server_auth: Result<bool, crate::cert::CertError>) -> Vec<RuleSource> {
    match has_server_auth {
        Ok(true) => tls_server_sources(),
        Ok(false) | Err(_) => generic_sources(),
    }
}

impl CertPurpose {
    /// The set of [`RuleSource`]s this purpose allows for `cert`.
    ///
    /// The returned ordering is stable (always `Rfc5280, Hygiene, CabfBr` for the
    /// tls-server set; `Rfc5280, Hygiene` for the generic set) so downstream
    /// output stays deterministic. The CLI intersects this set with its
    /// `--source` selection and passes the result to [`Registry::run_filtered`].
    ///
    /// - [`TlsServer`](CertPurpose::TlsServer) → `[Rfc5280, Hygiene, CabfBr]`.
    /// - [`Generic`](CertPurpose::Generic) → `[Rfc5280, Hygiene]`.
    /// - [`Auto`](CertPurpose::Auto) → resolved per cert via
    ///   [`Cert::has_server_auth`]: `Ok(true)` yields the tls-server set,
    ///   `Ok(false)` the generic set, and `Err(..)` **fails closed** to the
    ///   generic set (skipping `CabfBr`) so a defensive parse failure cannot
    ///   manufacture a Baseline Requirements false positive. This resolver never
    ///   panics and never propagates the error.
    ///
    /// `Auto` is a documented **heuristic**: a leaf with no EKU, or one that does
    /// not assert serverAuth, resolves to `generic`. Forcing
    /// [`TlsServer`](CertPurpose::TlsServer) runs the `CabfBr` set even when the
    /// serverAuth EKU is absent.
    pub fn allowed_sources(self, cert: &Cert) -> Vec<RuleSource> {
        match self {
            CertPurpose::TlsServer => tls_server_sources(),
            CertPurpose::Generic => generic_sources(),
            CertPurpose::Auto => auto_sources_from(cert.has_server_auth()),
        }
    }

    /// Resolves this purpose to a concrete, non-`Auto` purpose for `cert`.
    ///
    /// [`TlsServer`](CertPurpose::TlsServer) and [`Generic`](CertPurpose::Generic)
    /// resolve to themselves. [`Auto`](CertPurpose::Auto) resolves to
    /// [`TlsServer`](CertPurpose::TlsServer) when the leaf asserts serverAuth and
    /// to [`Generic`](CertPurpose::Generic) otherwise — including the fail-closed
    /// `Err(..)` path, matching [`allowed_sources`](CertPurpose::allowed_sources).
    ///
    /// The CLI uses this for the verbose `purpose:` header (for example
    /// `purpose: generic (auto)`), reporting which concrete purpose `auto`
    /// landed on. The result is consistent with `allowed_sources`: the returned
    /// purpose's `allowed_sources` equals this purpose's `allowed_sources` for
    /// the same cert.
    pub fn resolve(self, cert: &Cert) -> CertPurpose {
        match self {
            CertPurpose::TlsServer => CertPurpose::TlsServer,
            CertPurpose::Generic => CertPurpose::Generic,
            CertPurpose::Auto => match cert.has_server_auth() {
                Ok(true) => CertPurpose::TlsServer,
                Ok(false) | Err(_) => CertPurpose::Generic,
            },
        }
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
    use crate::lints::cabf_br;
    use crate::lints::hygiene;
    use crate::lints::rfc5280;

    Registry::with_lints(vec![
        // --- add new lints here ---
        // Hygiene (features 02 & 04). Order is deterministic and matters for the
        // feature 06 golden test — keep it stable. `not_expired` is registered
        // exactly once here (no earlier registration to deduplicate).
        Box::new(hygiene::NotExpired::new()),
        Box::new(hygiene::NoSha1Signature::new()),
        Box::new(hygiene::RsaKeyMin2048::new()),
        Box::new(hygiene::EcdsaCurveAllowlist::new()),
        // RFC 5280 structural lints (feature 03). Order is deterministic and
        // matters for the feature 06 golden test — keep it stable.
        Box::new(rfc5280::VersionIsV3::new()),
        Box::new(rfc5280::SerialNumberPositive::new()),
        Box::new(rfc5280::ValidityNotAfterAfterNotBefore::new()),
        Box::new(rfc5280::BasicConstraintsCriticalOnCa::new()),
        Box::new(rfc5280::KeyUsagePresentWhenCa::new()),
        Box::new(rfc5280::SanPresentIfSubjectEmpty::new()),
        // RFC 5280 depth-expansion lints (feature 12). Appended after the
        // original six; order is deterministic and matters for the feature 06
        // golden test — keep it stable.
        Box::new(rfc5280::CaSubjectFieldEmpty::new()),
        Box::new(rfc5280::ExtKeyUsageWithoutBits::new()),
        Box::new(rfc5280::ExtAuthorityKeyIdentifierNoKeyIdentifier::new()),
        Box::new(rfc5280::ExtSubjectKeyIdentifierMissingCa::new()),
        Box::new(rfc5280::ExtSubjectKeyIdentifierMissingSubCert::new()),
        Box::new(rfc5280::PathLenConstraintImproperlyIncluded::new()),
        Box::new(rfc5280::ExtNameConstraintsNotCritical::new()),
        Box::new(rfc5280::SubjectDnCountryNotPrintableString::new()),
        Box::new(rfc5280::ExtSanNoEntries::new()),
        Box::new(rfc5280::UtcTimeNotInZulu::new()),
        // CA/Browser Forum Baseline Requirements lints (feature 05). Order is
        // deterministic and matters for the feature 06 golden test — keep it
        // stable.
        Box::new(cabf_br::ValidityMax398Days::new()),
        Box::new(cabf_br::CnInSan::new()),
        Box::new(cabf_br::NoInternalNamesOrReservedIp::new()),
        Box::new(cabf_br::ExtKeyUsageServerAuthPresent::new()),
        // CA/Browser Forum BR depth-expansion lints (feature 12). Appended after
        // the original four; order is deterministic and matters for the feature
        // 06 golden test — keep it stable.
        Box::new(cabf_br::DnsnameUnderscoreInSld::new()),
        Box::new(cabf_br::DnsnameBadCharacterInLabel::new()),
        Box::new(cabf_br::DnsnameLabelTooLong::new()),
        Box::new(cabf_br::DnsnameWildcardLeftOfPublicSuffix::new()),
        Box::new(cabf_br::OrganizationalUnitNameProhibited::new()),
        Box::new(cabf_br::SubjectContainsReservedIp::new()),
        Box::new(cabf_br::ExtraSubjectCommonNames::new()),
        Box::new(cabf_br::SubjectCountryNotIso::new()),
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

            // Expect: the four hygiene lints, all sixteen RFC 5280 lints, and
            // the twelve CA/Browser Forum BR lints are wired in and reported —
            // one outcome per registered lint. `sample_cert()` is a CA, so the
            // BR lints and leaf-only rfc5280 lints are `NotApplicable` but still
            // produce one outcome each, keeping the outcome count equal to the
            // registry length.
            assert!(!registry.is_empty());
            assert_eq!(registry.len(), 32);
            assert_eq!(outcomes.len(), 32);

            let ids: Vec<&str> = outcomes.iter().map(|o| o.lint_id).collect();
            for expected in [
                "hygiene_not_expired",
                "hygiene_no_sha1_signature",
                "hygiene_rsa_key_min_2048",
                "hygiene_ecdsa_curve_allowlist",
                "rfc5280_version_is_v3",
                "rfc5280_serial_number_positive",
                "rfc5280_validity_not_after_after_not_before",
                "rfc5280_basic_constraints_critical_on_ca",
                "rfc5280_key_usage_present_when_ca",
                "rfc5280_san_present_if_subject_empty",
                "rfc5280_ca_subject_field_empty",
                "rfc5280_ext_key_usage_without_bits",
                "rfc5280_ext_authority_key_identifier_no_key_identifier",
                "rfc5280_ext_subject_key_identifier_missing_ca",
                "rfc5280_ext_subject_key_identifier_missing_sub_cert",
                "rfc5280_path_len_constraint_improperly_included",
                "rfc5280_ext_name_constraints_not_critical",
                "rfc5280_subject_dn_country_not_printable_string",
                "rfc5280_ext_san_no_entries",
                "rfc5280_utc_time_not_in_zulu",
                "cabf_br_validity_max_398_days",
                "cabf_br_cn_in_san",
                "cabf_br_no_internal_names_or_reserved_ip",
                "cabf_br_ext_key_usage_server_auth_present",
                "cabf_br_dnsname_underscore_in_sld",
                "cabf_br_dnsname_bad_character_in_label",
                "cabf_br_dnsname_label_too_long",
                "cabf_br_dnsname_wildcard_left_of_public_suffix",
                "cabf_br_organizational_unit_name_prohibited",
                "cabf_br_subject_contains_reserved_ip",
                "cabf_br_extra_subject_common_names",
                "cabf_br_subject_country_not_iso",
            ] {
                assert!(
                    ids.contains(&expected),
                    "default registry missing lint {expected}; got {ids:?}"
                );
            }
        }

        #[test]
        fn rfc5280_source_filter_runs_exactly_the_rfc5280_set() {
            // Setup & Invoke: filtering by RuleSource::Rfc5280 must select the
            // sixteen RFC 5280 lints and nothing else (e.g. not the hygiene lint).
            let registry = default_registry();
            let cert = sample_cert();
            let outcomes = registry.run_filtered(&cert, &[RuleSource::Rfc5280]);

            // Expect
            assert_eq!(outcomes.len(), 16);
            assert!(outcomes.iter().all(|o| o.source == RuleSource::Rfc5280));

            let ids: Vec<&str> = outcomes.iter().map(|o| o.lint_id).collect();
            for expected in [
                "rfc5280_version_is_v3",
                "rfc5280_serial_number_positive",
                "rfc5280_validity_not_after_after_not_before",
                "rfc5280_basic_constraints_critical_on_ca",
                "rfc5280_key_usage_present_when_ca",
                "rfc5280_san_present_if_subject_empty",
                "rfc5280_ca_subject_field_empty",
                "rfc5280_ext_key_usage_without_bits",
                "rfc5280_ext_authority_key_identifier_no_key_identifier",
                "rfc5280_ext_subject_key_identifier_missing_ca",
                "rfc5280_ext_subject_key_identifier_missing_sub_cert",
                "rfc5280_path_len_constraint_improperly_included",
                "rfc5280_ext_name_constraints_not_critical",
                "rfc5280_subject_dn_country_not_printable_string",
                "rfc5280_ext_san_no_entries",
                "rfc5280_utc_time_not_in_zulu",
            ] {
                assert!(
                    ids.contains(&expected),
                    "rfc5280 filter missing lint {expected}; got {ids:?}"
                );
            }
            assert!(!ids.contains(&"hygiene_not_expired"));
            assert!(!ids.contains(&"hygiene_no_sha1_signature"));
            assert!(!ids.contains(&"hygiene_rsa_key_min_2048"));
            assert!(!ids.contains(&"hygiene_ecdsa_curve_allowlist"));
        }

        #[test]
        fn hygiene_source_filter_runs_exactly_the_hygiene_set() {
            // Setup & Invoke: filtering by RuleSource::Hygiene must select the
            // four hygiene lints and nothing else (e.g. no RFC 5280 lints).
            let registry = default_registry();
            let cert = sample_cert();
            let outcomes = registry.run_filtered(&cert, &[RuleSource::Hygiene]);

            // Expect
            assert_eq!(outcomes.len(), 4);
            assert!(outcomes.iter().all(|o| o.source == RuleSource::Hygiene));

            let ids: Vec<&str> = outcomes.iter().map(|o| o.lint_id).collect();
            for expected in [
                "hygiene_not_expired",
                "hygiene_no_sha1_signature",
                "hygiene_rsa_key_min_2048",
                "hygiene_ecdsa_curve_allowlist",
            ] {
                assert!(
                    ids.contains(&expected),
                    "hygiene filter missing lint {expected}; got {ids:?}"
                );
            }
            assert!(!ids.iter().any(|id| id.starts_with("rfc5280_")));
        }

        #[test]
        fn cabf_br_source_filter_runs_exactly_the_cabf_br_set() {
            // Setup & Invoke: filtering by RuleSource::CabfBr must select the
            // twelve BR lints and nothing else (no RFC 5280 or hygiene lints).
            // Filtering is by source, before applicability, so the BR lints
            // appear even though `sample_cert()` is a CA (they are NotApplicable
            // but still emitted as outcomes).
            let registry = default_registry();
            let cert = sample_cert();
            let outcomes = registry.run_filtered(&cert, &[RuleSource::CabfBr]);

            // Expect
            assert_eq!(outcomes.len(), 12);
            assert!(outcomes.iter().all(|o| o.source == RuleSource::CabfBr));

            let ids: Vec<&str> = outcomes.iter().map(|o| o.lint_id).collect();
            for expected in [
                "cabf_br_validity_max_398_days",
                "cabf_br_cn_in_san",
                "cabf_br_no_internal_names_or_reserved_ip",
                "cabf_br_ext_key_usage_server_auth_present",
                "cabf_br_dnsname_underscore_in_sld",
                "cabf_br_dnsname_bad_character_in_label",
                "cabf_br_dnsname_label_too_long",
                "cabf_br_dnsname_wildcard_left_of_public_suffix",
                "cabf_br_organizational_unit_name_prohibited",
                "cabf_br_subject_contains_reserved_ip",
                "cabf_br_extra_subject_common_names",
                "cabf_br_subject_country_not_iso",
            ] {
                assert!(
                    ids.contains(&expected),
                    "cabf_br filter missing lint {expected}; got {ids:?}"
                );
            }
            assert!(!ids.iter().any(|id| id.starts_with("rfc5280_")));
            assert!(!ids.iter().any(|id| id.starts_with("hygiene_")));
        }

        #[test]
        fn default_trait_matches_default_registry() {
            assert_eq!(Registry::default().len(), default_registry().len());
        }
    }

    mod cert_purpose {
        use super::*;
        use crate::cert::CertError;

        /// Loads the workspace `testdata/good.pem` fixture, whose leaf asserts
        /// the serverAuth EKU (feature 05).
        fn good_cert() -> Cert {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
            let bytes = std::fs::read(path).expect("good.pem fixture must exist");
            let mut certs = Cert::from_pem(&bytes).expect("good.pem must parse");
            certs.pop().expect("good.pem must contain one cert")
        }

        #[test]
        fn tls_server_includes_cabf_br() {
            // Setup
            let cert = sample_cert();

            // Invoke
            let sources = CertPurpose::TlsServer.allowed_sources(&cert);

            // Expect: all three current sources, stable order, CabfBr present.
            assert_eq!(
                sources,
                vec![RuleSource::Rfc5280, RuleSource::Hygiene, RuleSource::CabfBr]
            );
            assert!(sources.contains(&RuleSource::CabfBr));
        }

        #[test]
        fn generic_omits_cabf_br() {
            // Setup
            let cert = sample_cert();

            // Invoke
            let sources = CertPurpose::Generic.allowed_sources(&cert);

            // Expect: only standard + hygiene, no CabfBr.
            assert_eq!(sources, vec![RuleSource::Rfc5280, RuleSource::Hygiene]);
            assert!(!sources.contains(&RuleSource::CabfBr));
        }

        #[test]
        fn auto_on_server_auth_leaf_includes_cabf_br() {
            // Setup: good.pem asserts the serverAuth EKU.
            let cert = good_cert();
            assert!(
                cert.has_server_auth().expect("good.pem re-parses"),
                "fixture precondition: good.pem must assert serverAuth"
            );

            // Invoke
            let sources = CertPurpose::Auto.allowed_sources(&cert);

            // Expect: resolves to the tls-server set incl. CabfBr.
            assert_eq!(
                sources,
                vec![RuleSource::Rfc5280, RuleSource::Hygiene, RuleSource::CabfBr]
            );
            assert_eq!(CertPurpose::Auto.resolve(&cert), CertPurpose::TlsServer);
        }

        #[test]
        fn auto_on_non_server_auth_resolves_to_generic_set() {
            // The pure decision: Ok(false) (a leaf without serverAuth) drops
            // CabfBr. Tested via the helper so no non-serverAuth fixture is
            // required (task 04 adds one later).
            let sources = auto_sources_from(Ok(false));

            assert_eq!(sources, vec![RuleSource::Rfc5280, RuleSource::Hygiene]);
            assert!(!sources.contains(&RuleSource::CabfBr));
        }

        #[test]
        fn auto_fails_closed_to_generic_on_error() {
            // The fail-closed decision: Err(..) must drop CabfBr so a defensive
            // parse failure cannot manufacture a BR false positive.
            let sources = auto_sources_from(Err(CertError::Der));

            assert_eq!(sources, vec![RuleSource::Rfc5280, RuleSource::Hygiene]);
            assert!(!sources.contains(&RuleSource::CabfBr));
        }

        #[test]
        fn auto_tls_server_set_matches_explicit_tls_server() {
            // The Auto-resolved-to-tls-server and explicit TlsServer sets stay in
            // sync (shared helper).
            let cert = good_cert();
            assert_eq!(
                CertPurpose::Auto.allowed_sources(&cert),
                CertPurpose::TlsServer.allowed_sources(&cert)
            );
        }

        #[test]
        fn explicit_purposes_resolve_to_themselves() {
            let cert = sample_cert();
            assert_eq!(
                CertPurpose::TlsServer.resolve(&cert),
                CertPurpose::TlsServer
            );
            assert_eq!(CertPurpose::Generic.resolve(&cert), CertPurpose::Generic);
        }
    }
}
