//! Integration tests for the twelve emailProtection-EKU-gated CA/Browser Forum
//! S/MIME Baseline Requirements lints (`cabf_smime_*`), exercised against the
//! real committed `testdata/cabf_smime_*.pem` fixtures through the public `Cert`
//! facade and the `Registry`.
//!
//! # Scoping (NARROW, emailProtection-EKU-gated — load-bearing)
//!
//! Every `cabf_smime` lint's `applies()` returns `NotApplicable` unless the cert
//! asserts the `emailProtection` EKU (OID 1.3.6.1.5.5.7.3.4) AND is not a CA.
//! This is the explicit anti-cascade design (see the feature-10 plan's
//! "Cascade-Avoidance Decision"): the S/MIME lints are `NotApplicable` on every
//! existing TLS / generic / code-signing / CA fixture from features 03/04/05/09,
//! so NO existing fixture was regenerated for this feature.
//!
//! # Isolation mechanism (why `run_filtered([CabfSmime])`, not the raw registry)
//!
//! The S/MIME fixtures carry `emailProtection` but deliberately NOT `serverAuth`,
//! and they are non-CA leaves. Under feature 05's BROAD `cabf_br` scoping, the BR
//! lints examine EVERY non-CA leaf regardless of EKU — so a RAW
//! `default_registry().run()` over an S/MIME fixture WOULD trip
//! `cabf_br_ext_key_usage_server_auth_present` (and, on a fixture that lacked a
//! host-shaped SAN, other BR lints). That co-fire is exactly the false positive
//! the smime PURPOSE (`--purpose smime`, or `auto` on an emailProtection leaf)
//! suppresses — it is NOT a fixture defect. To assert S/MIME rule isolation
//! cleanly we therefore run ONLY the S/MIME source via
//! `registry.run_filtered(&cert, &[RuleSource::CabfSmime])`; that is the robust
//! mechanism used by the per-lint tests below.
//!
//! The "good passes end-to-end" assertion instead runs the smime PURPOSE set
//! `[Rfc5280, Hygiene, CabfSmime]` (mirroring how the CLI's `auto` purpose treats
//! an emailProtection leaf: emailProtection -> smime, so `cabf_br` is NOT run) and
//! asserts no Error/Fatal. A raw all-source run on the clean leaf additionally
//! trips the broad `cabf_br` serverAuth-absent / SAN false positives — documented,
//! expected, and the reason the purpose filter exists.
//!
//! The no-cascade property (the S/MIME set stays quiet on a non-emailProtection
//! cert) is proved separately against the RAW registry on the non-emailProtection
//! `good.pem` (a serverAuth TLS leaf) AND on a CA fixture.
//!
//! # ⚠️ Time-fragility
//!
//! Every `cabf_smime_*.pem` fixture uses a currently-valid window
//! `2026-06-01 -> 2027-06-01` (365d, aligned with feature 05's `BR_OK`). They
//! EXPIRE on 2027-06-01; after that `hygiene_not_expired` fires on them and these
//! isolation tests fail wholesale. Regenerate `testdata/` annually (slide the
//! window forward — see the S/MIME section of `testdata/generate.sh`). If a flood
//! of `not_expired`-shaped failures appears, the window has lapsed.
//!
//! Conventions (`.claude/rules/rust-testing-core.md`): SIFER, nested module per
//! lint, `.unwrap()`-style result assertions.

use linter::{Applicability, Cert, RuleSource, Severity, default_registry};

// `include_bytes!` resolves relative to this source file
// (crates/linter/tests/cabf_smime.rs); `../../../testdata` reaches the
// workspace-root `testdata/` directory.
const SMIME_GOOD_PEM: &[u8] = include_bytes!("../../../testdata/cabf_smime_good.pem");
const SMIME_NO_SAN_PEM: &[u8] = include_bytes!("../../../testdata/cabf_smime_no_san.pem");
const SMIME_SAN_CRITICAL_PEM: &[u8] =
    include_bytes!("../../../testdata/cabf_smime_san_critical.pem");
const SMIME_CN_NOT_IN_SAN_PEM: &[u8] =
    include_bytes!("../../../testdata/cabf_smime_cn_email_not_in_san.pem");
const SMIME_TWO_EMAIL_PEM: &[u8] =
    include_bytes!("../../../testdata/cabf_smime_two_email_subject.pem");
const SMIME_NO_KU_PEM: &[u8] = include_bytes!("../../../testdata/cabf_smime_no_key_usage.pem");
const SMIME_KU_NOT_CRITICAL_PEM: &[u8] =
    include_bytes!("../../../testdata/cabf_smime_key_usage_not_critical.pem");
const SMIME_EKU_SERVER_AUTH_PEM: &[u8] =
    include_bytes!("../../../testdata/cabf_smime_eku_server_auth.pem");
const SMIME_NO_AKI_PEM: &[u8] = include_bytes!("../../../testdata/cabf_smime_no_aki.pem");
const SMIME_NO_CRL_DP_PEM: &[u8] = include_bytes!("../../../testdata/cabf_smime_no_crl_dp.pem");
const SMIME_CRL_DP_LDAP_PEM: &[u8] = include_bytes!("../../../testdata/cabf_smime_crl_dp_ldap.pem");
const SMIME_BAD_COUNTRY_PEM: &[u8] = include_bytes!("../../../testdata/cabf_smime_bad_country.pem");

// A non-emailProtection leaf (serverAuth EKU only) and a CA fixture — used for the
// no-cascade proofs.
const GOOD_PEM: &[u8] = include_bytes!("../../../testdata/good.pem");
const CA_PEM: &[u8] = include_bytes!("../../../testdata/rfc5280_ca_bc_not_critical.pem");

/// The twelve `cabf_smime` lint ids, in registry order.
const SMIME_LINT_IDS: [&str; 12] = [
    "cabf_smime_san_present",
    "cabf_smime_san_not_critical",
    "cabf_smime_email_in_san",
    "cabf_smime_single_email_subject",
    "cabf_smime_key_usage_present",
    "cabf_smime_key_usage_critical",
    "cabf_smime_eku_email_protection_present",
    "cabf_smime_eku_no_server_auth",
    "cabf_smime_authority_key_identifier_present",
    "cabf_smime_crl_distribution_points_present",
    "cabf_smime_crl_distribution_points_http",
    "cabf_smime_subject_country_valid",
];

/// Loads the single leaf certificate from a PEM fixture; `unwrap` surfaces the
/// `CertError` if the fixture is malformed.
fn load_leaf(pem: &[u8]) -> Cert {
    let mut certs = Cert::load(pem).unwrap();
    certs.remove(0)
}

/// Runs ONLY the `cabf_smime` source over the fixture (the robust isolation
/// mechanism — see the module doc). Returns the 12 S/MIME outcomes.
fn run_smime_only(cert: &Cert) -> Vec<linter::LintOutcome> {
    default_registry().run_filtered(cert, &[RuleSource::CabfSmime])
}

/// Collects all findings for a specific lint id from a set of outcomes.
fn findings_for<'a>(
    outcomes: &'a [linter::LintOutcome],
    lint_id: &str,
) -> Vec<&'a linter::Finding> {
    outcomes
        .iter()
        .filter(|o| o.lint_id == lint_id)
        .flat_map(|o| o.findings.iter())
        .collect()
}

/// Asserts that, under the S/MIME-only filter, EXACTLY the given lint id produced
/// findings and every other S/MIME lint was silent. Returns that lint's findings.
fn assert_only_smime_lint_fires<'a>(
    outcomes: &'a [linter::LintOutcome],
    target: &str,
) -> Vec<&'a linter::Finding> {
    for id in SMIME_LINT_IDS {
        let fs = findings_for(outcomes, id);
        if id == target {
            assert!(
                !fs.is_empty(),
                "expected {target} to fire under the cabf_smime filter, but it was silent"
            );
        } else {
            assert!(
                fs.is_empty(),
                "expected ONLY {target} to fire, but {id} also produced {fs:?}"
            );
        }
    }
    findings_for(outcomes, target)
}

mod good_passes_the_whole_smime_set {
    use super::*;

    #[test]
    fn clean_smime_leaf_produces_no_smime_findings() {
        // Setup: the clean S/MIME leaf.
        let cert = load_leaf(SMIME_GOOD_PEM);

        // Invoke: run only the S/MIME source.
        let outcomes = run_smime_only(&cert);

        // Find + Expect: all 12 S/MIME lints applied, none produced any finding.
        assert_eq!(
            outcomes.len(),
            12,
            "the cabf_smime filter must run all 12 S/MIME lints"
        );
        for o in &outcomes {
            assert_eq!(o.source, RuleSource::CabfSmime);
            assert_eq!(
                o.applicability,
                Applicability::Applies,
                "{} should apply to an emailProtection leaf",
                o.lint_id
            );
            assert!(
                o.findings.is_empty(),
                "{} produced unexpected findings on cabf_smime_good.pem: {:?}",
                o.lint_id,
                o.findings
            );
        }
    }

    #[test]
    fn clean_smime_leaf_passes_under_smime_purpose() {
        // The CLI's default `auto` purpose resolves an emailProtection leaf to the
        // S/MIME purpose, whose sources are [Rfc5280, Hygiene, CabfSmime] — CabfBr
        // is NOT run, so the broad serverAuth-absent / SAN false positives never
        // surface. Running exactly those sources over the clean S/MIME leaf must
        // produce zero Error/Fatal findings (it is RFC-5280-/hygiene-clean too).
        //
        // (A RAW all-source run additionally trips the broad cabf_br serverAuth
        // false positive on this fixture; that is expected and is exactly what the
        // purpose filter suppresses — see the module doc.)
        let cert = load_leaf(SMIME_GOOD_PEM);

        let outcomes = default_registry().run_filtered(
            &cert,
            &[
                RuleSource::Rfc5280,
                RuleSource::Hygiene,
                RuleSource::CabfSmime,
            ],
        );

        let errors: Vec<_> = outcomes
            .iter()
            .flat_map(|o| o.findings.iter().map(move |f| (o.lint_id, f)))
            .filter(|(_, f)| matches!(f.severity, Severity::Error | Severity::Fatal))
            .collect();
        assert!(
            errors.is_empty(),
            "cabf_smime_good.pem should be Error/Fatal-clean under the S/MIME purpose; offenders: {errors:?}"
        );
    }
}

mod san_present {
    use super::*;

    #[test]
    fn flags_a_leaf_with_no_rfc822_name_san() {
        // Setup: emailProtection leaf with NO SAN at all.
        let cert = load_leaf(SMIME_NO_SAN_PEM);

        let outcomes = run_smime_only(&cert);
        let findings = assert_only_smime_lint_fires(&outcomes, "cabf_smime_san_present");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0].message.contains("rfc822Name"),
            "message should name the missing rfc822Name: {:?}",
            findings[0].message
        );
    }
}

mod san_not_critical {
    use super::*;

    #[test]
    fn warns_when_san_is_critical_with_non_empty_subject() {
        // Setup: emailProtection leaf with a CRITICAL SAN and a populated subject.
        let cert = load_leaf(SMIME_SAN_CRITICAL_PEM);

        let outcomes = run_smime_only(&cert);
        let findings = assert_only_smime_lint_fires(&outcomes, "cabf_smime_san_not_critical");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(
            findings[0].message.contains("critical"),
            "message should describe the criticality issue: {:?}",
            findings[0].message
        );
    }
}

mod email_in_san {
    use super::*;

    #[test]
    fn flags_an_email_shaped_cn_absent_from_the_san() {
        // Setup: CN=cn-only@example.com (an email), SAN carries a DIFFERENT email.
        let cert = load_leaf(SMIME_CN_NOT_IN_SAN_PEM);

        let outcomes = run_smime_only(&cert);
        let findings = assert_only_smime_lint_fires(&outcomes, "cabf_smime_email_in_san");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0].message.contains("cn-only@example.com"),
            "message should name the offending CN: {:?}",
            findings[0].message
        );
    }
}

mod single_email_subject {
    use super::*;

    #[test]
    fn flags_two_subject_email_address_rdns() {
        // Setup: emailProtection leaf whose subject has TWO emailAddress RDNs.
        let cert = load_leaf(SMIME_TWO_EMAIL_PEM);

        let outcomes = run_smime_only(&cert);
        let findings = assert_only_smime_lint_fires(&outcomes, "cabf_smime_single_email_subject");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0].message.contains('2'),
            "message should name the observed count: {:?}",
            findings[0].message
        );
    }
}

mod key_usage_present {
    use super::*;

    #[test]
    fn flags_a_leaf_with_no_key_usage_extension() {
        // Setup: emailProtection leaf with NO KeyUsage extension.
        let cert = load_leaf(SMIME_NO_KU_PEM);

        let outcomes = run_smime_only(&cert);
        let findings = assert_only_smime_lint_fires(&outcomes, "cabf_smime_key_usage_present");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0].message.contains("Key Usage"),
            "message should name the missing extension: {:?}",
            findings[0].message
        );
    }
}

mod key_usage_critical {
    use super::*;

    #[test]
    fn warns_when_key_usage_is_present_but_not_critical() {
        // Setup: emailProtection leaf with a present-but-non-critical KeyUsage.
        let cert = load_leaf(SMIME_KU_NOT_CRITICAL_PEM);

        let outcomes = run_smime_only(&cert);
        let findings = assert_only_smime_lint_fires(&outcomes, "cabf_smime_key_usage_critical");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(
            findings[0].message.contains("critical"),
            "message should describe the criticality issue: {:?}",
            findings[0].message
        );
    }
}

mod eku_no_server_auth {
    use super::*;

    #[test]
    fn flags_a_leaf_asserting_both_email_protection_and_server_auth() {
        // Setup: emailProtection leaf that ALSO asserts serverAuth. The gate
        // (has_email_protection && !is_ca) is satisfied, so the S/MIME set runs
        // under the CabfSmime filter and the no-serverAuth rule fires — the
        // intended TLS-server-multipurpose-abuse signal (see the module doc).
        let cert = load_leaf(SMIME_EKU_SERVER_AUTH_PEM);

        let outcomes = run_smime_only(&cert);
        let findings = assert_only_smime_lint_fires(&outcomes, "cabf_smime_eku_no_server_auth");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0].message.contains("serverAuth"),
            "message should name the forbidden EKU: {:?}",
            findings[0].message
        );
    }
}

mod authority_key_identifier_present {
    use super::*;

    #[test]
    fn flags_a_leaf_with_no_authority_key_identifier() {
        // Setup: emailProtection leaf with NO AKI extension.
        let cert = load_leaf(SMIME_NO_AKI_PEM);

        let outcomes = run_smime_only(&cert);
        let findings =
            assert_only_smime_lint_fires(&outcomes, "cabf_smime_authority_key_identifier_present");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0].message.contains("Authority Key Identifier"),
            "message should name the missing extension: {:?}",
            findings[0].message
        );
    }
}

mod crl_distribution_points_present {
    use super::*;

    #[test]
    fn flags_a_leaf_with_no_crl_distribution_points() {
        // Setup: emailProtection leaf with NO CRL-DP extension.
        let cert = load_leaf(SMIME_NO_CRL_DP_PEM);

        let outcomes = run_smime_only(&cert);
        let findings =
            assert_only_smime_lint_fires(&outcomes, "cabf_smime_crl_distribution_points_present");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0].message.contains("CRL Distribution Points"),
            "message should name the missing extension: {:?}",
            findings[0].message
        );
    }
}

mod crl_distribution_points_http {
    use super::*;

    #[test]
    fn flags_a_non_http_crl_distribution_point_uri() {
        // Setup: emailProtection leaf whose CRL-DP fullName URI is ldap:// — the
        // CRL-DP extension is PRESENT (presence lint quiet), only the scheme wrong.
        let cert = load_leaf(SMIME_CRL_DP_LDAP_PEM);

        let outcomes = run_smime_only(&cert);
        let findings =
            assert_only_smime_lint_fires(&outcomes, "cabf_smime_crl_distribution_points_http");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0]
                .message
                .contains("ldap://crl.example.com/smime.crl"),
            "message should name the offending URI: {:?}",
            findings[0].message
        );
    }
}

mod subject_country_valid {
    use super::*;

    #[test]
    fn flags_a_three_letter_subject_country() {
        // Setup: emailProtection leaf whose subject country is the 3-letter "USA".
        let cert = load_leaf(SMIME_BAD_COUNTRY_PEM);

        let outcomes = run_smime_only(&cert);
        let findings = assert_only_smime_lint_fires(&outcomes, "cabf_smime_subject_country_valid");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0].message.contains("USA"),
            "message should name the offending country value: {:?}",
            findings[0].message
        );
    }
}

mod each_fixture_isolates_exactly_one_smime_violation {
    use super::*;

    /// Drives every (fixture, expected-lint-id) pair through the CabfSmime filter
    /// and asserts the firing-id set equals the single expected id — the S/MIME
    /// analogue of the rfc5280 / hygiene / cabf_cs "exactly one rule" tables.
    #[test]
    fn one_rule_per_violating_fixture_under_the_smime_filter() {
        let cases: &[(&[u8], &str)] = &[
            (SMIME_NO_SAN_PEM, "cabf_smime_san_present"),
            (SMIME_SAN_CRITICAL_PEM, "cabf_smime_san_not_critical"),
            (SMIME_CN_NOT_IN_SAN_PEM, "cabf_smime_email_in_san"),
            (SMIME_TWO_EMAIL_PEM, "cabf_smime_single_email_subject"),
            (SMIME_NO_KU_PEM, "cabf_smime_key_usage_present"),
            (SMIME_KU_NOT_CRITICAL_PEM, "cabf_smime_key_usage_critical"),
            (SMIME_EKU_SERVER_AUTH_PEM, "cabf_smime_eku_no_server_auth"),
            (
                SMIME_NO_AKI_PEM,
                "cabf_smime_authority_key_identifier_present",
            ),
            (
                SMIME_NO_CRL_DP_PEM,
                "cabf_smime_crl_distribution_points_present",
            ),
            (
                SMIME_CRL_DP_LDAP_PEM,
                "cabf_smime_crl_distribution_points_http",
            ),
            (SMIME_BAD_COUNTRY_PEM, "cabf_smime_subject_country_valid"),
        ];

        for (pem, expected) in cases {
            let cert = load_leaf(pem);
            let outcomes = run_smime_only(&cert);

            let firing: Vec<&str> = SMIME_LINT_IDS
                .into_iter()
                .filter(|id| !findings_for(&outcomes, id).is_empty())
                .collect();

            assert_eq!(
                firing,
                vec![*expected],
                "fixture for {expected} should fire exactly that one S/MIME lint, got {firing:?}"
            );
        }
    }
}

mod scoping_and_no_cascade {
    use super::*;

    #[test]
    fn all_twelve_smime_lints_apply_to_an_email_protection_leaf() {
        // Setup + Invoke: S/MIME-only filter over the emailProtection leaf.
        let cert = load_leaf(SMIME_GOOD_PEM);
        let outcomes = run_smime_only(&cert);

        // Expect: 12 outcomes, all CabfSmime, all Applies, the 12 known ids.
        assert_eq!(outcomes.len(), 12);
        let ids: Vec<&str> = outcomes.iter().map(|o| o.lint_id).collect();
        for id in SMIME_LINT_IDS {
            assert!(
                ids.contains(&id),
                "missing S/MIME lint {id} under the filter"
            );
        }
        assert!(outcomes.iter().all(|o| o.source == RuleSource::CabfSmime));
        assert!(
            outcomes
                .iter()
                .all(|o| o.applicability == Applicability::Applies)
        );
    }

    #[test]
    fn no_cascade_all_twelve_smime_lints_not_applicable_on_a_non_smime_leaf() {
        // The load-bearing no-cascade proof: run the RAW full registry over a
        // non-emailProtection cert (good.pem, serverAuth-only TLS leaf). Every
        // cabf_smime outcome must be NotApplicable with empty findings —
        // confirming the S/MIME set never engages on existing TLS/generic
        // fixtures, so none needed regeneration.
        let cert = load_leaf(GOOD_PEM);

        let outcomes = default_registry().run(&cert);

        let smime_outcomes: Vec<_> = outcomes
            .iter()
            .filter(|o| o.source == RuleSource::CabfSmime)
            .collect();
        assert_eq!(
            smime_outcomes.len(),
            12,
            "the full registry must emit all 12 S/MIME outcomes (as NotApplicable)"
        );
        for o in smime_outcomes {
            assert_eq!(
                o.applicability,
                Applicability::NotApplicable,
                "{} must be NotApplicable on a non-emailProtection leaf",
                o.lint_id
            );
            assert!(
                o.findings.is_empty(),
                "{} must produce no findings when NotApplicable",
                o.lint_id
            );
        }
    }

    #[test]
    fn no_cascade_all_twelve_smime_lints_not_applicable_on_a_ca() {
        // A CA certificate is not an S/MIME end-entity: the gate
        // (has_email_protection && !is_ca) excludes it even if it (hypothetically)
        // asserted emailProtection. Run the RAW full registry over a CA fixture
        // and confirm every cabf_smime outcome is NotApplicable.
        let cert = load_leaf(CA_PEM);

        let outcomes = default_registry().run(&cert);

        let smime_outcomes: Vec<_> = outcomes
            .iter()
            .filter(|o| o.source == RuleSource::CabfSmime)
            .collect();
        assert_eq!(smime_outcomes.len(), 12);
        for o in smime_outcomes {
            assert_eq!(
                o.applicability,
                Applicability::NotApplicable,
                "{} must be NotApplicable on a CA",
                o.lint_id
            );
            assert!(o.findings.is_empty());
        }
    }
}
