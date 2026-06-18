//! Integration tests for the nine self-scoped CA/Browser Forum Extended
//! Validation (EV) Guidelines lints (`cabf_ev_organization_name_missing`,
//! `cabf_ev_business_category_missing`, `cabf_ev_business_category_invalid`,
//! `cabf_ev_jurisdiction_country_missing`, `cabf_ev_serial_number_missing`,
//! `cabf_ev_not_wildcard`, `cabf_ev_san_no_ip_address`,
//! `cabf_ev_validity_max_398_days`, `cabf_ev_organization_id_present`),
//! exercised against the real committed `testdata/` fixtures through the public
//! `Cert` facade and the full `default_registry()`.
//!
//! # Scoping (SELF-SCOPING — load-bearing)
//!
//! EV is NOT identified by an EKU. A leaf is "EV" because it asserts a recognized
//! EV `certificatePolicies` OID (the project's test OID `1.3.6.1.4.1.99999.1.1`)
//! on top of being a `serverAuth` TLS leaf. Every `cabf_ev_*` lint self-gates on
//! EV scope, so it is `NotApplicable` on every non-EV leaf (incl. `good.pem`) and
//! on CA certs, and `Applies` on the EV fixtures. This means NO existing fixture
//! is regenerated and no feature-03/04/05 isolation test changes — the EV lints
//! stay quiet on every pre-existing fixture (no cascade).
//!
//! Each EV fixture is a clean EV leaf built BR-compliant EXCEPT its one EV
//! deviation, so running it over the FULL `default_registry()` isolates exactly
//! its one EV rule — the BR/RFC/hygiene lints stay quiet — with ONE documented
//! exception:
//!
//! - `cabf_ev_validity_400_days.pem` fires BOTH `cabf_ev_validity_max_398_days`
//!   AND `cabf_br_validity_max_398_days` (both ceilings are 398d): the documented
//!   two-rule case (one BR, one EV).
//!
//! The `cabf_ev_san_ip.pem` fixture deliberately uses the GENUINELY PUBLIC IP
//! `8.8.8.8` (not an RFC 5737 documentation address) so the broad BR reserved-IP
//! lint stays quiet and this fixture isolates ONLY `cabf_ev_san_no_ip_address`.
//! (A documentation IP such as `192.0.2.10` is classified as reserved by
//! `lints/cabf_br/reserved.rs`, which would co-fire the BR lint.)
//!
//! # ⚠️ Time-fragility
//!
//! The EV leaves reuse the BR_OK window (`2026-06-01 -> 2027-06-01`, 365d) and
//! the VAL400 window (`2026-06-01 -> 2027-07-06`, 400d) from `testdata/generate.sh`.
//! They EXPIRE in 2027; after that `hygiene_not_expired` fires on every EV leaf
//! and these isolation tests fail wholesale. This is the SAME chore already
//! documented in `generate.sh`'s header — there is no divergent EV warning.
//! Regenerate `testdata/` annually before 2027-06-01.
//!
//! Conventions (`.claude/rules/rust-testing-core.md`): SIFER, nested module per
//! lint, `.unwrap()`-style result assertions.

use linter::lints::cabf_ev::{
    BusinessCategoryInvalid, BusinessCategoryMissing, JurisdictionCountryMissing, NotWildcard,
    OrganizationIdPresent, OrganizationNameMissing, SanNoIpAddress, SerialNumberMissing,
    ValidityMax398Days,
};
use linter::{Applicability, Cert, Lint, RuleSource, Severity, default_registry};

// `include_bytes!` resolves relative to this source file
// (crates/linter/tests/cabf_ev.rs); `../../../testdata` reaches the
// workspace-root `testdata/` directory.
const GOOD_PEM: &[u8] = include_bytes!("../../../testdata/good.pem");
const CA_BC_NOT_CRITICAL_PEM: &[u8] =
    include_bytes!("../../../testdata/rfc5280_ca_bc_not_critical.pem");

const EV_GOOD_PEM: &[u8] = include_bytes!("../../../testdata/cabf_ev_good.pem");
const EV_ORG_NAME_MISSING_PEM: &[u8] =
    include_bytes!("../../../testdata/cabf_ev_org_name_missing.pem");
const EV_BUSINESS_CATEGORY_MISSING_PEM: &[u8] =
    include_bytes!("../../../testdata/cabf_ev_business_category_missing.pem");
const EV_BUSINESS_CATEGORY_INVALID_PEM: &[u8] =
    include_bytes!("../../../testdata/cabf_ev_business_category_invalid.pem");
const EV_JURISDICTION_COUNTRY_MISSING_PEM: &[u8] =
    include_bytes!("../../../testdata/cabf_ev_jurisdiction_country_missing.pem");
const EV_SERIAL_NUMBER_MISSING_PEM: &[u8] =
    include_bytes!("../../../testdata/cabf_ev_serial_number_missing.pem");
const EV_WILDCARD_SAN_PEM: &[u8] = include_bytes!("../../../testdata/cabf_ev_wildcard_san.pem");
const EV_SAN_IP_PEM: &[u8] = include_bytes!("../../../testdata/cabf_ev_san_ip.pem");
const EV_VALIDITY_400_PEM: &[u8] =
    include_bytes!("../../../testdata/cabf_ev_validity_400_days.pem");
const EV_ORG_ID_MISSING_PEM: &[u8] = include_bytes!("../../../testdata/cabf_ev_org_id_missing.pem");

/// The nine EV lint ids, in registry order.
const EV_LINT_IDS: &[&str] = &[
    "cabf_ev_organization_name_missing",
    "cabf_ev_business_category_missing",
    "cabf_ev_business_category_invalid",
    "cabf_ev_jurisdiction_country_missing",
    "cabf_ev_serial_number_missing",
    "cabf_ev_not_wildcard",
    "cabf_ev_san_no_ip_address",
    "cabf_ev_validity_max_398_days",
    "cabf_ev_organization_id_present",
];

/// Loads the single leaf certificate from a PEM fixture; `unwrap` surfaces the
/// `CertError` if the fixture is malformed.
fn load_leaf(pem: &[u8]) -> Cert {
    let mut certs = Cert::load(pem).unwrap();
    certs.remove(0)
}

/// Asserts `findings` contains at least one `Error` whose message contains
/// `needle`.
fn assert_error_mentions(findings: &[linter::Finding], needle: &str) {
    assert!(
        findings.iter().any(|f| f.severity == Severity::Error),
        "expected at least one Error finding, got {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.severity == Severity::Error && f.message.contains(needle)),
        "no Error finding mentioned {needle:?}; findings were {findings:?}"
    );
}

/// The sorted lint_ids that carry an Error/Fatal finding over the FULL registry
/// for `pem`.
fn firing_error_lints(pem: &[u8]) -> Vec<&'static str> {
    let registry = default_registry();
    let cert = load_leaf(pem);
    let mut firing: Vec<&'static str> = registry
        .run(&cert)
        .into_iter()
        .filter(|o| o.findings.iter().any(|f| f.severity >= Severity::Error))
        .map(|o| o.lint_id)
        .collect();
    firing.sort_unstable();
    firing
}

mod organization_name_missing {
    use super::*;

    #[test]
    fn flags_ev_leaf_without_organization_name() {
        let cert = load_leaf(EV_ORG_NAME_MISSING_PEM);
        let lint = OrganizationNameMissing::new();

        assert_eq!(lint.applies(&cert), Applicability::Applies);

        let findings = lint.check(&cert);
        assert_error_mentions(&findings, "organizationName");
    }

    #[test]
    fn passes_for_clean_ev_leaf() {
        let cert = load_leaf(EV_GOOD_PEM);
        assert!(OrganizationNameMissing::new().check(&cert).is_empty());
    }
}

mod business_category_missing {
    use super::*;

    #[test]
    fn flags_ev_leaf_without_business_category() {
        let cert = load_leaf(EV_BUSINESS_CATEGORY_MISSING_PEM);
        let lint = BusinessCategoryMissing::new();

        assert_eq!(lint.applies(&cert), Applicability::Applies);

        let findings = lint.check(&cert);
        assert_error_mentions(&findings, "businessCategory");
    }

    #[test]
    fn passes_for_clean_ev_leaf() {
        let cert = load_leaf(EV_GOOD_PEM);
        assert!(BusinessCategoryMissing::new().check(&cert).is_empty());
    }
}

mod business_category_invalid {
    use super::*;

    #[test]
    fn flags_disallowed_business_category_value() {
        let cert = load_leaf(EV_BUSINESS_CATEGORY_INVALID_PEM);
        let lint = BusinessCategoryInvalid::new();

        assert_eq!(lint.applies(&cert), Applicability::Applies);

        let findings = lint.check(&cert);
        // The fixture uses "Sole Proprietor" — not one of the three permitted values.
        assert_error_mentions(&findings, "Sole Proprietor");
    }

    #[test]
    fn passes_for_clean_ev_leaf_with_permitted_value() {
        // cabf_ev_good.pem uses "Private Organization" (a permitted value).
        let cert = load_leaf(EV_GOOD_PEM);
        assert!(BusinessCategoryInvalid::new().check(&cert).is_empty());
    }

    #[test]
    fn passes_when_business_category_absent() {
        // Absence is handled by business_category_missing, not _invalid.
        let cert = load_leaf(EV_BUSINESS_CATEGORY_MISSING_PEM);
        assert!(BusinessCategoryInvalid::new().check(&cert).is_empty());
    }
}

mod jurisdiction_country_missing {
    use super::*;

    #[test]
    fn flags_ev_leaf_without_jurisdiction_country() {
        let cert = load_leaf(EV_JURISDICTION_COUNTRY_MISSING_PEM);
        let lint = JurisdictionCountryMissing::new();

        assert_eq!(lint.applies(&cert), Applicability::Applies);

        let findings = lint.check(&cert);
        assert_error_mentions(&findings, "jurisdiction");
    }

    #[test]
    fn passes_for_clean_ev_leaf() {
        let cert = load_leaf(EV_GOOD_PEM);
        assert!(JurisdictionCountryMissing::new().check(&cert).is_empty());
    }
}

mod serial_number_missing {
    use super::*;

    #[test]
    fn flags_ev_leaf_without_subject_serial_number() {
        let cert = load_leaf(EV_SERIAL_NUMBER_MISSING_PEM);
        let lint = SerialNumberMissing::new();

        assert_eq!(lint.applies(&cert), Applicability::Applies);

        let findings = lint.check(&cert);
        assert_error_mentions(&findings, "serialNumber");
    }

    #[test]
    fn passes_for_clean_ev_leaf() {
        let cert = load_leaf(EV_GOOD_PEM);
        assert!(SerialNumberMissing::new().check(&cert).is_empty());
    }
}

mod not_wildcard {
    use super::*;

    #[test]
    fn flags_wildcard_san_entry_and_names_it() {
        let cert = load_leaf(EV_WILDCARD_SAN_PEM);
        let lint = NotWildcard::new();

        assert_eq!(lint.applies(&cert), Applicability::Applies);

        let findings = lint.check(&cert);
        assert_error_mentions(&findings, "*.ev.example.com");
    }

    #[test]
    fn passes_for_clean_ev_leaf_without_wildcard() {
        let cert = load_leaf(EV_GOOD_PEM);
        assert!(NotWildcard::new().check(&cert).is_empty());
    }
}

mod san_no_ip_address {
    use super::*;

    #[test]
    fn flags_ip_address_in_san_and_names_it() {
        let cert = load_leaf(EV_SAN_IP_PEM);
        let lint = SanNoIpAddress::new();

        assert_eq!(lint.applies(&cert), Applicability::Applies);

        let findings = lint.check(&cert);
        // The fixture's SAN includes the public IP 8.8.8.8.
        assert_error_mentions(&findings, "8.8.8.8");
    }

    #[test]
    fn passes_for_clean_ev_leaf_without_ip() {
        let cert = load_leaf(EV_GOOD_PEM);
        assert!(SanNoIpAddress::new().check(&cert).is_empty());
    }
}

mod validity_max_398_days {
    use super::*;

    #[test]
    fn flags_400_day_ev_leaf_and_names_the_duration() {
        let cert = load_leaf(EV_VALIDITY_400_PEM);
        let lint = ValidityMax398Days::new();

        assert_eq!(lint.applies(&cert), Applicability::Applies);

        let findings = lint.check(&cert);
        // Names the actual duration and the 398-day ceiling.
        assert_error_mentions(&findings, "400");
        assert_error_mentions(&findings, "398");
    }

    #[test]
    fn passes_for_clean_365_day_ev_leaf() {
        // cabf_ev_good.pem is 365 days (well within 398).
        let cert = load_leaf(EV_GOOD_PEM);
        assert!(ValidityMax398Days::new().check(&cert).is_empty());
    }
}

mod organization_id_present {
    use super::*;

    #[test]
    fn flags_ev_leaf_without_organization_identifier() {
        let cert = load_leaf(EV_ORG_ID_MISSING_PEM);
        let lint = OrganizationIdPresent::new();

        assert_eq!(lint.applies(&cert), Applicability::Applies);

        let findings = lint.check(&cert);
        assert_error_mentions(&findings, "organizationIdentifier");
    }

    #[test]
    fn passes_for_clean_ev_leaf() {
        let cert = load_leaf(EV_GOOD_PEM);
        assert!(OrganizationIdPresent::new().check(&cert).is_empty());
    }
}

mod self_scoping {
    use super::*;

    /// Every `cabf_ev_*` lint is `NotApplicable` on `good.pem` — a non-EV TLS
    /// leaf (serverAuth, but no EV policy OID). This is the no-cascade proof for
    /// existing fixtures.
    #[test]
    fn all_ev_lints_not_applicable_on_non_ev_good_leaf() {
        let registry = default_registry();
        let cert = load_leaf(GOOD_PEM);
        let outcomes = registry.run(&cert);

        for id in EV_LINT_IDS {
            let outcome = outcomes
                .iter()
                .find(|o| o.lint_id == *id)
                .unwrap_or_else(|| panic!("registry must contain {id}"));
            assert_eq!(
                outcome.applicability,
                Applicability::NotApplicable,
                "{id} must be NotApplicable on the non-EV good.pem leaf"
            );
            assert!(outcome.findings.is_empty());
        }
    }

    /// Every `cabf_ev_*` lint is `NotApplicable` on a CA cert (not a serverAuth
    /// leaf, no EV policy OID).
    #[test]
    fn all_ev_lints_not_applicable_on_ca_cert() {
        let registry = default_registry();
        let cert = load_leaf(CA_BC_NOT_CRITICAL_PEM);
        let outcomes = registry.run(&cert);

        for id in EV_LINT_IDS {
            let outcome = outcomes
                .iter()
                .find(|o| o.lint_id == *id)
                .unwrap_or_else(|| panic!("registry must contain {id}"));
            assert_eq!(
                outcome.applicability,
                Applicability::NotApplicable,
                "{id} must be NotApplicable on a CA cert"
            );
        }
    }

    /// Every `cabf_ev_*` lint `Applies` on `cabf_ev_good.pem` (in EV scope: a
    /// serverAuth leaf asserting the recognized test EV policy OID).
    #[test]
    fn all_ev_lints_apply_on_ev_good_leaf() {
        let registry = default_registry();
        let cert = load_leaf(EV_GOOD_PEM);
        let outcomes = registry.run(&cert);

        for id in EV_LINT_IDS {
            let outcome = outcomes
                .iter()
                .find(|o| o.lint_id == *id)
                .unwrap_or_else(|| panic!("registry must contain {id}"));
            assert_eq!(
                outcome.applicability,
                Applicability::Applies,
                "{id} must Apply on the EV cabf_ev_good.pem leaf"
            );
        }
    }
}

mod default_registry_isolation {
    use super::*;

    /// The positive EV control: `cabf_ev_good.pem` over the FULL registry yields
    /// no Error/Fatal findings — every EV lint applies and passes, and the
    /// BR/RFC/hygiene lints pass too.
    #[test]
    fn ev_good_yields_no_error_or_fatal_findings() {
        let registry = default_registry();
        let cert = load_leaf(EV_GOOD_PEM);
        let outcomes = registry.run(&cert);

        let bad: Vec<(&str, &linter::Finding)> = outcomes
            .iter()
            .flat_map(|o| o.findings.iter().map(move |f| (o.lint_id, f)))
            .filter(|(_, f)| f.severity >= Severity::Error)
            .collect();

        assert!(
            bad.is_empty(),
            "cabf_ev_good.pem must pass the whole registry; got {bad:?}"
        );
    }

    /// Each single-rule EV fixture, run over the FULL registry, surfaces exactly
    /// its one EV rule and no other Error/Fatal finding — proving the EV fixtures
    /// isolate exactly one rule and that the BR/RFC/hygiene lints stay quiet on
    /// EV fixtures. The two-rule validity fixture is asserted separately below.
    #[test]
    fn each_single_rule_ev_fixture_isolates_exactly_one_violation() {
        let cases: &[(&[u8], &str)] = &[
            (EV_ORG_NAME_MISSING_PEM, "cabf_ev_organization_name_missing"),
            (
                EV_BUSINESS_CATEGORY_MISSING_PEM,
                "cabf_ev_business_category_missing",
            ),
            (
                EV_BUSINESS_CATEGORY_INVALID_PEM,
                "cabf_ev_business_category_invalid",
            ),
            (
                EV_JURISDICTION_COUNTRY_MISSING_PEM,
                "cabf_ev_jurisdiction_country_missing",
            ),
            (
                EV_SERIAL_NUMBER_MISSING_PEM,
                "cabf_ev_serial_number_missing",
            ),
            (EV_WILDCARD_SAN_PEM, "cabf_ev_not_wildcard"),
            (EV_SAN_IP_PEM, "cabf_ev_san_no_ip_address"),
            (EV_ORG_ID_MISSING_PEM, "cabf_ev_organization_id_present"),
        ];

        for (pem, expected_lint) in cases {
            assert_eq!(
                firing_error_lints(pem),
                vec![*expected_lint],
                "fixture for {expected_lint} must violate exactly that rule"
            );
        }
    }

    /// `cabf_ev_validity_400_days.pem` — DOCUMENTED two-rule fixture. A 400-day EV
    /// leaf exceeds BOTH the EV and the BR 398-day validity ceiling (both are
    /// 398d), so over the full registry it fires exactly that pair and nothing
    /// else (one BR rule, one EV rule).
    #[test]
    fn validity_400_fixture_trips_both_br_and_ev_validity_rules() {
        assert_eq!(
            firing_error_lints(EV_VALIDITY_400_PEM),
            vec![
                "cabf_br_validity_max_398_days",
                "cabf_ev_validity_max_398_days",
            ]
        );
    }
}

mod cabf_ev_source_filter {
    use super::*;

    /// Filtering the full registry by `RuleSource::CabfEv` selects exactly the
    /// nine EV lints (and nothing from the other sources). On the in-scope EV
    /// control leaf they all Apply.
    #[test]
    fn runs_exactly_the_nine_ev_lints_on_ev_leaf() {
        let registry = default_registry();
        let cert = load_leaf(EV_GOOD_PEM);
        let outcomes = registry.run_filtered(&cert, &[RuleSource::CabfEv]);

        assert_eq!(outcomes.len(), 9);
        assert!(outcomes.iter().all(|o| o.source == RuleSource::CabfEv));
        assert!(
            outcomes
                .iter()
                .all(|o| o.applicability == Applicability::Applies)
        );

        let ids: Vec<&str> = outcomes.iter().map(|o| o.lint_id).collect();
        for expected in EV_LINT_IDS {
            assert!(ids.contains(expected), "missing {expected}; got {ids:?}");
        }
    }
}
