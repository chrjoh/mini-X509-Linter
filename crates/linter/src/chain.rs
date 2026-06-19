//! The chain pass: cross-certificate (chain-aware) linting.
//!
//! This module is the linter's first reasoning ACROSS certificates. It is kept
//! entirely **additive**: the per-cert [`Lint`](crate::Lint) /
//! [`Registry`](crate::Registry) / [`default_registry`](crate::default_registry)
//! path is byte-for-byte unchanged.
//!
//! The pass has three stages:
//!
//! 1. **Construction** ([`build_chain`]) — order-independent normalization. Each
//!    presented cert is linked to its issuer by byte-exact subject/issuer
//!    Name-DER matching (confirmed by AKI/SKI when both are present), producing a
//!    deterministic leaf→…→top [`OrderedChain`] plus a list of
//!    [`ConstructionDiagnostic`]s (disorder, missing-middle, unlinkable, fork,
//!    cycle, missing-top).
//! 2. **Construction-driven findings** — the diagnostics are mapped to
//!    [`Finding`]s carried by three construction-driven lints
//!    (`chain_subject_issuer_dn_match`, `chain_not_in_order`,
//!    `chain_issuer_not_in_chain`). These are registry entries with stable ids
//!    (counted in the registry) whose findings the engine *injects* from the
//!    diagnostics rather than from a pairwise `check`.
//! 3. **Pairwise link lints** — every [`ChainLint`] is run over each adjacent
//!    `(subject, issuer)` pair of the BUILT order, producing one
//!    [`ChainLinkReport`] per link.
//!
//! Everything here is deterministic, network-free, and panic-free: any accessor
//! `Err` on any cert degrades to "cannot evaluate" (no finding) rather than a
//! panic or an aborted pass.

use crate::cert::Cert;
use crate::lints::chain;
use crate::{Finding, RuleSource, Severity};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A rule that reasons across one adjacent link of an ordered certificate chain.
///
/// The chain pass walks the BUILT order `[c0 (leaf), c1, …, cN (top)]` and, for
/// each adjacent pair `(ci, ci+1)`, runs every chain lint, producing a
/// [`ChainLinkReport`] per link. The trait is object-safe so the registry can
/// hold `Vec<Box<dyn ChainLint>>`.
///
/// # Invariants
///
/// - [`check`](ChainLint::check) returning an empty `Vec` means the link passed
///   (the established "empty = pass" convention). A lint that cannot evaluate a
///   link (e.g. the subject has no AKI for `chain_aki_ski_match`) ALSO returns
///   empty — a documented *pass-by-vacuity*.
/// - Implementors must be deterministic, network-free, and panic-free: any
///   accessor `Err` degrades to no finding.
///
/// # Whole-chain context
///
/// Exactly one v1 lint (`chain_path_len_respected`) needs a single integer of
/// whole-chain context — the issuer's index in the built order. Rather than make
/// the trait non-pairwise, this is supplied via
/// [`check_with_depth`](ChainLint::check_with_depth), which has a default impl
/// delegating to [`check`](ChainLint::check). Only `chain_path_len_respected`
/// overrides it; every other lint implements the one-line `check`.
pub trait ChainLint {
    /// Stable, unique identifier for this lint (e.g. `"chain_aki_ski_match"`).
    fn id(&self) -> &'static str;

    /// The authority this lint enforces (always [`RuleSource::Chain`]).
    fn source(&self) -> RuleSource;

    /// Evaluate `subject` against its alleged `issuer`.
    ///
    /// An empty `Vec` means the link passed (or could not be evaluated — a
    /// pass-by-vacuity).
    fn check(&self, subject: &Cert, issuer: &Cert) -> Vec<Finding>;

    /// Evaluate `subject` against `issuer`, given the `issuer`'s index in the
    /// built leaf→top order (`0` = leaf).
    ///
    /// The default impl ignores the index and delegates to
    /// [`check`](ChainLint::check). Only `chain_path_len_respected` overrides it.
    fn check_with_depth(
        &self,
        subject: &Cert,
        issuer: &Cert,
        _issuer_index: usize,
    ) -> Vec<Finding> {
        self.check(subject, issuer)
    }

    /// Whether this lint is **construction-driven**: its findings come from
    /// [`build_chain`] diagnostics, injected by the engine, rather than from a
    /// pairwise [`check`](ChainLint::check) call.
    ///
    /// Construction-driven lints (`chain_subject_issuer_dn_match`,
    /// `chain_not_in_order`, `chain_issuer_not_in_chain`) are still counted in
    /// the registry and have stable ids, but the engine does NOT call their
    /// `check` (it would only ever return empty). The default is `false`.
    fn is_construction_driven(&self) -> bool {
        false
    }
}

/// The identity and findings of one chain lint over one link.
///
/// Mirrors [`LintOutcome`](crate::LintOutcome) but carries no `Applicability`:
/// the chain pass self-skips by returning empty findings. When serialized (with
/// the `serde` feature) it renders `{ lint_id, source, findings }`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ChainLinkOutcome {
    /// Stable identifier of the chain lint that produced this outcome.
    pub lint_id: &'static str,
    /// The authority the lint enforces (always [`RuleSource::Chain`]).
    pub source: RuleSource,
    /// Problems found; empty when the link passed this lint.
    pub findings: Vec<Finding>,
}

/// Sentinel index marking a [`ChainLinkReport`] as **chain-level** rather than a
/// real `(subject, issuer)` link.
///
/// A chain-level report carries construction-driven findings (the structural
/// integrity verdict, the not-in-order / issuer-not-in-chain Notices) for a set
/// that did NOT build into ≥2 linked positions — e.g. a missing-middle bundle, an
/// unlinkable pair, or a cycle that collapses to a single position. There is no
/// genuine adjacent link to attach these findings to, so both
/// [`subject_index`](ChainLinkReport::subject_index) and
/// [`issuer_index`](ChainLinkReport::issuer_index) are set to this sentinel and
/// the CLI renders the report under the `Chain checks:` header WITHOUT a
/// misleading `Certificate N → Certificate M` arrow.
pub const CHAIN_LEVEL_INDEX: usize = usize::MAX;

/// The full result of running every chain lint over one adjacent link.
///
/// `subject_index` / `issuer_index` are indices into the ORIGINAL input slice,
/// recovered from the built order, so the CLI can label the link
/// `Certificate N → Certificate M` deterministically.
///
/// When both indices equal [`CHAIN_LEVEL_INDEX`] the report is **chain-level**
/// (see [`is_chain_level`](ChainLinkReport::is_chain_level)): it carries
/// construction findings for a set that did not form a real ≥2-link chain, and
/// must be rendered without a link arrow.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ChainLinkReport {
    /// Original-input index of the subject (lower) cert of this link, or
    /// [`CHAIN_LEVEL_INDEX`] for a chain-level report.
    pub subject_index: usize,
    /// Original-input index of the issuer (upper) cert of this link, or
    /// [`CHAIN_LEVEL_INDEX`] for a chain-level report.
    pub issuer_index: usize,
    /// One outcome per chain lint (plus any injected construction-driven
    /// outcomes), in deterministic order.
    pub outcomes: Vec<ChainLinkOutcome>,
}

impl ChainLinkReport {
    /// Whether this report is **chain-level** (carries construction findings for
    /// a set that did not build into a real `(subject, issuer)` link) rather than
    /// a genuine adjacent link.
    ///
    /// A chain-level report has both indices set to [`CHAIN_LEVEL_INDEX`]; the
    /// CLI renders it without a `Certificate N → Certificate M` arrow.
    pub fn is_chain_level(&self) -> bool {
        self.subject_index == CHAIN_LEVEL_INDEX && self.issuer_index == CHAIN_LEVEL_INDEX
    }
}

/// A single adjacent link of the built chain, as a pair of original-input
/// indices (subject below, issuer above).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainLink {
    /// Original-input index of the subject (lower) cert.
    pub subject_index: usize,
    /// Original-input index of the issuer (upper) cert.
    pub issuer_index: usize,
}

/// The normalized leaf→…→top order produced by [`build_chain`].
///
/// [`order`](OrderedChain::order) holds the ORIGINAL input indices in
/// leaf-first order (`order[0]` is the leaf, the last element is the top cert).
/// For a set that does not form a single linear chain the order holds the best
/// deterministic linear walk that could be recovered; the accompanying
/// [`ConstructionDiagnostic`]s describe why it is not clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedChain {
    /// Original-input indices in built leaf→top order.
    pub order: Vec<usize>,
}

impl OrderedChain {
    /// The adjacent links of the built order, leaf-first.
    ///
    /// For an order of `N` indices this yields `N − 1` links `(order[i],
    /// order[i+1])` as `(subject_index, issuer_index)` pairs.
    pub fn links(&self) -> Vec<ChainLink> {
        self.order
            .windows(2)
            .map(|w| ChainLink {
                subject_index: w[0],
                issuer_index: w[1],
            })
            .collect()
    }
}

/// A diagnostic produced by chain construction ([`build_chain`]).
///
/// Each variant maps to a construction-driven lint + severity (see the
/// `build_chain` doc comment):
///
/// | Variant | Lint id | Severity |
/// |---|---|---|
/// | [`Disorder`](ConstructionDiagnostic::Disorder) | `chain_not_in_order` | Notice |
/// | [`MissingMiddleLink`](ConstructionDiagnostic::MissingMiddleLink) | `chain_subject_issuer_dn_match` | Error |
/// | [`Unlinkable`](ConstructionDiagnostic::Unlinkable) | `chain_subject_issuer_dn_match` | Error |
/// | [`Cycle`](ConstructionDiagnostic::Cycle) | `chain_subject_issuer_dn_match` | Error |
/// | [`Fork`](ConstructionDiagnostic::Fork) | `chain_subject_issuer_dn_match` | Warn |
/// | [`MissingTopIssuer`](ConstructionDiagnostic::MissingTopIssuer) | `chain_issuer_not_in_chain` | Notice |
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstructionDiagnostic {
    /// The certs DO form one linear chain, but the input order differed; the
    /// chain was reordered for analysis. Informational, NOT an error.
    Disorder,
    /// A non-top cert whose issuer is not present in the set: a hole in the
    /// middle of the path. Carries the offending cert's original input index.
    MissingMiddleLink(usize),
    /// A cert that belongs to no position in the single chain (it links neither
    /// in nor out). Carries the offending cert's original input index.
    Unlinkable(usize),
    /// A cert with more than one candidate issuer in the set (ambiguous). The
    /// engine still picks deterministically (lowest input index) and proceeds.
    /// Carries the ambiguous cert's original input index.
    Fork(usize),
    /// The linkage edges form a loop (no leaf / no top could be identified).
    Cycle,
    /// The top cert's issuer (e.g. the root) is simply absent from the set —
    /// normal for a `--from-host` presented chain. NOT an error. Carries the top
    /// cert's original input index.
    MissingTopIssuer(usize),
}

/// Whether `subject` is issued by `candidate` per the RFC 5280 linkage rule.
///
/// `subject` is issued by `candidate` iff `subject.issuer_name_der() ==
/// candidate.subject_name_der()` (byte-exact, RFC 5280 §4.1.2.4/§4.1.2.6). When
/// BOTH `subject.authority_key_id_bytes()` and `candidate.subject_key_id_bytes()`
/// are `Some`, they MUST also be equal (this disambiguates several certs sharing
/// a Name). When either is absent, the Name-DER match alone stands
/// (pass-by-vacuity). Any accessor `Err` → `false` (degrade, never panic).
fn is_issued_by(subject: &Cert, candidate: &Cert) -> bool {
    let (Ok(subject_issuer_dn), Ok(candidate_subject_dn)) =
        (subject.issuer_name_der(), candidate.subject_name_der())
    else {
        return false;
    };
    if subject_issuer_dn != candidate_subject_dn {
        return false;
    }
    // AKI/SKI confirmation, only when both key ids are present.
    match (
        subject.authority_key_id_bytes(),
        candidate.subject_key_id_bytes(),
    ) {
        (Ok(Some(aki)), Ok(Some(ski))) => aki == ski,
        // Either id absent (or unreadable) → Name match alone stands.
        _ => true,
    }
}

/// Whether `cert` is self-signed: subject DN == issuer DN, and (when both
/// present) its AKI keyId equals its own SKI. A self-signed cert is the chain
/// anchor, not a one-cert cycle.
fn is_self_signed(cert: &Cert) -> bool {
    let (Ok(subject_dn), Ok(issuer_dn)) = (cert.subject_name_der(), cert.issuer_name_der()) else {
        return false;
    };
    if subject_dn != issuer_dn {
        return false;
    }
    match (cert.authority_key_id_bytes(), cert.subject_key_id_bytes()) {
        (Ok(Some(aki)), Ok(Some(ski))) => aki == ski,
        _ => true,
    }
}

/// Builds the normalized leaf→…→top chain from an unordered set of certs.
///
/// # Linkage rule
///
/// Cert *A* is issued by cert *B* iff `A.issuer_name_der() ==
/// B.subject_name_der()` (byte-exact). When both `A.authority_key_id_bytes()`
/// and `B.subject_key_id_bytes()` are `Some`, they must also be equal
/// (disambiguating certs that share a Name). See the `is_issued_by` helper.
///
/// # Algorithm (deterministic)
///
/// 1. For each cert, compute its candidate in-set issuers (excluding itself,
///    except a self-signed cert is recognized as the anchor).
/// 2. The **leaf** is the cert no other cert links to (no other cert names it as
///    its issuer). Ties (a fork at the bottom) and the no-leaf case (a cycle) are
///    broken / diagnosed below.
/// 3. Walk leaf → issuer → … following the single confirmed edge until a cert
///    has no in-set issuer (the top).
/// 4. **Stable tie-breaks:** whenever a choice exists (a fork, or selecting among
///    unlinked certs) the engine picks the lowest ORIGINAL input index — never a
///    hash- or map-iteration-dependent order. This makes the built order, the
///    link labels, and the snapshots reproducible.
///
/// # Failure modes (diagnostics)
///
/// - [`Disorder`](ConstructionDiagnostic::Disorder): one clean linear chain, but
///   the input order differed → `chain_not_in_order` (Notice).
/// - [`MissingMiddleLink`](ConstructionDiagnostic::MissingMiddleLink): a non-top
///   cert whose issuer is absent → `chain_subject_issuer_dn_match` (Error).
/// - [`Unlinkable`](ConstructionDiagnostic::Unlinkable): a cert with no place in
///   the chain → `chain_subject_issuer_dn_match` (Error).
/// - [`Fork`](ConstructionDiagnostic::Fork): >1 candidate issuer; picked
///   deterministically → `chain_subject_issuer_dn_match` (Warn).
/// - [`Cycle`](ConstructionDiagnostic::Cycle): linkage loops → terminates and
///   reports `chain_subject_issuer_dn_match` (Error).
/// - [`MissingTopIssuer`](ConstructionDiagnostic::MissingTopIssuer): the top's
///   issuer (root) is absent → `chain_issuer_not_in_chain` (Notice).
///
/// Returns the best deterministic linear order recoverable plus the diagnostics.
/// Never panics: any accessor `Err` simply yields no candidate edge.
pub fn build_chain(certs: &[Cert]) -> (OrderedChain, Vec<ConstructionDiagnostic>) {
    let n = certs.len();
    let mut diagnostics = Vec::new();

    if n == 0 {
        return (OrderedChain { order: Vec::new() }, diagnostics);
    }
    if n == 1 {
        // A lone cert: it is its own chain. If self-signed it is its own anchor;
        // otherwise its issuer (root) is simply absent.
        if !is_self_signed(&certs[0]) {
            diagnostics.push(ConstructionDiagnostic::MissingTopIssuer(0));
        }
        return (OrderedChain { order: vec![0] }, diagnostics);
    }

    // candidate_issuers[i] = sorted indices j (j != i) such that certs[i] is
    // issued by certs[j]. Deterministic: indices are visited in ascending order.
    let mut candidate_issuers: Vec<Vec<usize>> = vec![Vec::new(); n];
    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }
            if is_issued_by(&certs[i], &certs[j]) {
                candidate_issuers[i].push(j);
            }
        }
    }

    // Flag forks (a cert with >1 candidate issuer). Deterministic order: by the
    // ambiguous cert's ascending index.
    for (i, issuers) in candidate_issuers.iter().enumerate() {
        if issuers.len() > 1 {
            diagnostics.push(ConstructionDiagnostic::Fork(i));
        }
    }

    // is_issuer_of_someone[j] = some other cert links to certs[j].
    let mut is_issuer_of_someone = vec![false; n];
    for issuers in &candidate_issuers {
        if let Some(&first) = issuers.first() {
            is_issuer_of_someone[first] = true;
        }
    }

    // The leaf is the lowest-index cert that is not an issuer of anyone. (Stable
    // tie-break by ascending index.)
    let leaf = (0..n).find(|&i| !is_issuer_of_someone[i]);

    let Some(leaf) = leaf else {
        // No leaf: every cert issues another → a cycle.
        diagnostics.push(ConstructionDiagnostic::Cycle);
        // Fall back to the input order so callers still have a stable sequence.
        return (
            OrderedChain {
                order: (0..n).collect(),
            },
            diagnostics,
        );
    };

    // Walk leaf → issuer → … following the lowest-index confirmed edge, guarding
    // against loops.
    let mut order = Vec::with_capacity(n);
    let mut visited = vec![false; n];
    let mut current = leaf;
    let mut cycle = false;
    loop {
        if visited[current] {
            // Re-entered a node: a loop in the middle of the walk.
            cycle = true;
            break;
        }
        visited[current] = true;
        order.push(current);
        match candidate_issuers[current].first() {
            Some(&next) => current = next,
            None => break, // reached the top (no in-set issuer)
        }
    }

    if cycle {
        diagnostics.push(ConstructionDiagnostic::Cycle);
    }

    // Any cert not on the walked path is unlinkable / extra (it neither links in
    // along the single chain nor is part of it). Deterministic: ascending index.
    let on_path = visited; // visited now marks exactly the walked path
    for (i, &seen) in on_path.iter().enumerate() {
        if !seen {
            diagnostics.push(ConstructionDiagnostic::Unlinkable(i));
        }
    }

    // The top cert of the walked chain.
    if let Some(&top) = order.last() {
        if is_self_signed(&certs[top]) {
            // Self-signed top is its own anchor: no missing issuer.
        } else if candidate_issuers[top].is_empty() {
            // No in-set issuer for the top.
            //
            // Distinguish "missing root at the TOP" (normal — Notice) from a
            // "missing MIDDLE link" (Error). It is a middle-link hole when the
            // top cert is itself an end-entity (not a CA): a non-CA cert should
            // not be the top of a real issuance path, so its absent issuer is a
            // hole rather than a merely-absent root.
            match certs[top].is_ca() {
                Ok(true) => diagnostics.push(ConstructionDiagnostic::MissingTopIssuer(top)),
                Ok(false) => diagnostics.push(ConstructionDiagnostic::MissingMiddleLink(top)),
                // CA-ness unreadable → treat as the benign missing-root Notice.
                Err(_) => diagnostics.push(ConstructionDiagnostic::MissingTopIssuer(top)),
            }
        }
    }

    // Disorder: the set forms a clean single linear chain (all certs on the
    // path, no cycle) but the built order differs from the input order.
    let clean_linear = !cycle && order.len() == n;
    if clean_linear {
        let in_input_order = order.iter().enumerate().all(|(pos, &idx)| pos == idx);
        if !in_input_order {
            diagnostics.push(ConstructionDiagnostic::Disorder);
        }
    }

    (OrderedChain { order }, diagnostics)
}

/// A collection of chain lints and the engine that runs them over a built chain.
///
/// Build the standard set with [`default_chain_registry`]. The registry holds
/// the 7 always-on chain lints (plus `chain_signature_valid` when the `verify`
/// feature is enabled).
pub struct ChainRegistry {
    lints: Vec<Box<dyn ChainLint>>,
}

impl ChainRegistry {
    /// Creates an empty registry with no chain lints.
    pub fn new() -> ChainRegistry {
        ChainRegistry { lints: Vec::new() }
    }

    /// Creates a registry from an explicit set of chain lints.
    pub fn with_lints(lints: Vec<Box<dyn ChainLint>>) -> ChainRegistry {
        ChainRegistry { lints }
    }

    /// The number of chain lints registered.
    pub fn len(&self) -> usize {
        self.lints.len()
    }

    /// Whether the registry holds no chain lints.
    pub fn is_empty(&self) -> bool {
        self.lints.is_empty()
    }

    /// Runs the chain pass over `certs`.
    ///
    /// Returns an EMPTY `Vec` when `certs.len() < 2` (no chain to lint — a lone
    /// leaf or empty slice has nothing to say). Otherwise it:
    ///
    /// 1. calls [`build_chain`] to normalize order and collect diagnostics;
    /// 2. injects the construction-driven findings
    ///    (`chain_subject_issuer_dn_match` Error/Warn, `chain_not_in_order`
    ///    Notice on the leaf link; `chain_issuer_not_in_chain` Notice on the top
    ///    link); and
    /// 3. runs every pairwise [`ChainLint`] over each adjacent link of the BUILT
    ///    order.
    ///
    /// The result is one [`ChainLinkReport`] per built link, in leaf→top order.
    /// `subject_index` / `issuer_index` are ORIGINAL input indices so the CLI can
    /// label `Certificate N → Certificate M`.
    ///
    /// # Collapsed / broken chains (`< 2` built links)
    ///
    /// When `certs.len() >= 2` but the built order collapses to fewer than two
    /// linked positions (a genuinely broken set: a missing middle link, an
    /// unlinkable pair, or a cycle), there is no real adjacent link to attach the
    /// construction-driven findings to. Rather than silently drop them, `run`
    /// emits a single **chain-level** [`ChainLinkReport`] (both indices set to
    /// [`CHAIN_LEVEL_INDEX`], so [`ChainLinkReport::is_chain_level`] is `true`)
    /// carrying the construction outcomes. This surfaces the
    /// `chain_subject_issuer_dn_match` Error (and any construction Notice) so it
    /// folds into the exit code; the CLI renders it without a link arrow. The
    /// construction outcomes are emitted on this single report exactly once (never
    /// duplicated onto a real link, since no real link exists in this case).
    pub fn run(&self, certs: &[Cert]) -> Vec<ChainLinkReport> {
        if certs.len() < 2 {
            return Vec::new();
        }

        let (chain, diagnostics) = build_chain(certs);
        let links = chain.links();

        let construction = construction_outcomes(&diagnostics, certs);

        if links.is_empty() {
            // A ≥2-cert set that built to a single position (broken chain). There
            // is no real link, so surface the construction-driven findings on one
            // synthetic chain-level report instead of dropping them. Carry both
            // the leaf-level outcomes (structural-integrity verdict + not-in-order
            // Notice) and the top-level outcome (issuer-not-in-chain Notice), each
            // construction lint id appearing exactly once.
            let mut outcomes = construction.leaf;
            outcomes.extend(construction.top);
            return vec![ChainLinkReport {
                subject_index: CHAIN_LEVEL_INDEX,
                issuer_index: CHAIN_LEVEL_INDEX,
                outcomes,
            }];
        }

        let last_link = links.len() - 1;
        let mut reports = Vec::with_capacity(links.len());
        for (link_pos, link) in links.iter().enumerate() {
            let subject = &certs[link.subject_index];
            let issuer = &certs[link.issuer_index];

            let mut outcomes = Vec::new();

            // Inject the leaf-link construction outcomes first (chain-wide
            // structural-integrity verdict + disorder Notice).
            if link_pos == 0 {
                outcomes.extend(construction.leaf.iter().cloned());
            }

            // Pairwise link lints over the BUILT link, in registration order.
            // The issuer sits at order position `link_pos + 1` (0 = leaf), which
            // chain_path_len_respected uses as the issuer's depth.
            let issuer_order_index = link_pos + 1;
            for lint in &self.lints {
                // Construction-driven lints' outcomes are injected from the
                // build_chain diagnostics (see construction_outcomes); skip their
                // pairwise check to avoid duplicate id entries per link.
                if lint.is_construction_driven() {
                    continue;
                }
                let findings = lint.check_with_depth(subject, issuer, issuer_order_index);
                outcomes.push(ChainLinkOutcome {
                    lint_id: lint.id(),
                    source: lint.source(),
                    findings,
                });
            }

            // Inject the top-link construction outcome last (issuer-not-in-chain
            // Notice on the top cert).
            if link_pos == last_link {
                outcomes.extend(construction.top.iter().cloned());
            }

            reports.push(ChainLinkReport {
                subject_index: link.subject_index,
                issuer_index: link.issuer_index,
                outcomes,
            });
        }

        reports
    }
}

impl Default for ChainRegistry {
    fn default() -> Self {
        default_chain_registry()
    }
}

/// The construction-driven outcomes, split into those that attach to the leaf
/// link (chain-wide) and the top link (issuer-not-in-chain).
struct ConstructionOutcomes {
    leaf: Vec<ChainLinkOutcome>,
    top: Vec<ChainLinkOutcome>,
}

/// Maps construction diagnostics to the construction-driven lint outcomes.
///
/// `chain_subject_issuer_dn_match` (structural integrity) and `chain_not_in_order`
/// attach to the leaf link (they describe the whole set); `chain_issuer_not_in_chain`
/// attaches to the top link (the top cert whose issuer is absent). Every
/// construction-driven lint id appears exactly once (with an empty findings list
/// when it has nothing to report) so the registry's chain ids are always present
/// and the output is snapshot-stable.
fn construction_outcomes(
    diagnostics: &[ConstructionDiagnostic],
    certs: &[Cert],
) -> ConstructionOutcomes {
    let mut dn_findings = Vec::new();
    let mut not_in_order_findings = Vec::new();
    let mut issuer_absent_findings = Vec::new();

    for diag in diagnostics {
        match diag {
            ConstructionDiagnostic::Disorder => {
                not_in_order_findings.push(Finding {
                    severity: Severity::Notice,
                    message: "certificates were not in leaf-to-root order; reordered for analysis"
                        .to_string(),
                });
            }
            ConstructionDiagnostic::MissingMiddleLink(i) => {
                dn_findings.push(Finding {
                    severity: Severity::Error,
                    message: format!(
                        "certificate {} ({}) links to no issuer in the presented set (missing middle link / broken chain)",
                        i + 1,
                        cert_dn_summary(certs.get(*i))
                    ),
                });
            }
            ConstructionDiagnostic::Unlinkable(i) => {
                dn_findings.push(Finding {
                    severity: Severity::Error,
                    message: format!(
                        "certificate {} ({}) does not link into the presented chain (unlinkable / extra certificate)",
                        i + 1,
                        cert_dn_summary(certs.get(*i))
                    ),
                });
            }
            ConstructionDiagnostic::Fork(i) => {
                dn_findings.push(Finding {
                    severity: Severity::Warn,
                    message: format!(
                        "certificate {} ({}) has more than one candidate issuer in the presented set (ambiguous chain; the lowest-index issuer was chosen)",
                        i + 1,
                        cert_dn_summary(certs.get(*i))
                    ),
                });
            }
            ConstructionDiagnostic::Cycle => {
                dn_findings.push(Finding {
                    severity: Severity::Error,
                    message: "the presented certificates form an issuance cycle (no single leaf-to-root chain)"
                        .to_string(),
                });
            }
            ConstructionDiagnostic::MissingTopIssuer(i) => {
                issuer_absent_findings.push(Finding {
                    severity: Severity::Notice,
                    message: format!(
                        "issuer (e.g. root) of certificate {} ({}) not present in the presented chain; trust to a root is verified separately by the connection verdict",
                        i + 1,
                        cert_dn_summary(certs.get(*i))
                    ),
                });
            }
        }
    }

    let leaf = vec![
        ChainLinkOutcome {
            lint_id: "chain_subject_issuer_dn_match",
            source: RuleSource::Chain,
            findings: dn_findings,
        },
        ChainLinkOutcome {
            lint_id: "chain_not_in_order",
            source: RuleSource::Chain,
            findings: not_in_order_findings,
        },
    ];
    let top = vec![ChainLinkOutcome {
        lint_id: "chain_issuer_not_in_chain",
        source: RuleSource::Chain,
        findings: issuer_absent_findings,
    }];

    ConstructionOutcomes { leaf, top }
}

/// A short human-readable DN summary for a cert (its RFC 4514-style subject), or
/// a placeholder when the cert or its subject cannot be read. Never dumps raw
/// bytes.
fn cert_dn_summary(cert: Option<&Cert>) -> String {
    match cert.map(Cert::subject_rfc4514) {
        Some(Ok(dn)) if !dn.is_empty() => dn,
        _ => "subject unavailable".to_string(),
    }
}

/// The standard chain-lint registry.
///
/// Registers the 7 always-on chain lints in a deterministic order:
///
/// 1. `chain_subject_issuer_dn_match` (construction-driven, structural integrity)
/// 2. `chain_not_in_order` (construction-driven, Notice)
/// 3. `chain_issuer_not_in_chain` (construction-driven, Notice)
/// 4. `chain_aki_ski_match`
/// 5. `chain_issuer_is_ca`
/// 6. `chain_path_len_respected`
/// 7. `chain_validity_nested`
///
/// When the `verify` feature is enabled, `chain_signature_valid` is appended as
/// the 8th lint. So the registry holds **7 without `verify`, 8 with `verify`**.
///
/// The three construction-driven lints are registry entries whose findings are
/// injected by the engine from [`build_chain`] diagnostics rather than from a
/// pairwise `check`; they are represented here by no-op pairwise lints so they
/// stay counted and ordered (the engine never calls their `check` — it injects
/// their outcomes directly, see [`ChainRegistry::run`]). To avoid double-running
/// them, they are NOT in the pairwise-lint list; instead they are counted via the
/// id roster below.
pub fn default_chain_registry() -> ChainRegistry {
    // The construction-driven lints are not pairwise: their outcomes are injected
    // by the engine. They are still counted as registry lints via dedicated
    // no-op marker types so `len()` reflects the full chain-lint roster.
    #[cfg_attr(not(feature = "verify"), allow(unused_mut))]
    let mut lints: Vec<Box<dyn ChainLint>> = vec![
        Box::new(chain::SubjectIssuerDnMatch::new()),
        Box::new(chain::NotInOrder::new()),
        Box::new(chain::IssuerNotInChain::new()),
        Box::new(chain::AkiSkiMatch::new()),
        Box::new(chain::IssuerIsCa::new()),
        Box::new(chain::PathLenRespected::new()),
        Box::new(chain::ValidityNested::new()),
    ];

    #[cfg(feature = "verify")]
    lints.push(Box::new(chain::SignatureValid::new()));

    ChainRegistry { lints }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    // Three real, linked certs minted with openssl: a leaf issued by an
    // intermediate issued by a self-signed root. All RSA / SHA-256. Subject and
    // issuer DNs link by Name, and SKI/AKI are present and consistent.
    const LEAF_PEM: &[u8] = include_bytes!("chain_testdata/link_leaf.pem");
    const INTER_PEM: &[u8] = include_bytes!("chain_testdata/link_inter.pem");
    const ROOT_PEM: &[u8] = include_bytes!("chain_testdata/link_root.pem");

    fn load_one(pem: &[u8]) -> Cert {
        let mut certs = Cert::from_pem(pem).expect("fixture must parse");
        certs.pop().expect("fixture must contain one cert")
    }

    fn leaf() -> Cert {
        load_one(LEAF_PEM)
    }
    fn inter() -> Cert {
        load_one(INTER_PEM)
    }
    fn root() -> Cert {
        load_one(ROOT_PEM)
    }

    fn has_diag(diags: &[ConstructionDiagnostic], want: &ConstructionDiagnostic) -> bool {
        diags.iter().any(|d| d == want)
    }

    mod registry {
        use super::*;

        #[test]
        fn holds_seven_lints_without_verify() {
            let reg = default_chain_registry();
            #[cfg(not(feature = "verify"))]
            assert_eq!(reg.len(), 7, "7 chain lints when verify is off");
            #[cfg(feature = "verify")]
            assert_eq!(reg.len(), 8, "8 chain lints when verify is on");
        }

        #[cfg(feature = "verify")]
        #[test]
        fn holds_eight_lints_with_verify() {
            let reg = default_chain_registry();
            assert_eq!(reg.len(), 8);
        }

        #[test]
        fn all_lints_are_chain_source() {
            let reg = default_chain_registry();
            for lint in &reg.lints {
                assert_eq!(lint.source(), RuleSource::Chain);
            }
        }

        #[test]
        fn ids_are_in_registration_order() {
            let reg = default_chain_registry();
            let ids: Vec<&str> = reg.lints.iter().map(|l| l.id()).collect();
            assert_eq!(ids[0], "chain_subject_issuer_dn_match");
            assert_eq!(ids[1], "chain_not_in_order");
            assert_eq!(ids[2], "chain_issuer_not_in_chain");
            assert_eq!(ids[3], "chain_aki_ski_match");
            assert_eq!(ids[4], "chain_issuer_is_ca");
            assert_eq!(ids[5], "chain_path_len_respected");
            assert_eq!(ids[6], "chain_validity_nested");
            #[cfg(feature = "verify")]
            assert_eq!(ids[7], "chain_signature_valid");
        }

        #[cfg(feature = "verify")]
        #[test]
        fn signature_lint_present_only_with_verify() {
            let reg = default_chain_registry();
            assert!(reg.lints.iter().any(|l| l.id() == "chain_signature_valid"));
        }
    }

    mod run {
        use super::*;

        #[test]
        fn empty_for_zero_certs() {
            let reg = default_chain_registry();
            assert!(reg.run(&[]).is_empty());
        }

        #[test]
        fn empty_for_one_cert() {
            let reg = default_chain_registry();
            assert!(reg.run(&[leaf()]).is_empty());
        }

        /// Finds the `chain_subject_issuer_dn_match` outcome's findings across
        /// all reports (there is exactly one such outcome carrier).
        fn dn_match_findings(reports: &[ChainLinkReport]) -> Vec<&Finding> {
            reports
                .iter()
                .flat_map(|r| r.outcomes.iter())
                .filter(|o| o.lint_id == "chain_subject_issuer_dn_match")
                .flat_map(|o| o.findings.iter())
                .collect()
        }

        #[test]
        fn missing_middle_two_cert_set_surfaces_dn_match_error() {
            // leaf + root only (no intermediate): the leaf is a non-CA whose
            // issuer is absent → MissingMiddleLink. The built order collapses to a
            // single position (leaf), so there are no real links — the engine must
            // STILL surface the structural-integrity Error on a chain-level report.
            let reg = default_chain_registry();
            let reports = reg.run(&[leaf(), root()]);
            assert_eq!(reports.len(), 1, "one chain-level report for a broken set");
            assert!(
                reports[0].is_chain_level(),
                "the broken-set report must be chain-level (no real link)"
            );
            assert_eq!(reports[0].subject_index, CHAIN_LEVEL_INDEX);
            assert_eq!(reports[0].issuer_index, CHAIN_LEVEL_INDEX);

            let dn = dn_match_findings(&reports);
            assert!(
                dn.iter().any(|f| f.severity == Severity::Error),
                "expected a chain_subject_issuer_dn_match Error, got {dn:?}"
            );

            // Each construction-driven lint id appears exactly once.
            let dn_count = reports[0]
                .outcomes
                .iter()
                .filter(|o| o.lint_id == "chain_subject_issuer_dn_match")
                .count();
            assert_eq!(dn_count, 1, "the dn-match outcome is not duplicated");
        }

        #[test]
        fn unlinkable_two_cert_set_surfaces_dn_match_error() {
            // The good leaf + an unrelated self-signed stray do not link → the set
            // collapses to a single position and the stray is unlinkable. The
            // engine must surface a chain-level dn-match Error.
            let reg = default_chain_registry();
            let stray = load_one(STRAY_PEM);
            let reports = reg.run(&[leaf(), stray]);
            assert_eq!(reports.len(), 1);
            assert!(reports[0].is_chain_level());
            let dn = dn_match_findings(&reports);
            assert!(
                dn.iter().any(|f| f.severity == Severity::Error),
                "expected a chain_subject_issuer_dn_match Error, got {dn:?}"
            );
        }

        #[test]
        fn broken_set_run_is_deterministic() {
            let reg = default_chain_registry();
            let a = reg.run(&[leaf(), root()]);
            let b = reg.run(&[leaf(), root()]);
            assert_eq!(a, b, "broken-set surfacing must be deterministic");
        }

        #[test]
        fn well_formed_chain_emits_no_chain_level_report() {
            // The happy path must be byte-for-byte unchanged: only real links, no
            // chain-level synthetic report.
            let reg = default_chain_registry();
            let reports = reg.run(&[leaf(), inter(), root()]);
            assert!(
                reports.iter().all(|r| !r.is_chain_level()),
                "a well-formed chain must not emit a chain-level report"
            );
        }

        #[test]
        fn clean_three_cert_chain_has_no_error_or_warn() {
            let reg = default_chain_registry();
            let reports = reg.run(&[leaf(), inter(), root()]);
            assert_eq!(reports.len(), 2, "N-1 links for a 3-cert chain");
            for report in &reports {
                for outcome in &report.outcomes {
                    for finding in &outcome.findings {
                        assert!(
                            finding.severity < Severity::Error,
                            "clean chain should have no Error/Warn, got {:?} from {}",
                            finding.severity,
                            outcome.lint_id
                        );
                    }
                }
            }
        }
    }

    mod build {
        use super::*;

        #[test]
        fn already_ordered_chain_keeps_input_order_no_disorder() {
            let (chain, diags) = build_chain(&[leaf(), inter(), root()]);
            assert_eq!(chain.order, vec![0, 1, 2]);
            assert!(!has_diag(&diags, &ConstructionDiagnostic::Disorder));
        }

        #[test]
        fn shuffled_chain_is_reordered_with_disorder_notice() {
            // Input order root, leaf, inter → must rebuild to leaf, inter, root.
            let (chain, diags) = build_chain(&[root(), leaf(), inter()]);
            // order holds ORIGINAL indices: leaf=1, inter=2, root=0.
            assert_eq!(chain.order, vec![1, 2, 0]);
            assert!(has_diag(&diags, &ConstructionDiagnostic::Disorder));
        }

        #[test]
        fn missing_middle_link_is_error() {
            // leaf + root only: the leaf's issuer (the intermediate) is absent.
            let (_chain, diags) = build_chain(&[leaf(), root()]);
            // The leaf cannot link to the root, so the leaf is the top and is a
            // non-CA whose issuer is absent → missing middle link.
            assert!(
                diags
                    .iter()
                    .any(|d| matches!(d, ConstructionDiagnostic::MissingMiddleLink(_))),
                "expected MissingMiddleLink, got {diags:?}"
            );
        }

        #[test]
        fn missing_top_root_is_notice() {
            // leaf + inter only: a valid partial chain whose top (the inter, a CA)
            // has no in-set issuer → missing root Notice, not an error.
            let (chain, diags) = build_chain(&[leaf(), inter()]);
            assert_eq!(chain.order, vec![0, 1]);
            assert!(
                diags
                    .iter()
                    .any(|d| matches!(d, ConstructionDiagnostic::MissingTopIssuer(_))),
                "expected MissingTopIssuer, got {diags:?}"
            );
            assert!(!diags.iter().any(|d| matches!(
                d,
                ConstructionDiagnostic::MissingMiddleLink(_) | ConstructionDiagnostic::Cycle
            )));
        }

        #[test]
        fn self_signed_root_alone_has_no_missing_issuer() {
            let (chain, diags) = build_chain(&[root()]);
            assert_eq!(chain.order, vec![0]);
            assert!(
                diags.is_empty(),
                "self-signed root needs no issuer: {diags:?}"
            );
        }

        #[test]
        fn unlinkable_extra_cert_is_error() {
            // A self-signed root from a DIFFERENT, unrelated hierarchy alongside a
            // clean leaf→inter pair. The good leaf/inter form the chain; the
            // unrelated root links to nothing → unlinkable.
            let good_leaf = leaf();
            let good_inter = inter();
            // Use the good root as the "extra": it is self-signed and the inter
            // links to it, so to get an unlinkable we instead drop the inter.
            // Construct: leaf + root (no inter) already covered. For unlinkable we
            // add a cert that neither issues nor is issued: reuse leaf twice would
            // be a fork. Instead use a cross set: leaf, inter, root, and an
            // unrelated self-signed cert.
            let stray = load_one(STRAY_PEM);
            let (_chain, diags) = build_chain(&[good_leaf, good_inter, root(), stray]);
            assert!(
                diags
                    .iter()
                    .any(|d| matches!(d, ConstructionDiagnostic::Unlinkable(_))),
                "expected Unlinkable, got {diags:?}"
            );
        }

        #[test]
        fn running_twice_on_shuffled_input_is_identical() {
            let input = [root(), leaf(), inter()];
            let (chain_a, diags_a) = build_chain(&input);
            let (chain_b, diags_b) = build_chain(&input);
            assert_eq!(chain_a, chain_b);
            assert_eq!(diags_a, diags_b);
        }
    }

    // A self-signed cert from an unrelated hierarchy (different DN, no link to
    // the leaf/inter/root set). Used for the unlinkable-extra test.
    const STRAY_PEM: &[u8] = include_bytes!("chain_testdata/link_stray.pem");
}
