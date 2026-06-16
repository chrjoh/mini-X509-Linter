//! Core contract for the mini-X509-Linter.
//!
//! This crate defines the engine-agnostic types every lint codes against:
//! the [`Severity`] / [`Finding`] / [`LintOutcome`] result model, the
//! [`RuleSource`] provenance enum, the [`Applicability`] gate, and the
//! object-safe [`Lint`] trait itself.
//!
//! The crate is intentionally network-free: all TLS/retrieval logic lives in
//! the separate `fetch` crate.
//!
//! # The lint contract
//!
//! A [`Lint`] is asked two things about a [`Cert`]:
//!
//! 1. [`Lint::applies`] — is this lint's rule even relevant to the certificate?
//! 2. [`Lint::check`] — if so, what (if anything) is wrong with it?
//!
//! The engine only calls [`Lint::check`] when [`Lint::applies`] returned
//! [`Applicability::Applies`]. An empty `Vec<Finding>` from `check` means the
//! certificate **passed** that lint — there is deliberately no `Pass` severity.

#![deny(missing_docs)]

pub mod cert;
mod finding;
pub mod lints;
pub mod registry;
mod source;

pub use cert::Cert;
pub use finding::{Applicability, Finding, LintOutcome, Severity};
pub use registry::{Registry, default_registry};
pub use source::RuleSource;

/// A single certificate-linting rule.
///
/// Implementors describe one rule and how to evaluate it against a [`Cert`].
/// The trait is object-safe so the engine can hold `Vec<Box<dyn Lint>>`.
///
/// # Invariants
///
/// - [`check`](Lint::check) returning an empty `Vec` means the certificate
///   passed this lint; there is no "pass" finding.
/// - The engine only calls [`check`](Lint::check) when
///   [`applies`](Lint::applies) returned [`Applicability::Applies`]. A lint may
///   therefore assume in `check` that its preconditions hold.
pub trait Lint {
    /// Stable, unique identifier for this lint (e.g. `"not_expired"`).
    fn id(&self) -> &'static str;

    /// The authority this lint enforces.
    fn source(&self) -> RuleSource;

    /// Whether this lint's rule is relevant to `cert`.
    fn applies(&self, cert: &Cert) -> Applicability;

    /// Evaluate the rule against `cert`, returning one [`Finding`] per problem.
    ///
    /// An empty `Vec` means the certificate passed. Only called by the engine
    /// when [`applies`](Lint::applies) returned [`Applicability::Applies`].
    fn check(&self, cert: &Cert) -> Vec<Finding>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_notice_below_fatal() {
        assert!(Severity::Notice < Severity::Warn);
        assert!(Severity::Warn < Severity::Error);
        assert!(Severity::Error < Severity::Fatal);
    }

    #[test]
    fn lint_trait_is_object_safe() {
        struct Dummy;
        impl Lint for Dummy {
            fn id(&self) -> &'static str {
                "dummy"
            }
            fn source(&self) -> RuleSource {
                RuleSource::Hygiene
            }
            fn applies(&self, _cert: &Cert) -> Applicability {
                Applicability::Applies
            }
            fn check(&self, _cert: &Cert) -> Vec<Finding> {
                Vec::new()
            }
        }

        let lint: Box<dyn Lint> = Box::new(Dummy);
        assert_eq!(lint.id(), "dummy");
        assert_eq!(lint.source(), RuleSource::Hygiene);
    }
}
