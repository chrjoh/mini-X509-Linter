//! The `cabf_smime_crl_distribution_points_http` lint
//! (CA/Browser Forum S/MIME BR §7.1.2.3).
//!
//! S/MIME BR §7.1.2.3: every CRL Distribution Point `fullName` URI MUST use the
//! `http` or `https` scheme. Each CRL-DP URI with any other scheme (e.g.
//! `ldap://`, `ftp://`) is flagged as a [`Severity::Error`] (one finding per
//! offending URI).
//!
//! If the CRL-DP extension is absent (no URIs), nothing is emitted — that is
//! [`CrlDistributionPointsPresent`](super::CrlDistributionPointsPresent)'s
//! concern.
//!
//! # Scheme-matching policy
//!
//! A URI is accepted when its scheme (the substring before the first `:`,
//! compared ASCII case-insensitively) is exactly `http` or `https`. A URI with
//! no `:` has no scheme and is flagged.
//!
//! emailProtection-EKU-gated (see [`applies_to_smime_leaf`]).

use super::applies_to_smime_leaf;
use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Requires every CRL-DP `fullName` URI to use the `http`/`https` scheme.
#[derive(Debug, Clone, Default)]
pub struct CrlDistributionPointsHttp;

impl CrlDistributionPointsHttp {
    /// Creates the lint.
    pub fn new() -> Self {
        CrlDistributionPointsHttp
    }
}

/// Whether `uri` uses the `http` or `https` scheme (ASCII case-insensitive).
fn is_http_scheme(uri: &str) -> bool {
    match uri.split_once(':') {
        Some((scheme, _)) => {
            let scheme = scheme.to_ascii_lowercase();
            scheme == "http" || scheme == "https"
        }
        None => false,
    }
}

/// Pure decision: one [`Finding`] per CRL-DP URI that is not `http`/`https`.
///
/// Kept separate so the scheme policy can be unit-tested with plain strings.
fn evaluate(uris: &[String]) -> Vec<Finding> {
    uris.iter()
        .filter(|uri| !is_http_scheme(uri))
        .map(|uri| Finding {
            severity: Severity::Error,
            message: format!(
                "CRL Distribution Point URI \"{uri}\" does not use the http/https scheme; \
                 CA/Browser Forum S/MIME BR §7.1.2.3 requires every fullName URI to be http or https"
            ),
        })
        .collect()
}

impl Lint for CrlDistributionPointsHttp {
    fn id(&self) -> &'static str {
        "cabf_smime_crl_distribution_points_http"
    }

    fn source(&self) -> RuleSource {
        RuleSource::CabfSmime
    }

    fn applies(&self, cert: &Cert) -> Applicability {
        applies_to_smime_leaf(cert)
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // Fail policy: unreadable CRL-DP URIs mean we cannot evaluate; emit
        // nothing.
        match cert.crl_distribution_point_uris() {
            Ok(uris) => evaluate(&uris),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;

    fn good_cert() -> Cert {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
        let bytes = std::fs::read(path).unwrap();
        let mut certs = Cert::from_pem(&bytes).unwrap();
        certs.remove(0)
    }

    fn s(v: &str) -> String {
        v.to_string()
    }

    mod evaluate {
        use super::*;

        #[test]
        fn passes_when_no_uris() {
            assert!(evaluate(&[]).is_empty());
        }

        #[test]
        fn passes_for_http_and_https() {
            assert!(
                evaluate(&[
                    s("http://crl.example.com/a.crl"),
                    s("https://x.example/b.crl")
                ])
                .is_empty()
            );
        }

        #[test]
        fn scheme_match_is_case_insensitive() {
            assert!(evaluate(&[s("HTTP://crl.example.com/a.crl")]).is_empty());
        }

        #[test]
        fn fires_for_ldap_uri() {
            let findings = evaluate(&[s("ldap://crl.example.com/a.crl")]);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Error);
            assert!(findings[0].message.contains("ldap://crl.example.com/a.crl"));
        }

        #[test]
        fn emits_one_finding_per_offending_uri() {
            let findings = evaluate(&[
                s("ldap://crl.example.com/a.crl"),
                s("http://ok.example/b.crl"),
                s("ftp://crl.example.com/c.crl"),
            ]);
            assert_eq!(findings.len(), 2);
        }
    }

    #[test]
    fn not_applicable_for_non_smime_leaf() {
        let cert = good_cert();
        assert_eq!(
            CrlDistributionPointsHttp::new().applies(&cert),
            Applicability::NotApplicable
        );
    }

    #[test]
    fn has_correct_id_and_source() {
        let lint = CrlDistributionPointsHttp::new();
        assert_eq!(lint.id(), "cabf_smime_crl_distribution_points_http");
        assert_eq!(lint.source(), RuleSource::CabfSmime);
    }
}
