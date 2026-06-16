//! The `hygiene_not_expired` lint.
//!
//! Flags certificates whose validity window has already ended. This is
//! informational hygiene, **not** an RFC 5280 hard failure: an expired
//! certificate is still a structurally valid certificate, it simply should no
//! longer be trusted. RFC 5280 §4.1.2.5 ("Validity") defines the window; whether
//! "now" falls outside it is a path-validation concern (RFC 5280 §6.1), so we
//! surface it as a [`Severity::Warn`] rather than an `Error`/`Fatal`.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::cert::Cert;
use crate::{Applicability, Finding, Lint, RuleSource, Severity};

/// Lint that warns when a certificate has already expired.
///
/// "Expired" means the current time is strictly after the certificate's
/// `notAfter` instant.
#[derive(Debug, Clone)]
pub struct NotExpired {
    /// The instant treated as "now", expressed as a Unix timestamp (seconds).
    ///
    /// `None` means "use the system clock at check time". Tests pin this to a
    /// fixed value to make the comparison deterministic.
    now_unix: Option<i64>,
}

impl NotExpired {
    /// Creates the lint using the system clock as "now".
    pub fn new() -> Self {
        NotExpired { now_unix: None }
    }

    /// Creates the lint with a fixed "now", expressed as a Unix timestamp in
    /// seconds. Intended for deterministic testing.
    pub fn with_now_unix(now_unix: i64) -> Self {
        NotExpired {
            now_unix: Some(now_unix),
        }
    }

    /// Resolves the instant to compare against, as a Unix timestamp in seconds.
    ///
    /// Falls back to `0` (the Unix epoch) if the system clock is somehow before
    /// the epoch; in that degenerate case nothing is reported as expired, which
    /// fails safe for an informational hygiene check.
    fn now_unix(&self) -> i64 {
        match self.now_unix {
            Some(t) => t,
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        }
    }
}

impl Default for NotExpired {
    fn default() -> Self {
        NotExpired::new()
    }
}

/// Pure expiry decision: returns the finding message if `now` is strictly after
/// `not_after`, otherwise `None`. Kept separate so it can be unit-tested without
/// constructing a certificate.
fn expired_message(not_after_unix: i64, now_unix: i64) -> Option<String> {
    if now_unix > not_after_unix {
        Some(format!(
            "certificate expired: notAfter is {not_after_unix} (Unix seconds), now is {now_unix}"
        ))
    } else {
        None
    }
}

impl Lint for NotExpired {
    fn id(&self) -> &'static str {
        "hygiene_not_expired"
    }

    fn source(&self) -> RuleSource {
        RuleSource::Hygiene
    }

    fn applies(&self, _cert: &Cert) -> Applicability {
        Applicability::Applies
    }

    fn check(&self, cert: &Cert) -> Vec<Finding> {
        // If the validity window cannot be read, report nothing here: parsing
        // problems are the concern of the parse stage and other lints, not this
        // informational hygiene check.
        let not_after = match cert.not_after() {
            Ok(t) => t.timestamp(),
            Err(_) => return Vec::new(),
        };

        match expired_message(not_after, self.now_unix()) {
            Some(message) => vec![Finding {
                severity: Severity::Warn,
                message,
            }],
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod expired_message {
        use super::*;

        #[test]
        fn reports_when_now_is_after_not_after() {
            let msg = expired_message(1_000, 2_000);
            assert!(msg.is_some());
        }

        #[test]
        fn silent_when_now_equals_not_after() {
            assert!(expired_message(1_000, 1_000).is_none());
        }

        #[test]
        fn silent_when_now_is_before_not_after() {
            assert!(expired_message(2_000, 1_000).is_none());
        }
    }

    mod check {
        use super::*;

        // The lint is exercised end-to-end through its public API against a real
        // certificate. The PEM is embedded inline to keep this in-file test
        // self-contained (the tester adds the shared `testdata/` fixtures
        // separately). This is a self-signed RSA-2048 certificate whose validity
        // window is notBefore=2010-01-01, notAfter=2011-01-01 — already expired.
        use crate::cert::Cert;

        const EXPIRED_PEM: &[u8] = b"\
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

        fn load_one(pem: &[u8]) -> Cert {
            let mut certs = Cert::from_pem(pem).expect("fixture must parse");
            certs.pop().expect("fixture must contain one cert")
        }

        #[test]
        fn warns_when_cert_is_expired() {
            let cert = load_one(EXPIRED_PEM);
            // "now" well past the fixture's notAfter.
            let lint = NotExpired::with_now_unix(4_102_444_800); // 2100-01-01
            let findings = lint.check(&cert);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, Severity::Warn);
        }

        #[test]
        fn passes_when_cert_not_yet_expired() {
            let cert = load_one(EXPIRED_PEM);
            // "now" well before the fixture's notAfter.
            let lint = NotExpired::with_now_unix(0); // 1970
            let findings = lint.check(&cert);
            assert!(findings.is_empty());
        }

        #[test]
        fn applies_always() {
            let cert = load_one(EXPIRED_PEM);
            assert_eq!(NotExpired::new().applies(&cert), Applicability::Applies);
        }
    }
}
