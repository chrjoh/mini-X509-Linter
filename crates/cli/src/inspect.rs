//! The certificate **inspection** summary renderer for `--info`.
//!
//! Builds a deterministic, stable-field-order summary of a certificate's *own*
//! values (version, serial, subject/issuer DN, validity, signature algorithm,
//! public key, BasicConstraints, KeyUsage, SubjectAltName) from the read-only
//! [`Cert`] facade inspection accessors. The summary is purely additive display;
//! it does not touch the lint engine.
//!
//! Two surfaces are exposed:
//!
//! - [`render_summary_text`] — a human-readable, snapshot-friendly text block
//!   (used by `--info` with `--format text`).
//! - [`build_summary_json`] — an owned [`serde_json::Value`] mirroring the text
//!   fields (used by `--info` with `--format json`, folded into the
//!   `{ "summary", "lints" }` envelope by `main.rs`).
//!
//! The JSON object is built directly as a [`serde_json::Value`] (rather than via
//! a `Serialize` derive) so the renderer needs no direct `serde` dependency; the
//! cli crate already depends on `serde_json`.
//!
//! Every field degrades gracefully: an accessor `Err` (which cannot happen in
//! practice — the DER was validated at construction) is rendered as a clear
//! marker rather than panicking, so the summary never crashes on odd input. The
//! output contains no timestamps beyond the certificate's own `notBefore` /
//! `notAfter`, so it is deterministic.

use std::fmt::Write as _;

use linter::Cert;
use linter::cert::{AlgorithmId, KeyUsageBits};
use serde_json::{Value, json};

/// Marker shown when a field cannot be read or an extension is absent.
const ABSENT: &str = "(not present)";
/// Marker shown when an accessor unexpectedly fails.
const UNAVAILABLE: &str = "(unavailable)";

/// An owned summary of a certificate's own fields.
///
/// Mirrors the text block field-for-field and is also the source for the JSON
/// object built by [`build_summary_json`], so the two surfaces stay in lockstep.
/// Every field is owned, plain data with no borrow from a parsed certificate.
#[derive(Debug, Clone)]
pub struct CertSummary {
    /// The X.509 version, e.g. `"v3"`.
    pub version: String,
    /// The serial number as uppercase, colon-separated hex, or a marker.
    pub serial: String,
    /// The subject DN (RFC 4514-style), or a marker.
    pub subject: String,
    /// The issuer DN (RFC 4514-style), or a marker.
    pub issuer: String,
    /// The validity window (the certificate's own dates).
    pub validity: Validity,
    /// The signature algorithm (OID plus best-effort name).
    pub signature_algorithm: AlgorithmDisplay,
    /// The subject public key.
    pub public_key: PublicKeyDisplay,
    /// The Basic Constraints extension, or `None` when absent.
    pub basic_constraints: Option<BasicConstraintsDisplay>,
    /// The Key Usage extension, or `None` when absent.
    pub key_usage: Option<KeyUsageDisplay>,
    /// The Subject Alternative Name extension, or `None` when absent.
    pub subject_alt_name: Option<SanDisplay>,
}

/// The certificate's validity window, rendered from its own dates.
#[derive(Debug, Clone)]
pub struct Validity {
    /// The `notBefore` time as the certificate encodes it, or a marker.
    pub not_before: String,
    /// The `notAfter` time as the certificate encodes it, or a marker.
    pub not_after: String,
}

/// A display-oriented algorithm identifier (OID plus optional name).
#[derive(Debug, Clone)]
pub struct AlgorithmDisplay {
    /// The algorithm OID in dotted-decimal form.
    pub oid: String,
    /// A human-readable name when known, else `None`.
    pub name: Option<String>,
}

impl From<AlgorithmId> for AlgorithmDisplay {
    fn from(value: AlgorithmId) -> Self {
        AlgorithmDisplay {
            oid: value.oid,
            name: value.name,
        }
    }
}

impl AlgorithmDisplay {
    /// Renders the algorithm as `"name (oid)"` when a name is known, else the
    /// raw OID with an `(unknown)` label so an unrecognised (e.g. PQC) algorithm
    /// is always displayed rather than omitted.
    fn render(&self) -> String {
        match &self.name {
            Some(name) => format!("{name} ({oid})", oid = self.oid),
            None => format!("{} (unknown)", self.oid),
        }
    }
}

/// A display-oriented view of the subject public key.
#[derive(Debug, Clone)]
pub struct PublicKeyDisplay {
    /// The key algorithm (OID plus best-effort name).
    pub algorithm: AlgorithmDisplay,
    /// The key size in bits when available, else `None`.
    pub key_bits: Option<usize>,
    /// The named curve for an EC key, else `None`.
    pub curve: Option<String>,
}

impl PublicKeyDisplay {
    /// Renders the public key as the algorithm plus any size / curve detail.
    fn render(&self) -> String {
        let mut out = self.algorithm.render();
        if let Some(bits) = self.key_bits {
            let _ = write!(out, ", {bits} bits");
        }
        if let Some(curve) = &self.curve {
            let _ = write!(out, ", curve {curve}");
        }
        out
    }
}

/// A display-oriented view of the Basic Constraints extension.
#[derive(Debug, Clone)]
pub struct BasicConstraintsDisplay {
    /// The `cA` boolean.
    pub ca: bool,
    /// The `pathLenConstraint`, when present.
    pub path_len: Option<u32>,
    /// Whether the extension is marked critical.
    pub critical: bool,
}

impl BasicConstraintsDisplay {
    /// Renders `CA:<bool>` plus an optional pathlen, and the criticality.
    fn render(&self) -> String {
        let mut out = format!("CA:{}", self.ca);
        if let Some(path_len) = self.path_len {
            let _ = write!(out, ", pathlen:{path_len}");
        }
        let _ = write!(out, " {}", critical_label(self.critical));
        out
    }
}

/// A display-oriented view of the Key Usage extension.
#[derive(Debug, Clone)]
pub struct KeyUsageDisplay {
    /// Every asserted KeyUsage bit, by canonical name, in bit order.
    pub bits: Vec<String>,
    /// Whether the extension is marked critical.
    pub critical: bool,
}

impl KeyUsageDisplay {
    /// Renders the asserted bits joined by `", "`, plus the criticality. An
    /// (unusual) KeyUsage with no asserted bits renders a clear marker.
    fn render(&self) -> String {
        let bits = if self.bits.is_empty() {
            "(no bits asserted)".to_string()
        } else {
            self.bits.join(", ")
        };
        format!("{bits} {}", critical_label(self.critical))
    }
}

/// A single Subject Alternative Name entry as a `kind:value` pair.
#[derive(Debug, Clone)]
pub struct SanEntryDisplay {
    /// The general-name kind label (e.g. `"DNS"`).
    pub kind: String,
    /// The entry value (e.g. `"example.com"`).
    pub value: String,
}

/// A display-oriented view of the Subject Alternative Name extension.
#[derive(Debug, Clone)]
pub struct SanDisplay {
    /// One entry per general name, in encounter order.
    pub entries: Vec<SanEntryDisplay>,
    /// Whether the extension is marked critical.
    pub critical: bool,
}

impl SanDisplay {
    /// Renders the entries as `kind:value` joined by `", "`, plus criticality.
    fn render(&self) -> String {
        let entries: Vec<String> = self
            .entries
            .iter()
            .map(|e| format!("{}:{}", e.kind, e.value))
            .collect();
        let body = if entries.is_empty() {
            "(no entries)".to_string()
        } else {
            entries.join(", ")
        };
        format!("{body} {}", critical_label(self.critical))
    }
}

/// The stable `(critical)` / `(not critical)` suffix for an extension.
fn critical_label(critical: bool) -> &'static str {
    if critical {
        "(critical)"
    } else {
        "(not critical)"
    }
}

/// Maps the DER version code (`0`=v1, `1`=v2, `2`=v3) to a `vN` label.
fn version_label(version: u32) -> String {
    // The DER encodes v1 as 0, v2 as 1, v3 as 2; display the 1-based number.
    format!("v{}", version.saturating_add(1))
}

/// Builds the owned, serializable [`CertSummary`] for `cert`.
///
/// Never panics or errors: every accessor `Err` degrades to a clear marker
/// string (or an absent extension to `None`) so the summary is always produced.
pub fn build_summary(cert: &Cert) -> CertSummary {
    let version = cert
        .version()
        .map(version_label)
        .unwrap_or_else(|_| UNAVAILABLE.to_string());

    let serial = cert
        .serial_hex()
        .unwrap_or_else(|_| UNAVAILABLE.to_string());

    let subject = cert
        .subject_rfc4514()
        .unwrap_or_else(|_| UNAVAILABLE.to_string());
    let issuer = cert
        .issuer_rfc4514()
        .unwrap_or_else(|_| UNAVAILABLE.to_string());

    let validity = Validity {
        not_before: cert
            .not_before()
            .map(|t| t.to_string())
            .unwrap_or_else(|_| UNAVAILABLE.to_string()),
        not_after: cert
            .not_after()
            .map(|t| t.to_string())
            .unwrap_or_else(|_| UNAVAILABLE.to_string()),
    };

    let signature_algorithm = match cert.signature_algorithm() {
        Ok(alg) => alg.into(),
        Err(_) => AlgorithmDisplay {
            oid: UNAVAILABLE.to_string(),
            name: None,
        },
    };

    let public_key = match cert.public_key_info() {
        Ok(info) => PublicKeyDisplay {
            algorithm: info.algorithm.into(),
            key_bits: info.key_bits,
            curve: info.curve,
        },
        Err(_) => PublicKeyDisplay {
            algorithm: AlgorithmDisplay {
                oid: UNAVAILABLE.to_string(),
                name: None,
            },
            key_bits: None,
            curve: None,
        },
    };

    // An accessor Err and an absent extension both collapse to `None`; the text
    // renderer distinguishes them only in that both print the absent marker.
    let basic_constraints =
        cert.basic_constraints()
            .ok()
            .flatten()
            .map(|bc| BasicConstraintsDisplay {
                ca: bc.is_ca,
                path_len: bc.path_len,
                critical: bc.critical,
            });

    let key_usage = cert
        .key_usage_bits()
        .ok()
        .flatten()
        .map(|ku| KeyUsageDisplay {
            bits: key_usage_names(&ku),
            critical: ku.critical,
        });

    let subject_alt_name = cert.san_entries().ok().flatten().map(|san| SanDisplay {
        entries: san
            .entries
            .into_iter()
            .map(|e| SanEntryDisplay {
                kind: e.kind,
                value: e.value,
            })
            .collect(),
        critical: san.critical,
    });

    CertSummary {
        version,
        serial,
        subject,
        issuer,
        validity,
        signature_algorithm,
        public_key,
        basic_constraints,
        key_usage,
        subject_alt_name,
    }
}

/// Builds the certificate summary as an owned [`serde_json::Value`] object.
///
/// The shape mirrors the text block: a top-level object whose keys are
/// `version`, `serial`, `subject`, `issuer`, `validity` (`not_before` /
/// `not_after`), `signature_algorithm` (`oid` / `name`), `public_key`
/// (`algorithm` / `key_bits` / `curve`), `basic_constraints` (`null` when
/// absent), `key_usage` (`null` when absent), and `subject_alt_name` (`null`
/// when absent). Folded under the `summary` key by `main.rs`.
pub fn build_summary_json(cert: &Cert) -> Value {
    let s = build_summary(cert);

    let signature_algorithm = json!({
        "oid": s.signature_algorithm.oid,
        "name": s.signature_algorithm.name,
    });

    let public_key = json!({
        "algorithm": {
            "oid": s.public_key.algorithm.oid,
            "name": s.public_key.algorithm.name,
        },
        "key_bits": s.public_key.key_bits,
        "curve": s.public_key.curve,
    });

    let basic_constraints = match &s.basic_constraints {
        Some(bc) => json!({
            "ca": bc.ca,
            "path_len": bc.path_len,
            "critical": bc.critical,
        }),
        None => Value::Null,
    };

    let key_usage = match &s.key_usage {
        Some(ku) => json!({
            "bits": ku.bits,
            "critical": ku.critical,
        }),
        None => Value::Null,
    };

    let subject_alt_name = match &s.subject_alt_name {
        Some(san) => {
            let entries: Vec<Value> = san
                .entries
                .iter()
                .map(|e| json!({ "kind": e.kind, "value": e.value }))
                .collect();
            json!({
                "entries": entries,
                "critical": san.critical,
            })
        }
        None => Value::Null,
    };

    json!({
        "version": s.version,
        "serial": s.serial,
        "subject": s.subject,
        "issuer": s.issuer,
        "validity": {
            "not_before": s.validity.not_before,
            "not_after": s.validity.not_after,
        },
        "signature_algorithm": signature_algorithm,
        "public_key": public_key,
        "basic_constraints": basic_constraints,
        "key_usage": key_usage,
        "subject_alt_name": subject_alt_name,
    })
}

/// Collects the asserted KeyUsage bit names in RFC 5280 §4.2.1.3 bit order.
fn key_usage_names(ku: &KeyUsageBits) -> Vec<String> {
    // Bit order matches RFC 5280 §4.2.1.3 (bit 0 .. bit 8) for stable output.
    let bits = [
        (ku.digital_signature, "Digital Signature"),
        (ku.non_repudiation, "Non Repudiation"),
        (ku.key_encipherment, "Key Encipherment"),
        (ku.data_encipherment, "Data Encipherment"),
        (ku.key_agreement, "Key Agreement"),
        (ku.key_cert_sign, "Certificate Sign"),
        (ku.crl_sign, "CRL Sign"),
        (ku.encipher_only, "Encipher Only"),
        (ku.decipher_only, "Decipher Only"),
    ];
    bits.iter()
        .filter(|(is_set, _)| *is_set)
        .map(|(_, name)| (*name).to_string())
        .collect()
}

/// Renders the certificate summary as a deterministic, stable-field-order text
/// block.
///
/// Field order is fixed: Version, Serial, Subject, Issuer, Validity
/// (notBefore / notAfter), Signature Algorithm, Public Key, BasicConstraints,
/// KeyUsage, SubjectAltName. Absent extensions and unreadable fields print a
/// clear marker; there are no timestamps beyond the certificate's own dates, so
/// the block is snapshot-friendly.
pub fn render_summary_text(cert: &Cert) -> String {
    let summary = build_summary(cert);

    let mut out = String::new();
    out.push_str("Certificate Summary\n");
    let _ = writeln!(out, "  Version:             {}", summary.version);
    let _ = writeln!(out, "  Serial:              {}", summary.serial);
    let _ = writeln!(out, "  Subject:             {}", summary.subject);
    let _ = writeln!(out, "  Issuer:              {}", summary.issuer);
    let _ = writeln!(
        out,
        "  Not Before:          {}",
        summary.validity.not_before
    );
    let _ = writeln!(out, "  Not After:           {}", summary.validity.not_after);
    let _ = writeln!(
        out,
        "  Signature Algorithm: {}",
        summary.signature_algorithm.render()
    );
    let _ = writeln!(
        out,
        "  Public Key:          {}",
        summary.public_key.render()
    );

    let bc = summary
        .basic_constraints
        .as_ref()
        .map_or_else(|| ABSENT.to_string(), BasicConstraintsDisplay::render);
    let _ = writeln!(out, "  Basic Constraints:   {bc}");

    let ku = summary
        .key_usage
        .as_ref()
        .map_or_else(|| ABSENT.to_string(), KeyUsageDisplay::render);
    let _ = writeln!(out, "  Key Usage:           {ku}");

    let san = summary
        .subject_alt_name
        .as_ref()
        .map_or_else(|| ABSENT.to_string(), SanDisplay::render);
    let _ = writeln!(out, "  Subject Alt Name:    {san}");

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_cert() -> Cert {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
        let bytes = std::fs::read(path).expect("good.pem fixture must exist");
        let mut certs = Cert::load(&bytes).expect("good.pem must parse");
        certs.remove(0)
    }

    mod render_summary_text {
        use super::*;

        #[test]
        fn has_stable_field_order() {
            let text = render_summary_text(&good_cert());
            let labels = [
                "Version:",
                "Serial:",
                "Subject:",
                "Issuer:",
                "Not Before:",
                "Not After:",
                "Signature Algorithm:",
                "Public Key:",
                "Basic Constraints:",
                "Key Usage:",
                "Subject Alt Name:",
            ];
            let mut last = 0;
            for label in labels {
                let at = text
                    .find(label)
                    .unwrap_or_else(|| panic!("summary must contain {label}"));
                assert!(
                    at >= last,
                    "field {label} out of order (at {at}, previous {last})"
                );
                last = at;
            }
        }

        #[test]
        fn starts_with_summary_header() {
            let text = render_summary_text(&good_cert());
            assert!(text.starts_with("Certificate Summary\n"));
        }

        #[test]
        fn is_deterministic() {
            let cert = good_cert();
            assert_eq!(render_summary_text(&cert), render_summary_text(&cert));
        }
    }

    mod algorithm_display {
        use super::*;

        #[test]
        fn known_name_shows_name_and_oid() {
            let alg = AlgorithmDisplay {
                oid: "1.2.840.113549.1.1.11".to_string(),
                name: Some("sha256WithRSAEncryption".to_string()),
            };
            assert_eq!(
                alg.render(),
                "sha256WithRSAEncryption (1.2.840.113549.1.1.11)"
            );
        }

        #[test]
        fn unknown_name_shows_raw_oid_with_label() {
            // A PQC / unknown OID with no registry name renders the raw OID plus
            // an `(unknown)` label and never panics.
            let alg = AlgorithmDisplay {
                oid: "2.16.840.1.101.3.4.3.20".to_string(),
                name: None,
            };
            assert_eq!(alg.render(), "2.16.840.1.101.3.4.3.20 (unknown)");
        }
    }

    mod key_usage_display {
        use super::*;

        fn empty_bits() -> KeyUsageBits {
            KeyUsageBits {
                digital_signature: false,
                non_repudiation: false,
                key_encipherment: false,
                data_encipherment: false,
                key_agreement: false,
                key_cert_sign: false,
                crl_sign: false,
                encipher_only: false,
                decipher_only: false,
                critical: false,
            }
        }

        #[test]
        fn lists_every_asserted_bit_in_order() {
            let ku = KeyUsageBits {
                key_cert_sign: true,
                crl_sign: true,
                ..empty_bits()
            };
            assert_eq!(key_usage_names(&ku), vec!["Certificate Sign", "CRL Sign"]);
        }

        #[test]
        fn render_appends_criticality() {
            let display = KeyUsageDisplay {
                bits: vec!["Certificate Sign".to_string(), "CRL Sign".to_string()],
                critical: true,
            };
            assert_eq!(display.render(), "Certificate Sign, CRL Sign (critical)");
        }

        #[test]
        fn render_marks_no_bits() {
            let display = KeyUsageDisplay {
                bits: Vec::new(),
                critical: false,
            };
            assert_eq!(display.render(), "(no bits asserted) (not critical)");
        }
    }

    mod san_display {
        use super::*;

        #[test]
        fn renders_each_entry_with_criticality() {
            let display = SanDisplay {
                entries: vec![
                    SanEntryDisplay {
                        kind: "DNS".to_string(),
                        value: "example.com".to_string(),
                    },
                    SanEntryDisplay {
                        kind: "IP".to_string(),
                        value: "10.0.0.1".to_string(),
                    },
                ],
                critical: false,
            };
            assert_eq!(
                display.render(),
                "DNS:example.com, IP:10.0.0.1 (not critical)"
            );
        }
    }

    mod basic_constraints_display {
        use super::*;

        #[test]
        fn renders_ca_pathlen_and_criticality() {
            let display = BasicConstraintsDisplay {
                ca: true,
                path_len: Some(0),
                critical: true,
            };
            assert_eq!(display.render(), "CA:true, pathlen:0 (critical)");
        }

        #[test]
        fn renders_without_pathlen() {
            let display = BasicConstraintsDisplay {
                ca: false,
                path_len: None,
                critical: false,
            };
            assert_eq!(display.render(), "CA:false (not critical)");
        }
    }

    mod version_label {
        use super::*;

        #[test]
        fn maps_der_codes_to_labels() {
            assert_eq!(version_label(0), "v1");
            assert_eq!(version_label(1), "v2");
            assert_eq!(version_label(2), "v3");
        }
    }
}
