//! The [`Cert`] parsing facade over `x509-parser`.
//!
//! Lints code against this type rather than `x509-parser`'s own structures, so
//! the underlying parser can be swapped later without touching every lint.
//!
//! A [`Cert`] **owns** its backing DER bytes. `x509-parser`'s
//! [`X509Certificate`] borrows from the input slice, which would otherwise leak
//! its lifetime into our public API. To stay self-contained, `Cert` stores the
//! owned DER and re-parses it on each accessor call. This keeps the facade
//! lifetime-free at the cost of cheap re-parsing; the parsed view never escapes.

use thiserror::Error;
use x509_parser::asn1_rs::Oid;
use x509_parser::certificate::X509Certificate;
use x509_parser::objects::{oid_registry, oid2sn};
use x509_parser::pem::Pem;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;
use x509_parser::time::ASN1Time;

#[cfg(feature = "serde")]
use serde::Serialize;

/// Errors that can occur while loading or parsing a certificate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CertError {
    /// The input was not valid PEM, or contained no certificate blocks.
    #[error("failed to decode PEM input")]
    Pem,
    /// The DER bytes could not be parsed as an X.509 certificate.
    #[error("failed to parse DER certificate")]
    Der,
    /// The input contained trailing bytes after a complete certificate.
    #[error("unexpected trailing data after certificate")]
    TrailingData,
}

/// A parsed X.509 certificate that lints inspect.
///
/// The value owns its backing DER bytes and is fully self-contained: no
/// borrowed `x509-parser` lifetime escapes the facade.
#[derive(Debug, Clone)]
pub struct Cert {
    der: Vec<u8>,
}

/// A summary of the certificate serial number's DER INTEGER encoding.
///
/// `serial_number_positive` needs to know whether the serial is positive
/// (RFC 5280 §4.1.2.2: the serial number MUST be a positive integer) and
/// whether it fits in 20 octets (the same section caps conforming serials at
/// 20 octets). The summary is derived from the raw DER content octets so the
/// lint never has to touch `x509-parser` or re-decode the value itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialSummary {
    /// `true` if the serial encodes the value zero (all content octets zero).
    pub is_zero: bool,
    /// `true` if the high bit of the leading content octet is set, i.e. the
    /// two's-complement DER INTEGER encodes a negative value.
    pub is_negative: bool,
    /// The number of content octets in the DER INTEGER (excluding tag/length).
    pub octet_len: usize,
}

/// A read-only view of the certificate's Basic Constraints extension.
///
/// Carries only what `basic_constraints_critical_on_ca` needs: the `cA`
/// boolean and whether the extension is marked critical (RFC 5280 §4.2.1.9,
/// which requires conforming CAs to mark Basic Constraints critical).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicConstraintsView {
    /// The `cA` boolean from the extension.
    pub is_ca: bool,
    /// The `pathLenConstraint` value, if present.
    pub path_len: Option<u32>,
    /// `true` if the extension is marked critical.
    pub critical: bool,
}

/// A read-only view of the certificate's Key Usage extension.
///
/// Carries only what `key_usage_present_when_ca` needs: the `keyCertSign` bit
/// (RFC 5280 §4.2.1.3) and whether the extension is marked critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsageView {
    /// `true` if the `keyCertSign` bit (bit 5) is asserted.
    pub key_cert_sign: bool,
    /// `true` if the extension is marked critical.
    pub critical: bool,
}

/// A read-only view of the certificate's Subject Alternative Name extension.
///
/// Carries only what `san_present_if_subject_empty` needs: whether the
/// extension is critical and whether it contains any general names
/// (RFC 5280 §4.2.1.6, which requires SAN to be critical when the subject DN
/// is empty). Full entry enumeration is deferred to a later feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SanView {
    /// `true` if the extension is marked critical.
    pub critical: bool,
    /// `true` if the extension contains no general names.
    pub is_empty: bool,
}

/// The algorithm family of a certificate's subject public key.
///
/// Scopes the key-strength hygiene lints' `applies()` checks: `rsa_key_min_2048`
/// runs only for [`Rsa`](PublicKeyAlg::Rsa) keys, `ecdsa_curve_allowlist` only
/// for [`Ec`](PublicKeyAlg::Ec) keys. Any other algorithm is surfaced as
/// [`Other`](PublicKeyAlg::Other) carrying the raw SPKI algorithm OID so the
/// facade never silently discards an unrecognised key type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum PublicKeyAlg {
    /// An RSA public key (`rsaEncryption`).
    Rsa,
    /// An elliptic-curve public key (`id-ecPublicKey`).
    Ec,
    /// Any other algorithm, identified by its SPKI algorithm OID in dotted form.
    Other(String),
}

/// Identification of a named elliptic curve from an EC key's SPKI parameters.
///
/// Carries what `ecdsa_curve_allowlist` needs to allowlist P-256 / P-384 /
/// P-521 (RFC 5480 §2.1.1): the curve OID in dotted form, plus a human-readable
/// short name from `oid-registry` when one is known. Common curve OIDs are
/// `1.2.840.10045.3.1.7` (P-256 / prime256v1), `1.3.132.0.34` (P-384 /
/// secp384r1), and `1.3.132.0.35` (P-521 / secp521r1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct NamedCurve {
    /// The named-curve OID in dotted-decimal form (e.g. `1.2.840.10045.3.1.7`).
    pub oid: String,
    /// A human-readable short name from `oid-registry`, or `None` if the OID is
    /// not in the registry.
    pub name: Option<String>,
}

impl Cert {
    /// Parses a single certificate from DER-encoded bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if `bytes` is not a valid DER X.509
    /// certificate, or [`CertError::TrailingData`] if extra bytes follow the
    /// certificate.
    pub fn from_der(bytes: &[u8]) -> Result<Cert, CertError> {
        let (rest, _parsed) = X509Certificate::from_der(bytes).map_err(|_| CertError::Der)?;
        if !rest.is_empty() {
            return Err(CertError::TrailingData);
        }
        Ok(Cert {
            der: bytes.to_vec(),
        })
    }

    /// Parses every certificate in a PEM document.
    ///
    /// A PEM file may contain several `CERTIFICATE` blocks; each one becomes a
    /// [`Cert`]. Non-certificate PEM blocks are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Pem`] if the input cannot be read as PEM or contains
    /// no certificate blocks, or [`CertError::Der`] if a block's contents are
    /// not a valid DER certificate.
    pub fn from_pem(bytes: &[u8]) -> Result<Vec<Cert>, CertError> {
        let mut certs = Vec::new();
        for pem in Pem::iter_from_buffer(bytes) {
            let pem = pem.map_err(|_| CertError::Pem)?;
            if pem.label != "CERTIFICATE" {
                continue;
            }
            // Validate the DER before keeping the owned bytes.
            let (rest, _parsed) =
                X509Certificate::from_der(&pem.contents).map_err(|_| CertError::Der)?;
            if !rest.is_empty() {
                return Err(CertError::TrailingData);
            }
            certs.push(Cert { der: pem.contents });
        }
        if certs.is_empty() {
            return Err(CertError::Pem);
        }
        Ok(certs)
    }

    /// Loads one or more certificates, auto-detecting PEM versus DER input.
    ///
    /// Input beginning with `-----BEGIN` (after leading whitespace) is treated
    /// as PEM; anything else is treated as a single DER certificate.
    ///
    /// # Errors
    ///
    /// Propagates [`CertError`] from [`from_pem`](Cert::from_pem) or
    /// [`from_der`](Cert::from_der) depending on the detected format.
    pub fn load(bytes: &[u8]) -> Result<Vec<Cert>, CertError> {
        if is_pem(bytes) {
            Cert::from_pem(bytes)
        } else {
            Cert::from_der(bytes).map(|c| vec![c])
        }
    }

    /// Runs `f` against the freshly re-parsed `x509-parser` view of this
    /// certificate, keeping the borrowed lifetime contained.
    ///
    /// The closure receives a reference whose lifetime is local to this call, so
    /// it cannot escape the facade. The DER was validated at construction time,
    /// so re-parsing here cannot fail in practice; an [`Err`] is surfaced
    /// defensively rather than panicking.
    fn with_parsed<T>(&self, f: impl FnOnce(&X509Certificate<'_>) -> T) -> Result<T, CertError> {
        let (_rest, parsed) = X509Certificate::from_der(&self.der).map_err(|_| CertError::Der)?;
        Ok(f(&parsed))
    }

    /// The start of the certificate's validity window (`notBefore`).
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn not_before(&self) -> Result<ASN1Time, CertError> {
        self.with_parsed(|c| c.validity().not_before)
    }

    /// The end of the certificate's validity window (`notAfter`).
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn not_after(&self) -> Result<ASN1Time, CertError> {
        self.with_parsed(|c| c.validity().not_after)
    }

    /// The certificate's version number as encoded in the DER (`0` for v1,
    /// `1` for v2, `2` for v3).
    ///
    /// RFC 5280 §4.1.2.1 ties the version to the presence of extensions, so
    /// `version_is_v3` pairs this with [`has_extensions`](Cert::has_extensions).
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn version(&self) -> Result<u32, CertError> {
        self.with_parsed(|c| c.version().0)
    }

    /// Whether the certificate carries any X.509v3 extensions.
    ///
    /// Per RFC 5280 §4.1.2.1, extensions may appear only in v3 certificates,
    /// which is what `version_is_v3` enforces.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn has_extensions(&self) -> Result<bool, CertError> {
        self.with_parsed(|c| !c.extensions().is_empty())
    }

    /// The raw DER INTEGER content octets of the certificate serial number,
    /// big-endian, exactly as encoded (no leading-zero stripping).
    ///
    /// These are the value octets surfaced by `x509-parser`'s `raw_serial`,
    /// i.e. the content of the DER INTEGER without its tag or length. The
    /// sign and octet count follow directly from them; see
    /// [`serial_summary`](Cert::serial_summary) for the derived view that
    /// `serial_number_positive` consumes.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn serial_der_octets(&self) -> Result<Vec<u8>, CertError> {
        self.with_parsed(|c| c.raw_serial().to_vec())
    }

    /// A summary of the serial number's DER INTEGER encoding (zero, sign, and
    /// octet count).
    ///
    /// Derived from [`serial_der_octets`](Cert::serial_der_octets):
    /// `is_negative` reflects the high bit of the leading content octet,
    /// `is_zero` reflects all-zero content, and `octet_len` is the content
    /// length used for the RFC 5280 §4.1.2.2 20-octet ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn serial_summary(&self) -> Result<SerialSummary, CertError> {
        let octets = self.serial_der_octets()?;
        Ok(SerialSummary {
            is_zero: octets.iter().all(|&b| b == 0),
            is_negative: octets.first().is_some_and(|&b| b & 0x80 != 0),
            octet_len: octets.len(),
        })
    }

    /// The Basic Constraints extension as a [`BasicConstraintsView`], or
    /// `None` if the extension is absent.
    ///
    /// Relied on by `basic_constraints_critical_on_ca` (RFC 5280 §4.2.1.9). A
    /// malformed or duplicated extension is treated as absent (`None`) rather
    /// than surfaced as an error, so the lint never panics on odd input.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn basic_constraints(&self) -> Result<Option<BasicConstraintsView>, CertError> {
        self.with_parsed(|c| {
            c.basic_constraints()
                .ok()
                .flatten()
                .map(|ext| BasicConstraintsView {
                    is_ca: ext.value.ca,
                    path_len: ext.value.path_len_constraint,
                    critical: ext.critical,
                })
        })
    }

    /// Whether the certificate is a CA (`basicConstraints cA = TRUE`).
    ///
    /// Convenience predicate for the CA-only lints' `applies()` checks.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn is_ca(&self) -> Result<bool, CertError> {
        Ok(self.basic_constraints()?.is_some_and(|bc| bc.is_ca))
    }

    /// The Key Usage extension as a [`KeyUsageView`], or `None` if the
    /// extension is absent.
    ///
    /// Relied on by `key_usage_present_when_ca` (RFC 5280 §4.2.1.3). A
    /// malformed or duplicated extension is treated as absent (`None`).
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn key_usage(&self) -> Result<Option<KeyUsageView>, CertError> {
        self.with_parsed(|c| {
            c.key_usage().ok().flatten().map(|ext| KeyUsageView {
                key_cert_sign: ext.value.key_cert_sign(),
                critical: ext.critical,
            })
        })
    }

    /// Whether the subject distinguished name is empty (contains no RDNs).
    ///
    /// Per RFC 5280 §4.1.2.6 a certificate may carry an empty subject only if
    /// it supplies a Subject Alternative Name, which `san_present_if_subject_empty`
    /// enforces.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_is_empty(&self) -> Result<bool, CertError> {
        self.with_parsed(|c| c.subject().iter_rdn().next().is_none())
    }

    /// The Subject Alternative Name extension as a [`SanView`], or `None` if
    /// the extension is absent.
    ///
    /// Relied on by `san_present_if_subject_empty` (RFC 5280 §4.2.1.6) for
    /// presence, criticality, and emptiness only. A malformed or duplicated
    /// extension is treated as absent (`None`).
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_alt_name(&self) -> Result<Option<SanView>, CertError> {
        self.with_parsed(|c| {
            c.subject_alternative_name()
                .ok()
                .flatten()
                .map(|ext| SanView {
                    critical: ext.critical,
                    is_empty: ext.value.general_names.is_empty(),
                })
        })
    }

    /// The certificate's signature-algorithm OID in dotted-decimal form
    /// (the outer `signatureAlgorithm`, e.g. `1.2.840.113549.1.1.11` for
    /// `sha256WithRSAEncryption`).
    ///
    /// `no_sha1_signature` uses this to detect SHA-1-based signatures robustly
    /// even when `oid-registry` has no name for the algorithm. Known SHA-1 OIDs
    /// include `1.2.840.113549.1.1.5` (sha1WithRSAEncryption),
    /// `1.2.840.10040.4.3` (dsa-with-sha1), and `1.2.840.10045.4.1`
    /// (ecdsa-with-SHA1).
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn signature_algorithm_oid(&self) -> Result<String, CertError> {
        self.with_parsed(|c| c.signature_algorithm.algorithm.to_string())
    }

    /// A human-readable short name for the signature algorithm from
    /// `oid-registry`, or `None` if the OID is not in the registry.
    ///
    /// Pairs with [`signature_algorithm_oid`](Cert::signature_algorithm_oid):
    /// the OID is authoritative, the name is a convenience for messages. Unknown
    /// algorithms yield `None` rather than an error so the facade degrades
    /// gracefully on unusual inputs.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn signature_algorithm_name(&self) -> Result<Option<String>, CertError> {
        self.with_parsed(|c| oid_name(&c.signature_algorithm.algorithm))
    }

    /// The algorithm family of the subject public key (RSA, EC, or other).
    ///
    /// Drives the key-strength lints' `applies()` scoping. Unrecognised
    /// algorithms are returned as [`PublicKeyAlg::Other`] carrying the dotted
    /// SPKI algorithm OID rather than being treated as an error.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn public_key_algorithm(&self) -> Result<PublicKeyAlg, CertError> {
        self.with_parsed(|c| {
            let oid = &c.public_key().algorithm.algorithm;
            // RFC 8017 rsaEncryption = 1.2.840.113549.1.1.1
            // RFC 5480 id-ecPublicKey = 1.2.840.10045.2.1
            match oid.to_string().as_str() {
                "1.2.840.113549.1.1.1" => PublicKeyAlg::Rsa,
                "1.2.840.10045.2.1" => PublicKeyAlg::Ec,
                other => PublicKeyAlg::Other(other.to_string()),
            }
        })
    }

    /// The RSA modulus length in bits, or `None` for non-RSA keys (and for an
    /// RSA SPKI that cannot be parsed).
    ///
    /// Consumed by `rsa_key_min_2048`, which flags moduli below 2048 bits. The
    /// bit length is derived from the parsed RSA modulus with any single DER
    /// sign-padding leading zero removed, so a 2048-bit modulus reports `2048`.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn rsa_modulus_bits(&self) -> Result<Option<u32>, CertError> {
        self.with_parsed(|c| match c.public_key().parsed() {
            Ok(PublicKey::RSA(rsa)) => rsa_modulus_bits(rsa.modulus),
            _ => None,
        })
    }

    /// The named elliptic curve of an EC public key, or `None` for non-EC keys
    /// (and for an EC key whose curve parameters are absent or not a named-curve
    /// OID).
    ///
    /// Consumed by `ecdsa_curve_allowlist`. The curve comes from the SPKI
    /// algorithm parameters (RFC 5480 §2.1.1): a named-curve OID. Explicit-curve
    /// parameters and missing parameters both yield `None`.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn ec_named_curve(&self) -> Result<Option<NamedCurve>, CertError> {
        self.with_parsed(|c| {
            let alg = &c.public_key().algorithm;
            // Only meaningful for EC keys; ignore for everything else.
            if alg.algorithm.to_string() != "1.2.840.10045.2.1" {
                return None;
            }
            let params = alg.parameters.as_ref()?;
            // EC named-curve parameters are an OID; explicit-curve params (a
            // SEQUENCE) are not, and decode to None.
            let oid = Oid::try_from(params).ok()?;
            Some(NamedCurve {
                oid: oid.to_string(),
                name: oid_name(&oid),
            })
        })
    }

    /// The raw DER bytes backing this certificate.
    pub fn der_bytes(&self) -> &[u8] {
        &self.der
    }
}

/// Looks up a human-readable short name for `oid` in x509-parser's bundled
/// registry, returning `None` when the OID is unknown.
fn oid_name(oid: &Oid<'_>) -> Option<String> {
    oid2sn(oid, oid_registry()).ok().map(str::to_owned)
}

/// Computes the bit length of a DER INTEGER modulus, stripping a single
/// sign-padding leading zero (positive INTEGERs whose MSB is set carry one).
///
/// Returns `None` for an empty modulus.
fn rsa_modulus_bits(modulus: &[u8]) -> Option<u32> {
    // Drop a leading 0x00 used only to keep the DER INTEGER positive.
    let stripped = match modulus {
        [0x00, rest @ ..] => rest,
        all => all,
    };
    let first = stripped.first()?;
    // Bit length = full bytes below the top byte plus the significant bits of
    // the top byte (ignoring its own leading zero bits).
    let lower_bits = (stripped.len() as u32 - 1) * 8;
    let top_bits = 8 - first.leading_zeros();
    Some(lower_bits + top_bits)
}

/// Returns `true` if `bytes` looks like a PEM document.
fn is_pem(bytes: &[u8]) -> bool {
    let trimmed = trim_ascii_start(bytes);
    trimmed.starts_with(b"-----BEGIN")
}

/// Skips leading ASCII whitespace without allocating.
fn trim_ascii_start(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    &bytes[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    mod is_pem {
        use super::*;

        #[test]
        fn detects_pem_header() {
            assert!(is_pem(b"-----BEGIN CERTIFICATE-----\n"));
        }

        #[test]
        fn detects_pem_header_after_whitespace() {
            assert!(is_pem(b"\n  -----BEGIN CERTIFICATE-----\n"));
        }

        #[test]
        fn rejects_der_magic_bytes() {
            assert!(!is_pem(&[0x30, 0x82, 0x01, 0x00]));
        }
    }

    mod parsing {
        use super::*;

        #[test]
        fn from_der_rejects_garbage() {
            Cert::from_der(&[0x00, 0x01, 0x02, 0x03]).unwrap_err();
        }

        #[test]
        fn from_pem_rejects_non_pem() {
            Cert::from_pem(b"not a pem document").unwrap_err();
        }

        #[test]
        fn load_routes_garbage_der_to_error() {
            Cert::load(&[0x00, 0x01, 0x02, 0x03]).unwrap_err();
        }
    }

    mod rfc5280_accessors {
        use super::*;

        /// Loads the workspace `testdata/good.pem` fixture (a v3 leaf cert).
        fn good_cert() -> Cert {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
            let bytes = std::fs::read(path).unwrap();
            let mut certs = Cert::from_pem(&bytes).unwrap();
            certs.remove(0)
        }

        #[test]
        fn good_cert_is_version_3() {
            let cert = good_cert();

            let version = cert.version().unwrap();

            assert_eq!(version, 2, "DER version 2 encodes X.509 v3");
        }

        #[test]
        fn good_cert_has_extensions() {
            let cert = good_cert();

            assert!(cert.has_extensions().unwrap());
        }

        #[test]
        fn good_cert_subject_is_not_empty() {
            let cert = good_cert();

            assert!(!cert.subject_is_empty().unwrap());
        }

        #[test]
        fn good_cert_is_a_leaf() {
            let cert = good_cert();

            let bc = cert.basic_constraints().unwrap().unwrap();

            assert!(!bc.is_ca, "good.pem carries CA:FALSE basic constraints");
            assert!(
                !bc.critical,
                "good.pem's basic constraints are not critical"
            );
            assert!(!cert.is_ca().unwrap());
        }

        #[test]
        fn good_cert_serial_is_positive_and_within_20_octets() {
            let cert = good_cert();

            let summary = cert.serial_summary().unwrap();

            assert!(!summary.is_zero);
            assert!(!summary.is_negative);
            assert!(summary.octet_len <= 20, "got {} octets", summary.octet_len);
        }

        #[test]
        fn good_cert_serial_octets_match_summary_length() {
            let cert = good_cert();

            let octets = cert.serial_der_octets().unwrap();
            let summary = cert.serial_summary().unwrap();

            assert_eq!(octets.len(), summary.octet_len);
        }

        #[test]
        fn good_cert_has_no_key_usage_or_san() {
            let cert = good_cert();

            assert!(cert.key_usage().unwrap().is_none());
            assert!(cert.subject_alt_name().unwrap().is_none());
        }
    }

    mod spki_accessors {
        use super::*;

        /// Loads the workspace `testdata/good.pem` fixture (RSA-2048 / SHA-256).
        fn good_cert() -> Cert {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
            let bytes = std::fs::read(path).unwrap();
            let mut certs = Cert::from_pem(&bytes).unwrap();
            certs.remove(0)
        }

        #[test]
        fn good_cert_signature_algorithm_is_sha256_rsa() {
            let cert = good_cert();

            let oid = cert.signature_algorithm_oid().unwrap();
            let name = cert.signature_algorithm_name().unwrap();

            assert_eq!(oid, "1.2.840.113549.1.1.11", "sha256WithRSAEncryption");
            assert_eq!(name.as_deref(), Some("sha256WithRSAEncryption"));
        }

        #[test]
        fn good_cert_public_key_algorithm_is_rsa() {
            let cert = good_cert();

            let alg = cert.public_key_algorithm().unwrap();

            assert_eq!(alg, PublicKeyAlg::Rsa);
        }

        #[test]
        fn good_cert_rsa_modulus_is_2048_bits() {
            let cert = good_cert();

            let bits = cert.rsa_modulus_bits().unwrap();

            assert_eq!(bits, Some(2048));
        }

        #[test]
        fn good_cert_has_no_ec_curve() {
            let cert = good_cert();

            let curve = cert.ec_named_curve().unwrap();

            assert!(curve.is_none(), "RSA key has no named curve");
        }
    }

    mod rsa_modulus_bits {
        use super::super::rsa_modulus_bits;

        #[test]
        fn strips_single_sign_padding_zero() {
            // 0x00 0x80 ... -> high bit set after stripping the pad: 1 byte = 8 bits.
            let bits = rsa_modulus_bits(&[0x00, 0x80]);

            assert_eq!(bits, Some(8));
        }

        #[test]
        fn counts_significant_bits_of_top_byte() {
            // 0x01 0x00 -> top byte 0x01 contributes 1 bit, plus one full lower byte.
            let bits = rsa_modulus_bits(&[0x01, 0x00]);

            assert_eq!(bits, Some(9));
        }

        #[test]
        fn full_top_byte_counts_eight_bits() {
            // 0xFF over 256 bytes (no pad) = 256 * 8 = 2048 bits.
            let modulus = vec![0xFFu8; 256];
            let bits = rsa_modulus_bits(&modulus);

            assert_eq!(bits, Some(2048));
        }

        #[test]
        fn empty_modulus_is_none() {
            let bits = rsa_modulus_bits(&[]);

            assert!(bits.is_none());
        }
    }

    mod serial_summary {
        use super::*;

        /// Builds a minimal `SerialSummary` directly to document its semantics.
        fn summarize(octets: &[u8]) -> SerialSummary {
            SerialSummary {
                is_zero: octets.iter().all(|&b| b == 0),
                is_negative: octets.first().is_some_and(|&b| b & 0x80 != 0),
                octet_len: octets.len(),
            }
        }

        #[test]
        fn single_zero_octet_is_zero_and_not_negative() {
            let summary = summarize(&[0x00]);

            assert!(summary.is_zero);
            assert!(!summary.is_negative);
            assert_eq!(summary.octet_len, 1);
        }

        #[test]
        fn high_bit_set_leading_octet_is_negative() {
            let summary = summarize(&[0x80, 0x01]);

            assert!(!summary.is_zero);
            assert!(summary.is_negative);
            assert_eq!(summary.octet_len, 2);
        }

        #[test]
        fn twenty_one_octets_exceeds_ceiling() {
            let summary = summarize(&[0x01; 21]);

            assert!(summary.octet_len > 20);
            assert!(!summary.is_negative);
        }
    }
}
