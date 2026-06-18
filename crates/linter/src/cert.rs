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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;
use x509_parser::asn1_rs::Oid;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
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

/// A read-only view of the certificate's Extended Key Usage extension.
///
/// Carries what the CA/Browser Forum BR `ext_key_usage_server_auth_present`
/// lint needs (BR §7.1.2.7): whether the extension is present at all, whether
/// the `serverAuth` purpose (OID `1.3.6.1.5.5.7.3.1`) is asserted, plus the
/// full set of EKU OIDs in dotted form for richer reporting. A view is only
/// produced when an EKU extension exists, so [`present`](EkuView::present) is
/// always `true` here; it is retained for clarity at call sites that store the
/// view alongside an absent (`None`) case.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct EkuView {
    /// `true` because the view is only built when the EKU extension exists.
    pub present: bool,
    /// `true` if the extension is marked critical.
    pub critical: bool,
    /// `true` if the `serverAuth` purpose (OID `1.3.6.1.5.5.7.3.1`) is present.
    pub server_auth: bool,
    /// `true` if the `clientAuth` purpose (OID `1.3.6.1.5.5.7.3.2`) is present.
    pub client_auth: bool,
    /// `true` if the extension carries NO key purposes at all: not `anyExtendedKeyUsage`,
    /// no recognised purpose bit, and no `other` purpose OIDs.
    ///
    /// RFC 5280 §4.2.1.12 requires the EKU extension to contain at least one
    /// `KeyPurposeId`; `ext_key_usage_without_bits` flags the empty case.
    pub is_empty: bool,
    /// Every EKU purpose OID in dotted-decimal form, in encounter order.
    pub oids: Vec<String>,
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

/// A read-only view of the certificate's Authority Key Identifier extension.
///
/// Carries what `ext_authority_key_identifier_no_key_identifier` needs
/// (RFC 5280 §4.2.1.1): whether the AKI carries a `keyIdentifier` field and
/// whether the extension is marked critical. A view is only produced when the
/// AKI extension is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AkiView {
    /// `true` if the AKI contains a `keyIdentifier` field.
    pub has_key_identifier: bool,
    /// `true` if the extension is marked critical.
    pub critical: bool,
}

/// A read-only view of the certificate's Name Constraints extension.
///
/// Carries only what `ext_name_constraints_not_critical` needs
/// (RFC 5280 §4.2.1.10, which requires the extension to be marked critical):
/// whether the extension is critical. A view is only produced when the
/// extension is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameConstraintsView {
    /// `true` if the extension is marked critical.
    pub critical: bool,
}

/// A read-only view of how a single validity time field is DER-encoded.
///
/// Carries what `utc_time_not_in_zulu` needs (RFC 5280 §4.1.2.5.1): whether the
/// field is a `UTCTime` (tag `0x17`) versus a `GeneralizedTime` (tag `0x18`),
/// and whether the encoded value ends in the Zulu marker `Z`. Derived from the
/// raw DER of the Validity SEQUENCE; see
/// [`validity_time_encodings`](Cert::validity_time_encodings).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeEncoding {
    /// `true` if the field is encoded as `UTCTime` (DER tag `0x17`); `false` if
    /// it is `GeneralizedTime` (DER tag `0x18`).
    pub is_utc_time: bool,
    /// `true` if the encoded value's last content octet is the Zulu marker
    /// (`b'Z'`).
    pub is_zulu: bool,
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

    /// The `dNSName` entries from the Subject Alternative Name extension, in
    /// encounter order, as owned strings.
    ///
    /// Consumed by the BR `cn_in_san` lint (BR §7.1.4.2) and the
    /// internal/reserved-name check. Returns an empty `Vec` when the SAN
    /// extension is absent, empty, or contains no `dNSName` entries. Invalid
    /// (non-UTF-8) general names are skipped rather than surfaced as an error.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn san_dns_names(&self) -> Result<Vec<String>, CertError> {
        self.with_parsed(|c| {
            let mut names = Vec::new();
            if let Ok(Some(ext)) = c.subject_alternative_name() {
                for gn in &ext.value.general_names {
                    if let GeneralName::DNSName(name) = gn {
                        names.push((*name).to_string());
                    }
                }
            }
            names
        })
    }

    /// The `iPAddress` entries from the Subject Alternative Name extension, in
    /// encounter order, as [`std::net::IpAddr`] values.
    ///
    /// Consumed by the BR `no_internal_names_or_reserved_ip` lint (BR §4.2.2 /
    /// §7.1.4.2). A SAN `iPAddress` is a raw octet string: 4 octets for IPv4,
    /// 16 for IPv6 (RFC 5280 §4.2.1.6). Entries with any other length are
    /// skipped (they cannot be a valid IP). Returns an empty `Vec` when the SAN
    /// extension is absent or contains no `iPAddress` entries.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn san_ip_addresses(&self) -> Result<Vec<IpAddr>, CertError> {
        self.with_parsed(|c| {
            let mut addrs = Vec::new();
            if let Ok(Some(ext)) = c.subject_alternative_name() {
                for gn in &ext.value.general_names {
                    if let GeneralName::IPAddress(octets) = gn
                        && let Some(ip) = ip_from_san_octets(octets)
                    {
                        addrs.push(ip);
                    }
                }
            }
            addrs
        })
    }

    /// The Common Name (CN) attribute values from the subject DN, in encounter
    /// order, as owned strings.
    ///
    /// Consumed by the BR `cn_in_san` lint (BR §7.1.4.2): each CN value must be
    /// present in the SAN. Returns an empty `Vec` when the subject has no CN
    /// attribute. CN values that are not valid UTF-8 are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_common_names(&self) -> Result<Vec<String>, CertError> {
        self.with_parsed(|c| {
            c.subject()
                .iter_common_name()
                .filter_map(|atv| atv.as_str().ok().map(str::to_owned))
                .collect()
        })
    }

    /// The Extended Key Usage extension as an [`EkuView`], or `None` if the
    /// extension is absent.
    ///
    /// Relied on by the BR `ext_key_usage_server_auth_present` lint
    /// (BR §7.1.2.7). A malformed or duplicated extension is treated as absent
    /// (`None`) rather than surfaced as an error, so the lint never panics on
    /// odd input.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn extended_key_usage(&self) -> Result<Option<EkuView>, CertError> {
        self.with_parsed(|c| {
            c.extended_key_usage().ok().flatten().map(|ext| {
                let eku = ext.value;
                EkuView {
                    present: true,
                    critical: ext.critical,
                    server_auth: eku.server_auth,
                    client_auth: eku.client_auth,
                    is_empty: eku_is_empty(eku),
                    oids: eku_oid_strings(eku),
                }
            })
        })
    }

    /// The Extended Key Usage purpose OIDs in dotted-decimal form, or `None` if
    /// the EKU extension is absent.
    ///
    /// Convenience wrapper over [`extended_key_usage`](Cert::extended_key_usage)
    /// that yields just the OID list (`Some(vec)` when present, `None` when the
    /// extension is absent). The list may be empty for an (unusual) EKU with no
    /// recognised or other purposes.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn ext_key_usage_oids(&self) -> Result<Option<Vec<String>>, CertError> {
        Ok(self.extended_key_usage()?.map(|eku| eku.oids))
    }

    /// Whether the certificate asserts the `serverAuth` EKU purpose
    /// (OID `1.3.6.1.5.5.7.3.1`).
    ///
    /// Consumed by the BR `ext_key_usage_server_auth_present` lint
    /// (BR §7.1.2.7). Returns `false` when the EKU extension is absent (a leaf
    /// with no EKU at all does not assert `serverAuth`).
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn has_server_auth(&self) -> Result<bool, CertError> {
        Ok(self
            .extended_key_usage()?
            .is_some_and(|eku| eku.server_auth))
    }

    /// The length of the validity window in whole days
    /// (`notAfter − notBefore`).
    ///
    /// Consumed by the BR `validity_max_398_days` lint (BR §6.3.2). A
    /// zero-length window (`notAfter == notBefore`) and an inverted window
    /// (`notAfter < notBefore`) both yield `0`: neither exceeds the 398-day
    /// ceiling, and the inverted case is the separate concern of
    /// `rfc5280_validity_not_after_after_not_before`.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn validity_days(&self) -> Result<i64, CertError> {
        self.with_parsed(|c| {
            let validity = c.validity();
            // ASN1Time subtraction yields `None` for a zero-length or inverted
            // window; treat both as a 0-day span for the 398-day ceiling.
            (validity.not_after - validity.not_before)
                .map(|d| d.whole_days())
                .unwrap_or(0)
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

    /// The Authority Key Identifier extension as an [`AkiView`], or `None` if
    /// the extension is absent.
    ///
    /// Relied on by `ext_authority_key_identifier_no_key_identifier`
    /// (RFC 5280 §4.2.1.1). [`has_key_identifier`](AkiView::has_key_identifier)
    /// reflects whether the `keyIdentifier` field is present in the AKI. A
    /// malformed extension is treated as absent (`None`).
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn authority_key_identifier(&self) -> Result<Option<AkiView>, CertError> {
        // OID 2.5.29.35 = id-ce-authorityKeyIdentifier (RFC 5280 §4.2.1.1).
        let oid = Oid::from(&[2, 5, 29, 35]).map_err(|_| CertError::Der)?;
        self.with_parsed(|c| {
            // A duplicated AKI is treated as absent (`None`) rather than an error.
            c.get_extension_unique(&oid).ok().flatten().and_then(|ext| {
                if let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension() {
                    Some(AkiView {
                        has_key_identifier: aki.key_identifier.is_some(),
                        critical: ext.critical,
                    })
                } else {
                    None
                }
            })
        })
    }

    /// Whether the certificate carries a Subject Key Identifier extension.
    ///
    /// Relied on by both SKI-presence lints
    /// (`ext_subject_key_identifier_missing_ca` and `..._missing_sub_cert`,
    /// RFC 5280 §4.2.1.2). Returns `false` when the extension is absent.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn has_subject_key_identifier(&self) -> Result<bool, CertError> {
        // OID 2.5.29.14 = id-ce-subjectKeyIdentifier (RFC 5280 §4.2.1.2).
        let oid = Oid::from(&[2, 5, 29, 14]).map_err(|_| CertError::Der)?;
        self.with_parsed(|c| {
            c.get_extension_unique(&oid)
                .ok()
                .flatten()
                .is_some_and(|ext| {
                    matches!(
                        ext.parsed_extension(),
                        ParsedExtension::SubjectKeyIdentifier(_)
                    )
                })
        })
    }

    /// The Name Constraints extension as a [`NameConstraintsView`], or `None`
    /// if the extension is absent.
    ///
    /// Relied on by `ext_name_constraints_not_critical` (RFC 5280 §4.2.1.10,
    /// which requires conforming CAs to mark Name Constraints critical). A
    /// malformed or duplicated extension is treated as absent (`None`).
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn name_constraints(&self) -> Result<Option<NameConstraintsView>, CertError> {
        self.with_parsed(|c| {
            c.name_constraints()
                .ok()
                .flatten()
                .map(|ext| NameConstraintsView {
                    critical: ext.critical,
                })
        })
    }

    /// The subject `countryName` (C, OID 2.5.4.6) attribute values, in encounter
    /// order, as owned strings.
    ///
    /// Consumed by `cabf_br_subject_country_not_iso` (BR §7.1.4.2.2). Returns an
    /// empty `Vec` when the subject has no `countryName` attribute. Values that
    /// are not valid UTF-8 are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_country_values(&self) -> Result<Vec<String>, CertError> {
        self.with_parsed(|c| {
            c.subject()
                .iter_country()
                .filter_map(|atv| atv.as_str().ok().map(str::to_owned))
                .collect()
        })
    }

    /// Whether the subject `countryName` (C) attribute value is DER-encoded as a
    /// `PrintableString`, or `None` when no `countryName` attribute is present.
    ///
    /// RFC 5280 Appendix A defines `X520countryName ::= PrintableString`, so a
    /// conforming `countryName` value MUST carry the `PrintableString` tag
    /// (universal tag number 19, DER `0x13`). x509-parser decodes the value to a
    /// plain string and offers no facade-level string-type predicate, so this
    /// inspects the ASN.1 tag the parser read from the attribute value's DER
    /// header (`attr_value().tag()`). The check is on the DER tag, not the
    /// decoded text. `Some(true)` when that tag number is `PrintableString`,
    /// `Some(false)` for any other string type (e.g. UTF8String tag 12 / `0x0C`,
    /// IA5String tag 22 / `0x16`), and `None` when there is no `countryName`
    /// attribute.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_country_is_printable_string(&self) -> Result<Option<bool>, CertError> {
        self.with_parsed(|c| {
            c.subject()
                .iter_country()
                .next()
                // `Tag` is a thin newtype over the ASN.1 universal tag number;
                // PrintableString is 19. Reading it inspects the value's DER
                // header tag, which x509-parser preserves on the `Any` value.
                .map(|atv| atv.attr_value().tag().0 == TAG_NUM_PRINTABLE_STRING)
        })
    }

    /// The number of `organizationalUnitName` (OU, OID 2.5.4.11) attributes in
    /// the subject DN.
    ///
    /// Consumed by `cabf_br_organizational_unit_name_prohibited` (BR §7.1.4.2.2,
    /// which prohibits the OU attribute). Returns `0` when the subject has no OU
    /// attribute.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_organizational_unit_count(&self) -> Result<usize, CertError> {
        self.with_parsed(|c| c.subject().iter_organizational_unit().count())
    }

    /// The DER time encodings of the `notBefore` and `notAfter` validity fields,
    /// as `(not_before, not_after)`.
    ///
    /// Consumed by `utc_time_not_in_zulu` (RFC 5280 §4.1.2.5.1, which requires a
    /// `UTCTime` to be expressed in Zulu form ending in `Z`). x509-parser
    /// normalises both fields to a single `ASN1Time` type, discarding whether
    /// the field was a `UTCTime` or `GeneralizedTime` and whether it ended in
    /// `Z`. This therefore walks the raw certificate DER to the Validity
    /// SEQUENCE and reads each time field's tag and trailing octet directly:
    /// `Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version
    /// OPTIONAL, serialNumber INTEGER, signature SEQUENCE, issuer SEQUENCE,
    /// validity SEQUENCE { notBefore Time, notAfter Time }, ... }, ... }`. For
    /// each `Time`, tag `0x17` = `UTCTime`, `0x18` = `GeneralizedTime`, and
    /// `is_zulu` is `true` when the last content octet is `b'Z'`.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER cannot be walked to the
    /// Validity SEQUENCE (it was validated as a certificate at construction
    /// time, so this should not occur in practice).
    pub fn validity_time_encodings(&self) -> Result<(TimeEncoding, TimeEncoding), CertError> {
        // Certificate SEQUENCE -> tbsCertificate SEQUENCE.
        let cert_body = tlv_content(&self.der, TAG_SEQUENCE).ok_or(CertError::Der)?;
        let tbs_body = tlv_content(cert_body, TAG_SEQUENCE).ok_or(CertError::Der)?;

        // Inside tbsCertificate, skip the optional [0] version, then INTEGER
        // serialNumber, SEQUENCE signature, SEQUENCE issuer, to reach the
        // Validity SEQUENCE. Skip a leading context-specific [0] (tag 0xA0)
        // version wrapper if present.
        let mut rest = tbs_body;
        if rest.first() == Some(&TAG_VERSION_CONTEXT) {
            rest = tlv_skip(rest).ok_or(CertError::Der)?;
        }
        // serialNumber INTEGER
        rest = tlv_skip(rest).ok_or(CertError::Der)?;
        // signature AlgorithmIdentifier SEQUENCE
        rest = tlv_skip(rest).ok_or(CertError::Der)?;
        // issuer Name SEQUENCE
        rest = tlv_skip(rest).ok_or(CertError::Der)?;
        // validity SEQUENCE
        let validity_body = tlv_content(rest, TAG_SEQUENCE).ok_or(CertError::Der)?;

        // notBefore Time
        let (not_before, after_nb) = read_time(validity_body).ok_or(CertError::Der)?;
        // notAfter Time
        let (not_after, _rest) = read_time(after_nb).ok_or(CertError::Der)?;

        Ok((not_before, not_after))
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

/// Converts a SAN `iPAddress` octet string to an [`IpAddr`].
///
/// RFC 5280 §4.2.1.6 encodes an `iPAddress` general name as a raw OCTET STRING:
/// 4 octets for IPv4, 16 for IPv6. Any other length is not a valid address and
/// yields `None`.
fn ip_from_san_octets(octets: &[u8]) -> Option<IpAddr> {
    match octets.len() {
        4 => {
            let bytes: [u8; 4] = octets.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        16 => {
            let bytes: [u8; 16] = octets.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Collects every EKU purpose OID from a parsed [`ExtendedKeyUsage`] into
/// dotted-decimal strings, preserving encounter order: the recognised purposes
/// first (in the order `x509-parser` flags them), then any `other` OIDs.
///
/// [`ExtendedKeyUsage`]: x509_parser::extensions::ExtendedKeyUsage
fn eku_oid_strings(eku: &x509_parser::extensions::ExtendedKeyUsage<'_>) -> Vec<String> {
    let mut oids = Vec::new();
    // Recognised purposes, dotted form per the EKU OID arc (RFC 5280 §4.2.1.12).
    if eku.any {
        oids.push("2.5.29.37.0".to_string());
    }
    if eku.server_auth {
        oids.push("1.3.6.1.5.5.7.3.1".to_string());
    }
    if eku.client_auth {
        oids.push("1.3.6.1.5.5.7.3.2".to_string());
    }
    if eku.code_signing {
        oids.push("1.3.6.1.5.5.7.3.3".to_string());
    }
    if eku.email_protection {
        oids.push("1.3.6.1.5.5.7.3.4".to_string());
    }
    if eku.time_stamping {
        oids.push("1.3.6.1.5.5.7.3.8".to_string());
    }
    if eku.ocsp_signing {
        oids.push("1.3.6.1.5.5.7.3.9".to_string());
    }
    for oid in &eku.other {
        oids.push(oid.to_string());
    }
    oids
}

/// Whether a parsed [`ExtendedKeyUsage`] carries no key purposes at all: not
/// `anyExtendedKeyUsage`, no recognised purpose bit, and no `other` OIDs.
///
/// RFC 5280 §4.2.1.12 requires at least one `KeyPurposeId`; this is the empty
/// case `ext_key_usage_without_bits` flags.
///
/// [`ExtendedKeyUsage`]: x509_parser::extensions::ExtendedKeyUsage
fn eku_is_empty(eku: &x509_parser::extensions::ExtendedKeyUsage<'_>) -> bool {
    !eku.any
        && !eku.server_auth
        && !eku.client_auth
        && !eku.code_signing
        && !eku.email_protection
        && !eku.time_stamping
        && !eku.ocsp_signing
        && eku.other.is_empty()
}

/// DER universal tag for `SEQUENCE` (constructed), used when walking the raw
/// certificate DER.
const TAG_SEQUENCE: u8 = 0x30;
/// DER tag for the optional `[0]` context-specific `version` wrapper inside
/// `tbsCertificate` (constructed, context class).
const TAG_VERSION_CONTEXT: u8 = 0xA0;
/// DER universal tag for `UTCTime`.
const TAG_UTC_TIME: u8 = 0x17;
/// DER universal tag for `GeneralizedTime`.
const TAG_GENERALIZED_TIME: u8 = 0x18;
/// ASN.1 universal tag number for `PrintableString` (DER tag `0x13`).
const TAG_NUM_PRINTABLE_STRING: u32 = 19;

/// Reads one DER TLV at the start of `input`, returning `(tag, content, rest)`
/// where `content` is the value octets and `rest` is everything after this TLV.
///
/// Supports short-form and long-form definite lengths only (DER never uses the
/// indefinite form). Returns `None` on any malformed or truncated header.
fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let len_byte = *input.get(1)?;
    let (len, header_len) = if len_byte & 0x80 == 0 {
        // Short form: the length is the byte itself.
        (len_byte as usize, 2)
    } else {
        // Long form: low 7 bits give the number of subsequent length octets.
        let num = (len_byte & 0x7f) as usize;
        // Reject the reserved 0x80 (indefinite) form and oversized counts that
        // could not fit in a usize.
        if num == 0 || num > core::mem::size_of::<usize>() {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num {
            len = (len << 8) | (*input.get(2 + i)? as usize);
        }
        (len, 2 + num)
    };
    let content = input.get(header_len..header_len.checked_add(len)?)?;
    let rest = &input[header_len + len..];
    Some((tag, content, rest))
}

/// Returns the content octets of the TLV at the start of `input` if its tag
/// equals `expected_tag`, else `None`.
fn tlv_content(input: &[u8], expected_tag: u8) -> Option<&[u8]> {
    let (tag, content, _rest) = read_tlv(input)?;
    (tag == expected_tag).then_some(content)
}

/// Skips the TLV at the start of `input`, returning the bytes that follow it.
fn tlv_skip(input: &[u8]) -> Option<&[u8]> {
    read_tlv(input).map(|(_tag, _content, rest)| rest)
}

/// Reads a `Time` TLV (`UTCTime` `0x17` or `GeneralizedTime` `0x18`) at the
/// start of `input`, returning its [`TimeEncoding`] and the trailing bytes.
///
/// `is_zulu` is `true` when the value's last content octet is `b'Z'`.
fn read_time(input: &[u8]) -> Option<(TimeEncoding, &[u8])> {
    let (tag, content, rest) = read_tlv(input)?;
    let is_utc_time = match tag {
        TAG_UTC_TIME => true,
        TAG_GENERALIZED_TIME => false,
        _ => return None,
    };
    let is_zulu = content.last() == Some(&b'Z');
    Some((
        TimeEncoding {
            is_utc_time,
            is_zulu,
        },
        rest,
    ))
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
        fn good_cert_has_san_and_server_auth_but_no_key_usage() {
            let cert = good_cert();

            // The regenerated BR-compliant good.pem carries a SAN (one dNSName
            // equal to the CN) and the serverAuth EKU, but deliberately has NO
            // KeyUsage extension (serverAuth is carried via EKU only).
            assert!(
                cert.key_usage().unwrap().is_none(),
                "good.pem has no KeyUsage extension"
            );

            let san = cert.subject_alt_name().unwrap();
            assert!(san.is_some(), "good.pem now carries a SAN extension");
            assert!(!san.unwrap().is_empty, "good.pem's SAN has a dNSName entry");

            let dns_names = cert.san_dns_names().unwrap();
            assert_eq!(
                dns_names,
                vec!["good.example.com".to_string()],
                "good.pem's SAN dNSName equals the CN"
            );

            // The CN is present and matches the SAN dNSName.
            assert_eq!(
                cert.subject_common_names().unwrap(),
                vec!["good.example.com".to_string()],
                "good.pem CN is good.example.com"
            );

            let eku = cert.extended_key_usage().unwrap();
            assert!(eku.is_some(), "good.pem carries an EKU extension");
            assert!(
                eku.unwrap().server_auth,
                "good.pem's EKU asserts serverAuth"
            );
            assert!(cert.has_server_auth().unwrap());
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

    mod ip_from_san_octets {
        use super::super::ip_from_san_octets;
        use std::net::IpAddr;

        #[test]
        fn four_octets_decode_to_ipv4() {
            let ip = ip_from_san_octets(&[10, 0, 0, 1]);

            assert_eq!(ip, Some("10.0.0.1".parse::<IpAddr>().unwrap()));
        }

        #[test]
        fn sixteen_octets_decode_to_ipv6() {
            let octets = [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ];

            let ip = ip_from_san_octets(&octets);

            assert_eq!(ip, Some("2001:db8::1".parse::<IpAddr>().unwrap()));
        }

        #[test]
        fn other_lengths_are_none() {
            assert!(ip_from_san_octets(&[]).is_none());
            assert!(ip_from_san_octets(&[1, 2, 3]).is_none());
            assert!(ip_from_san_octets(&[0u8; 5]).is_none());
        }
    }

    mod feature12_accessors {
        use super::*;

        /// Loads the workspace `testdata/good.pem` fixture (a BR-compliant v3
        /// leaf: SKI present, EKU=serverAuth, SAN with one dNSName, no AKI, no
        /// NameConstraints, no country/OU attributes, UTCTime Zulu validity).
        fn good_cert() -> Cert {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
            let bytes = std::fs::read(path).unwrap();
            let mut certs = Cert::from_pem(&bytes).unwrap();
            certs.remove(0)
        }

        #[test]
        fn good_cert_has_no_authority_key_identifier() {
            let cert = good_cert();

            // Absent case: good.pem carries no AKI extension.
            assert!(cert.authority_key_identifier().unwrap().is_none());
        }

        #[test]
        fn good_cert_has_subject_key_identifier() {
            let cert = good_cert();

            // Present case: good.pem carries a SubjectKeyIdentifier extension.
            assert!(cert.has_subject_key_identifier().unwrap());
        }

        #[test]
        fn good_cert_has_no_name_constraints() {
            let cert = good_cert();

            // Absent case: good.pem carries no NameConstraints extension.
            assert!(cert.name_constraints().unwrap().is_none());
        }

        #[test]
        fn good_cert_eku_is_not_empty() {
            let cert = good_cert();

            let eku = cert.extended_key_usage().unwrap().unwrap();

            // good.pem's EKU asserts serverAuth, so it is not empty.
            assert!(!eku.is_empty, "good.pem EKU carries serverAuth");
        }

        #[test]
        fn good_cert_has_no_country_attribute() {
            let cert = good_cert();

            // Absent country: empty values and None string-type predicate.
            assert!(cert.subject_country_values().unwrap().is_empty());
            assert!(
                cert.subject_country_is_printable_string()
                    .unwrap()
                    .is_none()
            );
        }

        #[test]
        fn good_cert_has_no_organizational_unit() {
            let cert = good_cert();

            assert_eq!(cert.subject_organizational_unit_count().unwrap(), 0);
        }

        #[test]
        fn good_cert_validity_is_utc_time_in_zulu() {
            let cert = good_cert();

            let (not_before, not_after) = cert.validity_time_encodings().unwrap();

            // good.pem's window (2026-06-01 -> 2027-06-01, both pre-2050) is
            // encoded as UTCTime ending in Z.
            assert!(not_before.is_utc_time, "notBefore is UTCTime");
            assert!(not_before.is_zulu, "notBefore ends in Z");
            assert!(not_after.is_utc_time, "notAfter is UTCTime");
            assert!(not_after.is_zulu, "notAfter ends in Z");
        }
    }

    mod eku_is_empty {
        use super::super::eku_is_empty;
        use x509_parser::asn1_rs::Oid;
        use x509_parser::extensions::ExtendedKeyUsage;

        /// An EKU with every flag cleared and no `other` OIDs is empty.
        fn empty_eku() -> ExtendedKeyUsage<'static> {
            ExtendedKeyUsage {
                any: false,
                server_auth: false,
                client_auth: false,
                code_signing: false,
                email_protection: false,
                time_stamping: false,
                ocsp_signing: false,
                other: Vec::new(),
            }
        }

        #[test]
        fn no_purposes_is_empty() {
            assert!(eku_is_empty(&empty_eku()));
        }

        #[test]
        fn recognised_purpose_is_not_empty() {
            let mut eku = empty_eku();
            eku.server_auth = true;

            assert!(!eku_is_empty(&eku));
        }

        #[test]
        fn any_purpose_is_not_empty() {
            let mut eku = empty_eku();
            eku.any = true;

            assert!(!eku_is_empty(&eku));
        }

        #[test]
        fn other_oid_is_not_empty() {
            let mut eku = empty_eku();
            eku.other.push(Oid::from(&[1, 2, 3]).unwrap());

            assert!(!eku_is_empty(&eku));
        }
    }

    mod der_tlv {
        use super::super::{TAG_SEQUENCE, read_time, read_tlv, tlv_content, tlv_skip};

        #[test]
        fn reads_short_form_tlv() {
            // INTEGER 0x02, len 1, value 0x05, then a trailing byte.
            let (tag, content, rest) = read_tlv(&[0x02, 0x01, 0x05, 0xFF]).unwrap();

            assert_eq!(tag, 0x02);
            assert_eq!(content, &[0x05]);
            assert_eq!(rest, &[0xFF]);
        }

        #[test]
        fn reads_long_form_length() {
            // SEQUENCE, long-form length 0x81 0x02 (2 octets), value 0xAA 0xBB.
            let bytes = [0x30, 0x81, 0x02, 0xAA, 0xBB];

            let content = tlv_content(&bytes, TAG_SEQUENCE).unwrap();

            assert_eq!(content, &[0xAA, 0xBB]);
        }

        #[test]
        fn rejects_truncated_content() {
            // Claims 4 content octets but only 1 is present.
            assert!(read_tlv(&[0x04, 0x04, 0x01]).is_none());
        }

        #[test]
        fn rejects_indefinite_length() {
            // 0x80 is the reserved indefinite-length form (not valid DER).
            assert!(read_tlv(&[0x30, 0x80, 0x00, 0x00]).is_none());
        }

        #[test]
        fn tlv_content_rejects_wrong_tag() {
            // The bytes are an INTEGER, not a SEQUENCE.
            assert!(tlv_content(&[0x02, 0x01, 0x00], TAG_SEQUENCE).is_none());
        }

        #[test]
        fn tlv_skip_advances_past_one_tlv() {
            // Two back-to-back INTEGERs; skipping the first yields the second.
            let rest = tlv_skip(&[0x02, 0x01, 0x05, 0x02, 0x01, 0x06]).unwrap();

            assert_eq!(rest, &[0x02, 0x01, 0x06]);
        }

        #[test]
        fn read_time_detects_utc_time_in_zulu() {
            // UTCTime "260601000000Z" (tag 0x17), len 13.
            let mut bytes = vec![0x17, 0x0D];
            bytes.extend_from_slice(b"260601000000Z");

            let (enc, rest) = read_time(&bytes).unwrap();

            assert!(enc.is_utc_time);
            assert!(enc.is_zulu);
            assert!(rest.is_empty());
        }

        #[test]
        fn read_time_detects_utc_time_offset_not_zulu() {
            // UTCTime "2606010000000000" with no trailing Z (offset form).
            let value = b"2606010000+0000";
            let mut bytes = vec![0x17, value.len() as u8];
            bytes.extend_from_slice(value);

            let (enc, _rest) = read_time(&bytes).unwrap();

            assert!(enc.is_utc_time);
            assert!(!enc.is_zulu, "offset form does not end in Z");
        }

        #[test]
        fn read_time_detects_generalized_time() {
            // GeneralizedTime "20500601000000Z" (tag 0x18), len 15.
            let value = b"20500601000000Z";
            let mut bytes = vec![0x18, value.len() as u8];
            bytes.extend_from_slice(value);

            let (enc, _rest) = read_time(&bytes).unwrap();

            assert!(!enc.is_utc_time, "tag 0x18 is GeneralizedTime");
            assert!(enc.is_zulu);
        }

        #[test]
        fn read_time_rejects_non_time_tag() {
            // An INTEGER is not a Time field.
            assert!(read_time(&[0x02, 0x01, 0x00]).is_none());
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
