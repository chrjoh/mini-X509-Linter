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
use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
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
/// Carries what `key_usage_present_when_ca` (the `keyCertSign` bit) and the
/// CA/Browser Forum Code-Signing BR `cabf_cs_key_usage_required` lint (the
/// `digitalSignature` bit) need, plus whether the extension is marked critical
/// (RFC 5280 §4.2.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsageView {
    /// `true` if the `digitalSignature` bit (bit 0) is asserted
    /// (RFC 5280 §4.2.1.3).
    pub digital_signature: bool,
    /// `true` if the `keyEncipherment` bit (bit 2) is asserted
    /// (RFC 5280 §4.2.1.3). Consumed by `pqc_key_usage_consistency`: a PQC
    /// *signature* key MUST NOT assert it.
    pub key_encipherment: bool,
    /// `true` if the `keyAgreement` bit (bit 4) is asserted
    /// (RFC 5280 §4.2.1.3). Consumed by `pqc_key_usage_consistency`: a PQC
    /// *signature* key MUST NOT assert it.
    pub key_agreement: bool,
    /// `true` if the `keyCertSign` bit (bit 5) is asserted
    /// (RFC 5280 §4.2.1.3).
    pub key_cert_sign: bool,
    /// `true` if the `cRLSign` bit (bit 6) is asserted (RFC 5280 §4.2.1.3).
    /// Consumed by `pqc_key_usage_consistency` as the CA-side SHOULD check.
    pub crl_sign: bool,
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
    /// `true` if the `codeSigning` purpose (OID `1.3.6.1.5.5.7.3.3`) is present
    /// (RFC 5280 §4.2.1.12); the defining purpose of the CA/Browser Forum
    /// Code-Signing BR profile.
    pub code_signing: bool,
    /// `true` if the `emailProtection` purpose (OID `1.3.6.1.5.5.7.3.4`) is
    /// present (RFC 5280 §4.2.1.12); the defining purpose of the CA/Browser
    /// Forum S/MIME BR profile.
    pub email_protection: bool,
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
///
/// The two post-quantum signature families ML-DSA and SLH-DSA are recognised by
/// their NIST `2.16.840.1.101.3.4.3` "sigAlgs" OID arcs and surfaced as the
/// [`MlDsa`](PublicKeyAlg::MlDsa) / [`SlhDsa`](PublicKeyAlg::SlhDsa) variants,
/// each carrying a [`PqcParamSet`] that names the parameter set (or marks an
/// arc member whose slot is not an assigned parameter set). This is the basis
/// for the `pqc` lint family's SPKI gate (gate on the *arc*, then let
/// `pqc_algorithm_known` distinguish a known set from an unassigned slot — see
/// the feature 13 plan). The `Rsa` / `Ec` / `Other` variants and their
/// behaviour are unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum PublicKeyAlg {
    /// An RSA public key (`rsaEncryption`).
    Rsa,
    /// An elliptic-curve public key (`id-ecPublicKey`).
    Ec,
    /// A Module-Lattice Digital Signature Algorithm (ML-DSA) public key, whose
    /// SPKI OID lies in the `2.16.840.1.101.3.4.3.{17,18,19}` arc
    /// (NIST FIPS 204 + the IETF LAMPS ML-DSA X.509 algorithm-identifier
    /// profile, RFC number TBC). The carried [`PqcParamSet`] names the parameter
    /// set (`.17`–`.19`) or marks an unassigned arc member.
    MlDsa(PqcParamSet),
    /// A Stateless Hash-Based Digital Signature Algorithm (SLH-DSA) public key,
    /// whose SPKI OID lies in the `2.16.840.1.101.3.4.3.{20..35}` arc
    /// (NIST FIPS 205 + the IETF LAMPS SLH-DSA X.509 algorithm-identifier
    /// profile, RFC number TBC). The carried [`PqcParamSet`] names the parameter
    /// set (`.20`–`.31`) or marks an unassigned arc member (`.32`–`.35`).
    SlhDsa(PqcParamSet),
    /// Any other algorithm, identified by its SPKI algorithm OID in dotted form.
    Other(String),
}

/// The parameter-set identity of a post-quantum key recognised by its OID arc.
///
/// Carried by [`PublicKeyAlg::MlDsa`] / [`PublicKeyAlg::SlhDsa`]. The gate that
/// admits the `pqc` lints fires on *any* member of the two PQC arcs (so an
/// arc-but-unknown OID can still be flagged through the registry); this enum
/// distinguishes a recognised, named parameter set from an arc member whose slot
/// is not assigned to a published FIPS 204 / FIPS 205 parameter set.
///
/// `pqc_algorithm_known` fires an Error on the [`Unknown`](PqcParamSet::Unknown)
/// case; the length / key-usage lints treat `Unknown` as "no finding" because
/// they cannot validate a length or family they do not know.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum PqcParamSet {
    /// A recognised parameter set, named by its canonical FIPS short name
    /// (e.g. `"ML-DSA-65"`, `"SLH-DSA-SHA2-128s"`).
    Known(&'static str),
    /// An OID in the ML-DSA / SLH-DSA arc that does not name an assigned
    /// parameter set (a reserved-but-unassigned SLH-DSA slot such as `.32`–`.35`,
    /// or any other member of the arc with no published mapping). Carries the
    /// full dotted OID for reporting.
    Unknown(String),
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

/// An algorithm identified by its OID, with an optional human-readable name.
///
/// Display-oriented owned view used by the inspection accessors
/// [`signature_algorithm`](Cert::signature_algorithm) and the `algorithm`
/// field of [`PublicKeyInfo`]. The `oid` is always the authoritative
/// dotted-decimal string; `name` is best-effort: it is filled from
/// `oid-registry` when the OID is known, or from the post-quantum
/// classification ([`PublicKeyAlg`] / [`PqcParamSet`]) for ML-DSA / SLH-DSA
/// arc members, and is `None` for any algorithm with no recognised name. An
/// unknown algorithm (e.g. an unassigned PQC slot) is never an error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct AlgorithmId {
    /// The algorithm OID in dotted-decimal form (e.g. `1.2.840.113549.1.1.11`).
    pub oid: String,
    /// A human-readable name (from `oid-registry` or the PQC classification),
    /// or `None` when no name is known for the OID.
    pub name: Option<String>,
}

/// A display-oriented view of the certificate's subject public-key parameters.
///
/// Used by the inspection summary. The `algorithm` is always populated (with at
/// least its raw OID); `key_bits` and `curve` are best-effort and `None` when
/// the parser does not reasonably expose them (e.g. for a post-quantum key
/// whose size the facade does not derive). The view degrades gracefully for
/// unknown algorithms rather than erroring.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct PublicKeyInfo {
    /// The subject public-key algorithm (OID plus best-effort name).
    pub algorithm: AlgorithmId,
    /// The key size in bits when reasonably available (RSA modulus bits, or the
    /// EC field size), else `None`.
    pub key_bits: Option<usize>,
    /// The named curve (e.g. `prime256v1`) for an EC key, else `None`.
    pub curve: Option<String>,
}

/// The full RFC 5280 §4.2.1.3 Key Usage bit set plus the `critical` flag.
///
/// Display-oriented owned view returned by [`key_usage_bits`](Cert::key_usage_bits).
/// Unlike [`KeyUsageView`] (which carries only the subset the lints consume),
/// this exposes **all nine** KeyUsage bits so the inspection summary can render
/// every asserted purpose by name. `None` from the accessor means the extension
/// is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct KeyUsageBits {
    /// `true` if the `digitalSignature` bit (bit 0) is asserted.
    pub digital_signature: bool,
    /// `true` if the `nonRepudiation` / `contentCommitment` bit (bit 1) is
    /// asserted.
    pub non_repudiation: bool,
    /// `true` if the `keyEncipherment` bit (bit 2) is asserted.
    pub key_encipherment: bool,
    /// `true` if the `dataEncipherment` bit (bit 3) is asserted.
    pub data_encipherment: bool,
    /// `true` if the `keyAgreement` bit (bit 4) is asserted.
    pub key_agreement: bool,
    /// `true` if the `keyCertSign` bit (bit 5) is asserted.
    pub key_cert_sign: bool,
    /// `true` if the `cRLSign` bit (bit 6) is asserted.
    pub crl_sign: bool,
    /// `true` if the `encipherOnly` bit (bit 7) is asserted.
    pub encipher_only: bool,
    /// `true` if the `decipherOnly` bit (bit 8) is asserted.
    pub decipher_only: bool,
    /// `true` if the extension is marked critical.
    pub critical: bool,
}

/// A single Subject Alternative Name general name as a display-oriented pair.
///
/// `kind` is a stable short label for the general-name variant (`"DNS"`,
/// `"IP"`, `"email"`, `"URI"`, `"DirName"`, `"OtherName"`, `"RegisteredID"`,
/// `"X400Address"`, `"EDIPartyName"`, or `"Invalid"`); `value` is the entry's
/// display string. Used by [`san_entries`](Cert::san_entries).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct GeneralNameView {
    /// A stable short label for the general-name variant (e.g. `"DNS"`).
    pub kind: String,
    /// The entry's display string (e.g. `"example.com"`).
    pub value: String,
}

/// A display-oriented view of the Subject Alternative Name extension.
///
/// Carries the `critical` flag and one [`GeneralNameView`] per entry, in
/// encounter order. Returned by [`san_entries`](Cert::san_entries); the
/// accessor yields `None` when the extension is absent. Unlike [`SanView`]
/// (presence/emptiness only, for the lints), this enumerates every entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct SanEntries {
    /// `true` if the extension is marked critical.
    pub critical: bool,
    /// One owned view per general name, in encounter order.
    pub entries: Vec<GeneralNameView>,
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
                digital_signature: ext.value.digital_signature(),
                key_encipherment: ext.value.key_encipherment(),
                key_agreement: ext.value.key_agreement(),
                key_cert_sign: ext.value.key_cert_sign(),
                crl_sign: ext.value.crl_sign(),
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

    /// The `rfc822Name` (email) entries from the Subject Alternative Name
    /// extension, in encounter order, as owned strings.
    ///
    /// Consumed by the S/MIME BR `cabf_smime_san_present` lint (S/MIME BR
    /// §7.1.2.3, which requires the SAN to carry at least one `rfc822Name`) and
    /// by `cabf_smime_email_in_san` (S/MIME BR §7.1.4.2.1, which requires every
    /// email-shaped subject CN to appear here). Returns an empty `Vec` when the
    /// SAN extension is absent, empty, or contains no `rfc822Name` entries.
    /// Invalid (non-UTF-8) general names are skipped rather than surfaced as an
    /// error.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn san_rfc822_names(&self) -> Result<Vec<String>, CertError> {
        self.with_parsed(|c| {
            let mut names = Vec::new();
            if let Ok(Some(ext)) = c.subject_alternative_name() {
                for gn in &ext.value.general_names {
                    if let GeneralName::RFC822Name(name) = gn {
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
                    code_signing: eku.code_signing,
                    email_protection: eku.email_protection,
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

    /// Whether the certificate asserts the `codeSigning` EKU purpose
    /// (OID `1.3.6.1.5.5.7.3.3`).
    ///
    /// The defining shape predicate of the CA/Browser Forum Code-Signing BR
    /// profile: every `cabf_cs_*` lint's `applies()` is gated on this. Returns
    /// `false` when the EKU extension is absent (a leaf with no EKU at all does
    /// not assert `codeSigning`).
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn has_code_signing(&self) -> Result<bool, CertError> {
        Ok(self
            .extended_key_usage()?
            .is_some_and(|eku| eku.code_signing))
    }

    /// Whether the certificate asserts the `emailProtection` EKU purpose
    /// (OID `1.3.6.1.5.5.7.3.4`).
    ///
    /// The defining shape predicate of the CA/Browser Forum S/MIME BR profile:
    /// every `cabf_smime_*` lint's `applies()` is gated on this
    /// (`cabf_smime_eku_email_protection_present`, S/MIME BR §7.1.2.3), and the
    /// `CertPurpose::Auto` resolver uses it to detect S/MIME leaves. Returns
    /// `false` when the EKU extension is absent (a leaf with no EKU at all does
    /// not assert `emailProtection`).
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn has_email_protection(&self) -> Result<bool, CertError> {
        Ok(self
            .extended_key_usage()?
            .is_some_and(|eku| eku.email_protection))
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

    /// The algorithm family of the subject public key (RSA, EC, ML-DSA,
    /// SLH-DSA, or other).
    ///
    /// Drives the key-strength lints' `applies()` scoping and the `pqc` lint
    /// family's SPKI gate. RSA (`1.2.840.113549.1.1.1`, RFC 8017) and EC
    /// (`1.2.840.10045.2.1`, RFC 5480) are recognised as before. The two
    /// post-quantum signature families are recognised by their NIST
    /// `2.16.840.1.101.3.4.3` "sigAlgs" OID arcs and returned as
    /// [`PublicKeyAlg::MlDsa`] (`.17`–`.19`, NIST FIPS 204) or
    /// [`PublicKeyAlg::SlhDsa`] (`.20`–`.35`, NIST FIPS 205), per the IETF LAMPS
    /// ML-DSA / SLH-DSA X.509 algorithm-identifier profiles (RFC number TBC).
    /// **Any** member of those two arcs maps to its PQC variant — an arc OID
    /// whose slot is not an assigned parameter set carries
    /// [`PqcParamSet::Unknown`], so the gate engages and `pqc_algorithm_known`
    /// can flag it. Every other algorithm is returned as
    /// [`PublicKeyAlg::Other`] carrying the dotted SPKI algorithm OID rather
    /// than being treated as an error.
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
            let dotted = oid.to_string();
            match dotted.as_str() {
                "1.2.840.113549.1.1.1" => PublicKeyAlg::Rsa,
                "1.2.840.10045.2.1" => PublicKeyAlg::Ec,
                other => classify_pqc_oid(other)
                    .unwrap_or_else(|| PublicKeyAlg::Other(other.to_string())),
            }
        })
    }

    /// Whether the subject public key's SPKI `AlgorithmIdentifier` carries a
    /// `parameters` field.
    ///
    /// `AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER,
    /// parameters ANY DEFINED BY algorithm OPTIONAL }` (RFC 5280 §4.1.1.2).
    /// Returns `true` iff that OPTIONAL `parameters` field is *present* —
    /// a present-as-`NULL` parameters value counts as present. Consumed by
    /// `pqc_spki_parameters_absent`: the IETF LAMPS ML-DSA / SLH-DSA X.509
    /// algorithm-identifier profiles (FIPS 204 / FIPS 205, RFC number TBC)
    /// require the `parameters` field to be **absent** for these algorithms.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn spki_algorithm_parameters_present(&self) -> Result<bool, CertError> {
        self.with_parsed(|c| c.public_key().algorithm.parameters.is_some())
    }

    /// Whether the certificate's outer `signatureAlgorithm`
    /// `AlgorithmIdentifier` carries a `parameters` field.
    ///
    /// Same presence semantics as
    /// [`spki_algorithm_parameters_present`](Cert::spki_algorithm_parameters_present)
    /// (present-as-`NULL` counts as present), applied to the certificate
    /// signature algorithm rather than the SPKI algorithm. Consumed by
    /// `pqc_signature_parameters_absent`: the IETF LAMPS ML-DSA / SLH-DSA X.509
    /// profiles (FIPS 204 / FIPS 205, RFC number TBC) require the signature
    /// `parameters` field to be **absent** for these algorithms.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn signature_algorithm_parameters_present(&self) -> Result<bool, CertError> {
        self.with_parsed(|c| c.signature_algorithm.parameters.is_some())
    }

    /// The byte length of the raw subject public key.
    ///
    /// Measures the number of content octets of the SPKI `subjectPublicKey` BIT
    /// STRING **excluding** the leading unused-bits octet — i.e. the encoded
    /// public-key bytes themselves. For ML-DSA / SLH-DSA the LAMPS X.509 profile
    /// defines the public key as exactly these BIT STRING value octets, so this
    /// length is directly comparable to the parameter-set public-key size from
    /// FIPS 204 / FIPS 205. (For an RSA or EC SPKI this is still the raw BIT
    /// STRING value length, which is *not* the modulus / point size; the PQC
    /// lints only consult it for keys already classified as ML-DSA / SLH-DSA.)
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn public_key_raw_len(&self) -> Result<usize, CertError> {
        self.with_parsed(|c| c.public_key().subject_public_key.data.len())
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

    /// Whether the certificate carries an Authority Key Identifier extension.
    ///
    /// Consumed by the S/MIME BR `cabf_smime_authority_key_identifier_present`
    /// lint (S/MIME BR §7.1.2.3, which requires the AKI extension on a
    /// Subscriber cert). This is a *presence* predicate only; see
    /// [`authority_key_identifier`](Cert::authority_key_identifier) for the
    /// field-level view. Returns `false` when the extension is absent. A
    /// duplicated AKI is treated as absent rather than an error.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn has_authority_key_identifier(&self) -> Result<bool, CertError> {
        Ok(self.authority_key_identifier()?.is_some())
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

    /// Whether the certificate carries an Authority Information Access (AIA)
    /// extension.
    ///
    /// Relied on by `cabf_cs_authority_information_access`, which expects an AIA
    /// extension (carrying CA Issuers / OCSP pointers) on a code-signing leaf.
    /// This is a *presence* predicate only: it does NOT enumerate the
    /// `accessLocation` URIs (deferred to a follow-up lint). Returns `false`
    /// when the extension is absent.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn has_authority_info_access(&self) -> Result<bool, CertError> {
        // OID 1.3.6.1.5.5.7.1.1 = id-pe-authorityInfoAccess (RFC 5280 §4.2.2.1).
        let oid = Oid::from(&[1, 3, 6, 1, 5, 5, 7, 1, 1]).map_err(|_| CertError::Der)?;
        self.with_parsed(|c| {
            // A duplicated AIA is treated as absent rather than an error.
            c.get_extension_unique(&oid)
                .ok()
                .flatten()
                .is_some_and(|ext| {
                    matches!(
                        ext.parsed_extension(),
                        ParsedExtension::AuthorityInfoAccess(_)
                    )
                })
        })
    }

    /// Whether the certificate carries a CRL Distribution Points extension.
    ///
    /// Relied on by `cabf_cs_crl_distribution_points`, which expects a CRL-DP
    /// extension (a revocation pointer) on a code-signing leaf. This is a
    /// *presence* predicate only: it does NOT enumerate the distribution-point
    /// URIs. Returns `false` when the extension is absent.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn has_crl_distribution_points(&self) -> Result<bool, CertError> {
        // OID 2.5.29.31 = id-ce-cRLDistributionPoints (RFC 5280 §4.2.1.13).
        let oid = Oid::from(&[2, 5, 29, 31]).map_err(|_| CertError::Der)?;
        self.with_parsed(|c| {
            // A duplicated CRL-DP is treated as absent rather than an error.
            c.get_extension_unique(&oid)
                .ok()
                .flatten()
                .is_some_and(|ext| {
                    matches!(
                        ext.parsed_extension(),
                        ParsedExtension::CRLDistributionPoints(_)
                    )
                })
        })
    }

    /// The `fullName` URI entries (`GeneralName::URI`) from every CRL
    /// Distribution Point, in encounter order, as owned strings.
    ///
    /// Consumed by the S/MIME BR `cabf_smime_crl_distribution_points_http` lint
    /// (S/MIME BR §7.1.2.3, which requires every CRL DP `fullName` URI to use
    /// the `http`/`https` scheme). Walks every `CRLDistributionPoint`, takes the
    /// `fullName` form of its `distributionPoint`, and collects each
    /// `GeneralName::URI`. Non-URI general names (and the
    /// `nameRelativeToCRLIssuer` form) are skipped. Returns an empty `Vec` when
    /// the CRL-DP extension is absent or carries no `fullName` URIs. A
    /// duplicated CRL-DP extension is treated as absent.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn crl_distribution_point_uris(&self) -> Result<Vec<String>, CertError> {
        // OID 2.5.29.31 = id-ce-cRLDistributionPoints (RFC 5280 §4.2.1.13).
        let oid = Oid::from(&[2, 5, 29, 31]).map_err(|_| CertError::Der)?;
        self.with_parsed(|c| {
            let mut uris = Vec::new();
            // A duplicated CRL-DP is treated as absent rather than an error.
            if let Ok(Some(ext)) = c.get_extension_unique(&oid)
                && let ParsedExtension::CRLDistributionPoints(dps) = ext.parsed_extension()
            {
                for dp in &dps.points {
                    if let Some(DistributionPointName::FullName(names)) = &dp.distribution_point {
                        for gn in names {
                            if let GeneralName::URI(uri) = gn {
                                uris.push((*uri).to_string());
                            }
                        }
                    }
                }
            }
            uris
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

    /// The subject `countryName` (C, OID 2.5.4.6) attribute values, in encounter
    /// order, as owned strings — raw, with no length validation.
    ///
    /// Consumed by the S/MIME BR `cabf_smime_subject_country_valid` lint
    /// (S/MIME BR §7.1.4.2, which requires a 2-letter value); the length check
    /// lives in the lint, not here. This is an alias for
    /// [`subject_country_values`](Cert::subject_country_values), which already
    /// enumerates the same attribute for the BR
    /// `cabf_br_subject_country_not_iso` lint; it exists under the S/MIME-facing
    /// name the S/MIME subset references. Returns an empty `Vec` when the
    /// subject has no `countryName` attribute; non-UTF-8 values are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_country_names(&self) -> Result<Vec<String>, CertError> {
        self.subject_country_values()
    }

    /// The subject `emailAddress` (OID 1.2.840.113549.1.9.1, PKCS#9) attribute
    /// values, in encounter order, as owned strings.
    ///
    /// Consumed by the S/MIME BR `cabf_smime_single_email_subject` lint
    /// (S/MIME BR §7.1.4.2.1, which permits at most one `emailAddress` RDN):
    /// the lint flags when this returns more than one value. Returns an empty
    /// `Vec` when the subject has no `emailAddress` attribute. Values that are
    /// not valid UTF-8 are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_email_addresses(&self) -> Result<Vec<String>, CertError> {
        self.with_parsed(|c| {
            c.subject()
                .iter_email()
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

    /// All values of the subject-DN attribute identified by `oid_arc`, in
    /// encounter order, as owned strings.
    ///
    /// This is the shared, DRY backbone for the subject-attribute accessors:
    /// `subject_common_names` reads OID `2.5.4.3` the same way, and the EV
    /// identity accessors below
    /// ([`subject_organization_names`](Cert::subject_organization_names),
    /// [`subject_business_category`](Cert::subject_business_category),
    /// [`subject_jurisdiction_country`](Cert::subject_jurisdiction_country),
    /// [`subject_serial_numbers`](Cert::subject_serial_numbers),
    /// [`subject_organization_identifiers`](Cert::subject_organization_identifiers))
    /// each delegate here with their own attribute OID. Attribute values that
    /// are not valid UTF-8 are skipped rather than surfaced as an error.
    ///
    /// `oid_arc` is the BER OID component arc (e.g. `&[2, 5, 4, 10]` for
    /// `organizationName`). An un-encodable arc yields [`CertError::Der`].
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if `oid_arc` cannot be encoded as an OID, or if
    /// the owned DER unexpectedly fails to re-parse (it was validated at
    /// construction time).
    fn subject_attribute_values(&self, oid_arc: &[u64]) -> Result<Vec<String>, CertError> {
        let oid = Oid::from(oid_arc).map_err(|_| CertError::Der)?;
        self.with_parsed(|c| {
            c.subject()
                .iter_by_oid(&oid)
                .filter_map(|atv| atv.as_str().ok().map(str::to_owned))
                .collect()
        })
    }

    /// The certificate-policy OIDs from the `certificatePolicies` extension
    /// (OID `2.5.29.32`, RFC 5280 §4.2.1.4), in dotted-decimal form and encounter
    /// order.
    ///
    /// Consumed by the EV-scope gate `is_ev_scope()` (feature 11): a TLS leaf is
    /// "in EV scope" when one of its policy OIDs is on the curated EV allowlist.
    /// Returns an empty `Vec` when the extension is absent or carries no policy
    /// information; a malformed or duplicated extension is likewise treated as an
    /// empty list rather than surfaced as an error, so the EV gate fails closed
    /// (a parse failure never manufactures an EV finding).
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn certificate_policy_oids(&self) -> Result<Vec<String>, CertError> {
        // OID 2.5.29.32 = id-ce-certificatePolicies (RFC 5280 §4.2.1.4).
        let oid = Oid::from(&[2, 5, 29, 32]).map_err(|_| CertError::Der)?;
        self.with_parsed(|c| {
            let mut oids = Vec::new();
            // A duplicated certificatePolicies extension is treated as absent.
            if let Ok(Some(ext)) = c.get_extension_unique(&oid)
                && let ParsedExtension::CertificatePolicies(policies) = ext.parsed_extension()
            {
                for info in policies {
                    oids.push(info.policy_id.to_string());
                }
            }
            oids
        })
    }

    /// The subject `organizationName` (O, OID `2.5.4.10`) attribute values, in
    /// encounter order, as owned strings.
    ///
    /// Consumed by the EV `cabf_ev_organization_name_missing` lint (EVG §9.2.1,
    /// which requires an EV subject to carry `organizationName`). Returns an empty
    /// `Vec` when the subject has no `organizationName` attribute; non-UTF-8
    /// values are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_organization_names(&self) -> Result<Vec<String>, CertError> {
        // OID 2.5.4.10 = id-at-organizationName.
        self.subject_attribute_values(&[2, 5, 4, 10])
    }

    /// The subject `businessCategory` (OID `2.5.4.15`) attribute values, in
    /// encounter order, as owned strings.
    ///
    /// Consumed by the EV `cabf_ev_business_category_missing` and
    /// `cabf_ev_business_category_invalid` lints (EVG §9.2.4, which requires an EV
    /// subject to carry `businessCategory` set to one of the permitted values).
    /// Returns an empty `Vec` when the subject has no `businessCategory`
    /// attribute; non-UTF-8 values are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_business_category(&self) -> Result<Vec<String>, CertError> {
        // OID 2.5.4.15 = id-at-businessCategory.
        self.subject_attribute_values(&[2, 5, 4, 15])
    }

    /// The subject `jurisdictionOfIncorporationCountryName`
    /// (OID `1.3.6.1.4.1.311.60.2.1.3`) attribute values, in encounter order, as
    /// owned strings.
    ///
    /// Consumed by the EV `cabf_ev_jurisdiction_country_missing` lint (EVG §9.2.4,
    /// which requires an EV subject to carry the jurisdiction-of-incorporation
    /// country). This is the Microsoft-arc jurisdiction OID, distinct from the
    /// plain subject `countryName` (OID `2.5.4.6`, see
    /// [`subject_country_values`](Cert::subject_country_values)). Returns an empty
    /// `Vec` when the attribute is absent; non-UTF-8 values are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_jurisdiction_country(&self) -> Result<Vec<String>, CertError> {
        // OID 1.3.6.1.4.1.311.60.2.1.3 = jurisdictionOfIncorporationCountryName.
        self.subject_attribute_values(&[1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3])
    }

    /// The subject-DN `serialNumber` (OID `2.5.4.5`) attribute values, in
    /// encounter order, as owned strings.
    ///
    /// **This is the subject DN `serialNumber` attribute — the EV
    /// registration/incorporation number of the legal entity — NOT the
    /// certificate serial number.** The certificate serial (the
    /// `TBSCertificate.serialNumber` INTEGER) is a wholly separate field surfaced
    /// by [`serial_summary`](Cert::serial_summary) /
    /// [`serial_der_octets`](Cert::serial_der_octets); the two share a name but
    /// nothing else.
    ///
    /// Consumed by the EV `cabf_ev_serial_number_missing` lint (EVG §9.2.6, which
    /// requires an EV subject to carry the registration number in this attribute).
    /// Returns an empty `Vec` when the subject has no `serialNumber` attribute;
    /// non-UTF-8 values are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_serial_numbers(&self) -> Result<Vec<String>, CertError> {
        // OID 2.5.4.5 = id-at-serialNumber (the subject DN attribute, NOT the
        // certificate serial number — see serial_summary / serial_der_octets).
        self.subject_attribute_values(&[2, 5, 4, 5])
    }

    /// The subject `organizationIdentifier` (OID `2.5.4.97`) attribute values, in
    /// encounter order, as owned strings.
    ///
    /// Consumed by the EV `cabf_ev_organization_id_present` lint (EVG §9.2.8,
    /// which requires an EV subject to carry an `organizationIdentifier`); the
    /// lint flags the *absence* of any value here. Returns an empty `Vec` when the
    /// subject has no `organizationIdentifier` attribute; non-UTF-8 values are
    /// skipped.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_organization_identifiers(&self) -> Result<Vec<String>, CertError> {
        // OID 2.5.4.97 = id-at-organizationIdentifier.
        self.subject_attribute_values(&[2, 5, 4, 97])
    }

    /// The Subject Alternative Name `dNSName` entries that are wildcard names
    /// (begin with the literal `*.` label), in encounter order, as owned strings.
    ///
    /// Consumed by the EV `cabf_ev_not_wildcard` lint (EVG §9.2.2 / the BR
    /// wildcard prohibition for EV, which forbids any wildcard SAN name on an EV
    /// cert); the lint emits one finding per offending entry. This reuses the same
    /// SAN `dNSName` parsing path as [`san_dns_names`](Cert::san_dns_names),
    /// filtered to the wildcard entries. Returns an empty `Vec` when the SAN is
    /// absent or carries no wildcard `dNSName` entries.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn san_wildcard_dns_names(&self) -> Result<Vec<String>, CertError> {
        Ok(self
            .san_dns_names()?
            .into_iter()
            .filter(|name| name.starts_with("*."))
            .collect())
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

    /// The subject distinguished name as a human-readable RFC 4514-style string.
    ///
    /// Formatted by x509-parser using `oid-registry` for attribute-type names
    /// (e.g. `CN=good.example.com, O=Example`). The order is the DN's encounter
    /// order with attributes joined by `", "` and multi-valued RDNs joined by
    /// `" + "`. This is the conventional x509-parser display form rather than a
    /// byte-strict RFC 4514 serialization; it is intended for human-readable
    /// inspection, not canonicalization. An un-formattable name degrades to an
    /// empty string rather than erroring.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_rfc4514(&self) -> Result<String, CertError> {
        self.with_parsed(|c| {
            c.subject()
                .to_string_with_registry(oid_registry())
                .unwrap_or_default()
        })
    }

    /// The issuer distinguished name as a human-readable RFC 4514-style string.
    ///
    /// Same formatting and caveats as
    /// [`subject_rfc4514`](Cert::subject_rfc4514), applied to the issuer DN.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn issuer_rfc4514(&self) -> Result<String, CertError> {
        self.with_parsed(|c| {
            c.issuer()
                .to_string_with_registry(oid_registry())
                .unwrap_or_default()
        })
    }

    /// The certificate serial number as an uppercase, colon-separated hex
    /// string (e.g. `0A:1B:2C`).
    ///
    /// Derived from [`serial_der_octets`](Cert::serial_der_octets): each DER
    /// INTEGER content octet is rendered as two uppercase hex digits, joined by
    /// `:`. Leading sign-padding octets are preserved exactly as encoded (no
    /// stripping). An empty serial yields the empty string.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn serial_hex(&self) -> Result<String, CertError> {
        let octets = self.serial_der_octets()?;
        let hex: Vec<String> = octets.iter().map(|b| format!("{b:02X}")).collect();
        Ok(hex.join(":"))
    }

    /// The certificate's outer `signatureAlgorithm` as an [`AlgorithmId`]
    /// (dotted OID plus best-effort human-readable name).
    ///
    /// The OID is always present. The name is looked up in `oid-registry`; if
    /// the registry has no name but the OID is a recognised ML-DSA / SLH-DSA
    /// arc member with an assigned parameter set, the FIPS short name is used
    /// instead (e.g. `SLH-DSA-SHA2-128s`). Any algorithm with no known name —
    /// including an unassigned PQC slot — yields `name = None` and never errors.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn signature_algorithm(&self) -> Result<AlgorithmId, CertError> {
        self.with_parsed(|c| {
            let oid = &c.signature_algorithm.algorithm;
            let dotted = oid.to_string();
            let name = oid_name(oid).or_else(|| pqc_name_for_oid(&dotted));
            AlgorithmId { oid: dotted, name }
        })
    }

    /// The subject public key as a [`PublicKeyInfo`] (algorithm, optional key
    /// size, optional curve).
    ///
    /// `algorithm` carries the SPKI algorithm OID plus a best-effort name
    /// (registry name, falling back to the ML-DSA / SLH-DSA parameter-set name
    /// for recognised PQC arc members, else `None`). `key_bits` is the RSA
    /// modulus bit length or the EC field size when available, else `None`;
    /// `curve` is the EC named curve, else `None`. Unknown (e.g. post-quantum)
    /// algorithms degrade gracefully to `key_bits`/`curve` of `None` rather
    /// than erroring.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn public_key_info(&self) -> Result<PublicKeyInfo, CertError> {
        let curve = self.ec_named_curve()?;
        self.with_parsed(|c| {
            let spki = c.public_key();
            let oid = &spki.algorithm.algorithm;
            let dotted = oid.to_string();
            let name = oid_name(oid).or_else(|| pqc_name_for_oid(&dotted));

            // key_size() returns the RSA modulus bits / EC field size, or 0 for
            // an algorithm the parser cannot size (e.g. PQC keys). Treat 0 as
            // "not available" so unknown algorithms degrade to None.
            let key_bits = match spki.parsed() {
                Ok(parsed) => match parsed.key_size() {
                    0 => None,
                    bits => Some(bits),
                },
                Err(_) => None,
            };

            PublicKeyInfo {
                algorithm: AlgorithmId { oid: dotted, name },
                key_bits,
                curve: curve
                    .as_ref()
                    .map(|nc| nc.name.clone().unwrap_or_else(|| nc.oid.clone())),
            }
        })
    }

    /// The full Key Usage bit set as a [`KeyUsageBits`], or `None` if the
    /// extension is absent.
    ///
    /// Exposes all nine RFC 5280 §4.2.1.3 KeyUsage bits plus the `critical`
    /// flag for the inspection summary, in contrast to
    /// [`key_usage`](Cert::key_usage) which carries only the subset the lints
    /// consume. A malformed or duplicated extension is treated as absent
    /// (`None`).
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn key_usage_bits(&self) -> Result<Option<KeyUsageBits>, CertError> {
        self.with_parsed(|c| {
            c.key_usage().ok().flatten().map(|ext| {
                let ku = ext.value;
                KeyUsageBits {
                    digital_signature: ku.digital_signature(),
                    non_repudiation: ku.non_repudiation(),
                    key_encipherment: ku.key_encipherment(),
                    data_encipherment: ku.data_encipherment(),
                    key_agreement: ku.key_agreement(),
                    key_cert_sign: ku.key_cert_sign(),
                    crl_sign: ku.crl_sign(),
                    encipher_only: ku.encipher_only(),
                    decipher_only: ku.decipher_only(),
                    critical: ext.critical,
                }
            })
        })
    }

    /// The Subject Alternative Name extension as a [`SanEntries`] (one
    /// [`GeneralNameView`] per entry, plus the `critical` flag), or `None` if
    /// the extension is absent.
    ///
    /// Each general name is rendered to a stable `kind`/`value` pair for the
    /// inspection summary. `iPAddress` entries are rendered as standard IPv4 /
    /// IPv6 text (an octet string of any other length falls back to a raw hex
    /// display). A malformed or duplicated extension is treated as absent
    /// (`None`).
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn san_entries(&self) -> Result<Option<SanEntries>, CertError> {
        self.with_parsed(|c| {
            c.subject_alternative_name()
                .ok()
                .flatten()
                .map(|ext| SanEntries {
                    critical: ext.critical,
                    entries: ext
                        .value
                        .general_names
                        .iter()
                        .map(general_name_view)
                        .collect(),
                })
        })
    }

    /// The raw DER bytes backing this certificate.
    pub fn der_bytes(&self) -> &[u8] {
        &self.der
    }

    /// The DER encoding of the subject `Name` (the raw `RDNSequence` bytes,
    /// including the outer `SEQUENCE` tag and length), exactly as they appear in
    /// the certificate.
    ///
    /// This is the byte-exact form RFC 5280 §4.1.2.6 name matching needs: chain
    /// construction links a cert *A* to its issuer *B* when
    /// `A.issuer_name_der() == B.subject_name_der()`. Because both accessors
    /// surface the same parser-preserved DER of the same `Name` production, a
    /// self-signed certificate satisfies `subject_name_der() == issuer_name_der()`.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_name_der(&self) -> Result<Vec<u8>, CertError> {
        self.with_parsed(|c| c.subject().as_raw().to_vec())
    }

    /// The DER encoding of the issuer `Name` (the raw `RDNSequence` bytes,
    /// including the outer `SEQUENCE` tag and length), exactly as they appear in
    /// the certificate.
    ///
    /// The byte-exact counterpart of [`subject_name_der`](Cert::subject_name_der)
    /// for RFC 5280 §4.1.2.4 issuer matching. Chain construction compares a
    /// subject's `issuer_name_der()` against a candidate issuer's
    /// `subject_name_der()`; both return the same encoding for the same logical
    /// `Name`.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn issuer_name_der(&self) -> Result<Vec<u8>, CertError> {
        self.with_parsed(|c| c.issuer().as_raw().to_vec())
    }

    /// The raw `keyIdentifier` octets of the Subject Key Identifier extension
    /// (the OCTET STRING contents — the actual key id), or `None` when the SKI
    /// extension is absent.
    ///
    /// This is the byte counterpart of
    /// [`has_subject_key_identifier`](Cert::has_subject_key_identifier)
    /// (RFC 5280 §4.2.1.2). Chain construction compares a subject's AKI
    /// `keyIdentifier` (see [`authority_key_id_bytes`](Cert::authority_key_id_bytes))
    /// against the issuer's SKI to disambiguate certificates that share a `Name`.
    /// A malformed or duplicated extension is treated as absent (`None`) rather
    /// than surfaced as an error.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn subject_key_id_bytes(&self) -> Result<Option<Vec<u8>>, CertError> {
        // OID 2.5.29.14 = id-ce-subjectKeyIdentifier (RFC 5280 §4.2.1.2).
        let oid = Oid::from(&[2, 5, 29, 14]).map_err(|_| CertError::Der)?;
        self.with_parsed(|c| {
            // A duplicated SKI is treated as absent (`None`) rather than an error.
            c.get_extension_unique(&oid).ok().flatten().and_then(|ext| {
                if let ParsedExtension::SubjectKeyIdentifier(ski) = ext.parsed_extension() {
                    Some(ski.0.to_vec())
                } else {
                    None
                }
            })
        })
    }

    /// The raw `keyIdentifier` octets of the Authority Key Identifier extension
    /// (the OCTET STRING contents), or `None` when the AKI extension is absent
    /// OR when it carries no `keyIdentifier` field (e.g. an AKI holding only
    /// `authorityCertIssuer` / `authorityCertSerialNumber`).
    ///
    /// This is the byte counterpart of the
    /// [`AkiView::has_key_identifier`] boolean (RFC 5280 §4.2.1.1). Chain
    /// construction compares this against the issuer's
    /// [`subject_key_id_bytes`](Cert::subject_key_id_bytes). A malformed or
    /// duplicated extension is treated as absent (`None`).
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn authority_key_id_bytes(&self) -> Result<Option<Vec<u8>>, CertError> {
        // OID 2.5.29.35 = id-ce-authorityKeyIdentifier (RFC 5280 §4.2.1.1).
        let oid = Oid::from(&[2, 5, 29, 35]).map_err(|_| CertError::Der)?;
        self.with_parsed(|c| {
            // A duplicated AKI is treated as absent (`None`) rather than an error.
            c.get_extension_unique(&oid).ok().flatten().and_then(|ext| {
                if let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension() {
                    aki.key_identifier.as_ref().map(|kid| kid.0.to_vec())
                } else {
                    None
                }
            })
        })
    }

    /// The raw DER of the `tbsCertificate` (the exact bytes the certificate
    /// signature is computed over, including the outer `SEQUENCE` tag and
    /// length).
    ///
    /// These are the bytes a verifier hashes and checks against the issuer's
    /// public key for `chain_signature_valid` (RFC 5280 §4.1.1.1 / §4.1.1.3).
    /// Surfaced via `x509-parser`'s `TbsCertificate: AsRef<[u8]>`, which yields
    /// the parser-preserved raw TBS slice.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn tbs_der(&self) -> Result<Vec<u8>, CertError> {
        self.with_parsed(|c| c.tbs_certificate.as_ref().to_vec())
    }

    /// The certificate `signatureValue` BIT STRING content octets (the raw
    /// signature bytes), excluding the BIT STRING's leading unused-bits octet.
    ///
    /// For a certificate signature the unused-bits count is always zero, so this
    /// is exactly the signature a verifier checks against the issuer's public key
    /// (RFC 5280 §4.1.1.3). Pairs with [`tbs_der`](Cert::tbs_der) and
    /// [`signature_algorithm_oid`](Cert::signature_algorithm_oid) for
    /// `chain_signature_valid`.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn signature_value_bytes(&self) -> Result<Vec<u8>, CertError> {
        self.with_parsed(|c| c.signature_value.data.to_vec())
    }

    /// The full `SubjectPublicKeyInfo` DER of **this** certificate.
    ///
    /// Returns the **complete SPKI DER** — the outer `SEQUENCE` wrapping the
    /// `AlgorithmIdentifier` and the `subjectPublicKey` BIT STRING (RFC 5280
    /// §4.1.2.7) — *not* the raw public-key bytes alone. The full SPKI is the
    /// most generally useful form for the verify module (task 02): a caller can
    /// extract both the algorithm and the key material from it, feeding `ring`
    /// (which wants the per-algorithm key bytes, re-derived from the SPKI) or
    /// `fips204` / `fips205` (which want the encoded public key) as each backend
    /// requires.
    ///
    /// Named `issuer_spki_bytes` because chain verification calls it on the
    /// *issuer* certificate (`issuer.issuer_spki_bytes()`) to obtain the key that
    /// must verify the subject's signature; when called on any cert it returns
    /// that same cert's own SPKI.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::Der`] if the owned DER unexpectedly fails to
    /// re-parse (it was validated at construction time).
    pub fn issuer_spki_bytes(&self) -> Result<Vec<u8>, CertError> {
        self.with_parsed(|c| c.public_key().raw.to_vec())
    }
}

/// Looks up a human-readable short name for `oid` in x509-parser's bundled
/// registry, returning `None` when the OID is unknown.
fn oid_name(oid: &Oid<'_>) -> Option<String> {
    oid2sn(oid, oid_registry()).ok().map(str::to_owned)
}

/// A best-effort human-readable name for a dotted OID that `oid-registry` does
/// not know but which is a recognised post-quantum (ML-DSA / SLH-DSA) arc
/// member with an assigned parameter set.
///
/// Returns the FIPS short name (e.g. `SLH-DSA-SHA2-128s`) for a known parameter
/// set, or `None` for any OID that is not a PQC arc member or whose slot is
/// unassigned ([`PqcParamSet::Unknown`]). This lets the inspection accessors
/// display a friendly name for PQC algorithms while never erroring on an
/// unknown one.
fn pqc_name_for_oid(dotted: &str) -> Option<String> {
    match classify_pqc_oid(dotted)? {
        PublicKeyAlg::MlDsa(PqcParamSet::Known(name))
        | PublicKeyAlg::SlhDsa(PqcParamSet::Known(name)) => Some(name.to_string()),
        _ => None,
    }
}

/// Renders a parsed [`GeneralName`] to an owned [`GeneralNameView`] with a
/// stable `kind` label and display `value`.
///
/// `iPAddress` octets are rendered as standard IPv4 / IPv6 text when they are a
/// valid 4- or 16-octet address, and as colon-separated hex otherwise.
fn general_name_view(gn: &GeneralName<'_>) -> GeneralNameView {
    let (kind, value) = match gn {
        GeneralName::DNSName(s) => ("DNS", (*s).to_string()),
        GeneralName::RFC822Name(s) => ("email", (*s).to_string()),
        GeneralName::URI(s) => ("URI", (*s).to_string()),
        GeneralName::IPAddress(octets) => {
            let value = ip_from_san_octets(octets)
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| {
                    octets
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(":")
                });
            ("IP", value)
        }
        GeneralName::DirectoryName(dn) => (
            "DirName",
            dn.to_string_with_registry(oid_registry())
                .unwrap_or_default(),
        ),
        GeneralName::OtherName(oid, _) => ("OtherName", oid.to_string()),
        GeneralName::RegisteredID(oid) => ("RegisteredID", oid.to_string()),
        GeneralName::X400Address(_) => ("X400Address", "<unparsed>".to_string()),
        GeneralName::EDIPartyName(_) => ("EDIPartyName", "<unparsed>".to_string()),
        GeneralName::Invalid(tag, _) => ("Invalid", format!("tag={tag}")),
    };
    GeneralNameView {
        kind: kind.to_string(),
        value,
    }
}

/// The shared NIST `2.16.840.1.101.3.4.3` "sigAlgs" arc that prefixes every
/// ML-DSA / SLH-DSA OID, in dotted form with a trailing dot.
const PQC_ARC_PREFIX: &str = "2.16.840.1.101.3.4.3.";

/// Classifies a dotted SPKI algorithm OID as an ML-DSA or SLH-DSA key, or
/// `None` if it is not in either post-quantum OID arc.
///
/// Recognises the NIST FIPS 204 ML-DSA arc `2.16.840.1.101.3.4.3.{17,18,19}`
/// and the FIPS 205 SLH-DSA arc `2.16.840.1.101.3.4.3.{20..35}` (per the IETF
/// LAMPS ML-DSA / SLH-DSA X.509 algorithm-identifier profiles, RFC number TBC).
/// An OID that lies in either arc but whose final component is not an assigned
/// parameter-set slot — the reserved-but-unassigned SLH-DSA slots `.32`–`.35`,
/// or any other arc member with no published mapping — is still returned as the
/// matching PQC variant carrying [`PqcParamSet::Unknown`], so the `pqc` gate
/// engages and `pqc_algorithm_known` can flag it. Anything outside both arcs
/// yields `None`, leaving `public_key_algorithm()` to fall through to
/// [`PublicKeyAlg::Other`].
///
/// The OID → parameter-set table below was transcribed from FIPS 204 §4 /
/// FIPS 205 (parameter-set tables) and MUST be re-verified against the published
/// LAMPS registrations.
fn classify_pqc_oid(dotted: &str) -> Option<PublicKeyAlg> {
    // The final arithmetic component after the shared `sigAlgs` arc prefix.
    let suffix = dotted.strip_prefix(PQC_ARC_PREFIX)?;
    // The suffix must be a single integer component (no further sub-arc); a
    // longer OID such as `...3.17.1` is not an assigned PQC algorithm.
    if suffix.contains('.') {
        return None;
    }
    let slot: u32 = suffix.parse().ok()?;

    // ML-DSA (FIPS 204): .17 ML-DSA-44, .18 ML-DSA-65, .19 ML-DSA-87.
    let ml_dsa_name = match slot {
        17 => Some("ML-DSA-44"),
        18 => Some("ML-DSA-65"),
        19 => Some("ML-DSA-87"),
        _ => None,
    };
    if (17..=19).contains(&slot) {
        let params = ml_dsa_name
            .map(PqcParamSet::Known)
            .unwrap_or_else(|| PqcParamSet::Unknown(dotted.to_string()));
        return Some(PublicKeyAlg::MlDsa(params));
    }

    // SLH-DSA (FIPS 205): the reserved span .20..=.35 (16 slots); .20..=.31 are
    // the 12 published parameter sets, .32..=.35 are reserved-but-unassigned.
    if (20..=35).contains(&slot) {
        let name = slh_dsa_param_set_name(slot);
        let params = name
            .map(PqcParamSet::Known)
            .unwrap_or_else(|| PqcParamSet::Unknown(dotted.to_string()));
        return Some(PublicKeyAlg::SlhDsa(params));
    }

    None
}

/// The canonical FIPS 205 short name for an SLH-DSA OID slot in the
/// `2.16.840.1.101.3.4.3.{20..31}` published range, or `None` for an
/// unassigned slot (`.32`–`.35`).
fn slh_dsa_param_set_name(slot: u32) -> Option<&'static str> {
    match slot {
        20 => Some("SLH-DSA-SHA2-128s"),
        21 => Some("SLH-DSA-SHA2-128f"),
        22 => Some("SLH-DSA-SHA2-192s"),
        23 => Some("SLH-DSA-SHA2-192f"),
        24 => Some("SLH-DSA-SHA2-256s"),
        25 => Some("SLH-DSA-SHA2-256f"),
        26 => Some("SLH-DSA-SHAKE-128s"),
        27 => Some("SLH-DSA-SHAKE-128f"),
        28 => Some("SLH-DSA-SHAKE-192s"),
        29 => Some("SLH-DSA-SHAKE-192f"),
        30 => Some("SLH-DSA-SHAKE-256s"),
        31 => Some("SLH-DSA-SHAKE-256f"),
        _ => None,
    }
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

    mod chain_raw_bytes_accessors {
        use super::*;

        fn load_one(name: &str) -> Cert {
            let path = format!("{}/../../testdata/{name}", env!("CARGO_MANIFEST_DIR"));
            let bytes = std::fs::read(&path).unwrap();
            let mut certs = Cert::from_pem(&bytes).unwrap();
            certs.remove(0)
        }

        #[test]
        fn good_cert_name_der_is_non_empty_der_sequence() {
            let cert = load_one("good.pem");

            let subject = cert.subject_name_der().unwrap();
            let issuer = cert.issuer_name_der().unwrap();

            assert!(!subject.is_empty(), "subject Name DER is non-empty");
            assert!(!issuer.is_empty(), "issuer Name DER is non-empty");
            // The Name is a DER SEQUENCE (universal tag 0x30).
            assert_eq!(subject[0], TAG_SEQUENCE, "subject Name is a SEQUENCE");
            assert_eq!(issuer[0], TAG_SEQUENCE, "issuer Name is a SEQUENCE");
        }

        #[test]
        fn self_signed_subject_name_der_equals_issuer_name_der() {
            // good.pem is self-signed (Issuer == Subject == CN=good.example.com),
            // so the two Name encodings are byte-for-byte identical.
            let cert = load_one("good.pem");

            let subject = cert.subject_name_der().unwrap();
            let issuer = cert.issuer_name_der().unwrap();

            assert_eq!(
                subject, issuer,
                "a self-signed cert's subject and issuer Name DER must match"
            );
        }

        #[test]
        fn self_signed_ca_subject_name_der_equals_issuer_name_der() {
            // A second, structurally different self-signed CA fixture as a
            // cross-check (multi-RDN DN: CN + C + O).
            let cert = load_one("slh_dsa_root_ca.pem");

            assert_eq!(
                cert.subject_name_der().unwrap(),
                cert.issuer_name_der().unwrap(),
                "self-signed CA subject/issuer Name DER must match"
            );
        }

        #[test]
        fn good_cert_has_subject_key_id_bytes_but_no_authority_key_id() {
            // good.pem carries an SKI (20-octet key id) and NO AKI extension.
            let cert = load_one("good.pem");

            let ski = cert.subject_key_id_bytes().unwrap();
            assert!(ski.is_some(), "good.pem carries an SKI extension");
            let ski = ski.unwrap();
            assert_eq!(ski.len(), 20, "SKI key id is a 20-octet SHA-1 hash");
            // Matches the openssl-reported SKI 1D:33:53:BC:... for good.pem.
            assert_eq!(
                &ski[..4],
                &[0x1D, 0x33, 0x53, 0xBC],
                "SKI key id matches the fixture's first octets"
            );

            assert!(
                cert.authority_key_id_bytes().unwrap().is_none(),
                "good.pem has no AKI extension, so no AKI key id"
            );
        }

        #[test]
        fn ski_missing_ca_has_no_subject_key_id_bytes() {
            // rfc5280_ski_missing_ca.pem deliberately omits the SKI extension.
            let cert = load_one("rfc5280_ski_missing_ca.pem");

            assert!(
                cert.subject_key_id_bytes().unwrap().is_none(),
                "the SKI-missing fixture returns None (not Err)"
            );
        }

        #[test]
        fn self_signed_ca_with_aki_exposes_key_id_bytes() {
            // slh_dsa_root_ca.pem carries both SKI and AKI (it is self-signed, so
            // its AKI key id equals its own SKI key id).
            let cert = load_one("slh_dsa_root_ca.pem");

            let ski = cert.subject_key_id_bytes().unwrap();
            let aki = cert.authority_key_id_bytes().unwrap();

            assert!(ski.is_some(), "root CA carries an SKI");
            assert!(aki.is_some(), "root CA carries an AKI key id");
            assert_eq!(
                ski, aki,
                "a self-signed root's AKI key id equals its SKI key id"
            );
        }

        #[test]
        fn good_cert_tbs_and_signature_and_spki_are_non_empty() {
            let cert = load_one("good.pem");

            let tbs = cert.tbs_der().unwrap();
            let sig = cert.signature_value_bytes().unwrap();
            let spki = cert.issuer_spki_bytes().unwrap();

            assert!(!tbs.is_empty(), "tbs_der is non-empty");
            assert_eq!(tbs[0], TAG_SEQUENCE, "tbsCertificate is a SEQUENCE");
            // RSA-2048 signature is 256 octets.
            assert_eq!(sig.len(), 256, "RSA-2048 signature is 256 octets");
            assert!(!spki.is_empty(), "issuer_spki_bytes is non-empty");
            assert_eq!(spki[0], TAG_SEQUENCE, "SPKI is a SEQUENCE (full DER)");
        }

        #[test]
        fn tbs_der_is_a_subslice_of_the_certificate_der() {
            // The TBS DER must appear verbatim inside the full certificate DER.
            let cert = load_one("good.pem");

            let tbs = cert.tbs_der().unwrap();
            let der = cert.der_bytes();

            assert!(
                der.windows(tbs.len()).any(|w| w == tbs.as_slice()),
                "the TBS DER is a contiguous slice of the certificate DER"
            );
        }

        #[test]
        fn good_cert_signature_algorithm_oid_is_sha256_rsa() {
            // signature_algorithm_oid() is the existing accessor the verify
            // module dispatches on; confirm the known OID for good.pem.
            let cert = load_one("good.pem");

            assert_eq!(
                cert.signature_algorithm_oid().unwrap(),
                "1.2.840.113549.1.1.11",
                "good.pem is signed with sha256WithRSAEncryption"
            );
        }

        #[test]
        fn chain_bundle_certs_expose_name_der_and_ski() {
            // chain_bundle.pem holds two certs; each exposes a non-empty Name DER
            // and a present SKI. (Cross-cert linkage is covered by task 04's
            // dedicated chain fixtures.)
            let path = format!(
                "{}/../../testdata/chain_bundle.pem",
                env!("CARGO_MANIFEST_DIR")
            );
            let bytes = std::fs::read(&path).unwrap();
            let certs = Cert::from_pem(&bytes).unwrap();
            assert_eq!(certs.len(), 2, "chain_bundle has two certs");

            for cert in &certs {
                assert!(!cert.subject_name_der().unwrap().is_empty());
                assert!(!cert.issuer_name_der().unwrap().is_empty());
                assert!(
                    cert.subject_key_id_bytes().unwrap().is_some(),
                    "each chain_bundle cert carries an SKI"
                );
                assert!(!cert.tbs_der().unwrap().is_empty());
                assert!(!cert.signature_value_bytes().unwrap().is_empty());
                assert!(!cert.issuer_spki_bytes().unwrap().is_empty());
            }
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

    mod feature09_accessors {
        use super::*;

        /// Loads the workspace `testdata/good.pem` fixture: a BR-compliant TLS
        /// leaf with serverAuth EKU (NO codeSigning), no KeyUsage extension, and
        /// no AIA / CRL-DP extensions — the negative case for every CS accessor.
        fn good_cert() -> Cert {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
            let bytes = std::fs::read(path).unwrap();
            let mut certs = Cert::from_pem(&bytes).unwrap();
            certs.remove(0)
        }

        #[test]
        fn good_cert_does_not_assert_code_signing() {
            let cert = good_cert();

            // good.pem asserts serverAuth, not codeSigning.
            assert!(!cert.has_code_signing().unwrap());

            // The EkuView.code_signing field agrees with the predicate.
            let eku = cert.extended_key_usage().unwrap().unwrap();
            assert!(!eku.code_signing, "good.pem EKU has no codeSigning purpose");
            assert!(eku.server_auth, "good.pem EKU asserts serverAuth");
            assert!(
                !eku.oids.contains(&"1.3.6.1.5.5.7.3.3".to_string()),
                "codeSigning OID absent from EKU oids"
            );
        }

        #[test]
        fn good_cert_has_no_authority_info_access() {
            let cert = good_cert();

            assert!(!cert.has_authority_info_access().unwrap());
        }

        #[test]
        fn good_cert_has_no_crl_distribution_points() {
            let cert = good_cert();

            assert!(!cert.has_crl_distribution_points().unwrap());
        }

        #[test]
        fn good_cert_has_no_key_usage_so_no_digital_signature_view() {
            let cert = good_cert();

            // good.pem carries no KeyUsage extension, so there is no view at all;
            // a code-signing leaf would expose `digital_signature == true` here.
            assert!(
                cert.key_usage().unwrap().is_none(),
                "good.pem has no KeyUsage extension"
            );
        }
    }

    mod feature10_accessors {
        use super::*;

        /// Loads the workspace `testdata/good.pem` fixture: a BR-compliant TLS
        /// leaf with the serverAuth EKU (NO emailProtection), a SAN carrying one
        /// `dNSName` (no `rfc822Name`), no AKI, no CRL-DP, and no subject
        /// `emailAddress` / `countryName` attributes — the negative case for
        /// every S/MIME accessor.
        fn good_cert() -> Cert {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
            let bytes = std::fs::read(path).unwrap();
            let mut certs = Cert::from_pem(&bytes).unwrap();
            certs.remove(0)
        }

        #[test]
        fn good_cert_san_has_no_rfc822_names() {
            let cert = good_cert();

            // good.pem's SAN carries a dNSName, not an rfc822Name.
            assert!(cert.san_rfc822_names().unwrap().is_empty());
        }

        #[test]
        fn good_cert_does_not_assert_email_protection() {
            let cert = good_cert();

            // good.pem asserts serverAuth, not emailProtection.
            assert!(!cert.has_email_protection().unwrap());

            // The EkuView.email_protection field agrees with the predicate.
            let eku = cert.extended_key_usage().unwrap().unwrap();
            assert!(
                !eku.email_protection,
                "good.pem EKU has no emailProtection purpose"
            );
            assert!(
                !eku.oids.contains(&"1.3.6.1.5.5.7.3.4".to_string()),
                "emailProtection OID absent from EKU oids"
            );
        }

        #[test]
        fn good_cert_has_no_authority_key_identifier_predicate() {
            let cert = good_cert();

            // Presence predicate agrees with the field-level view (both absent).
            assert!(!cert.has_authority_key_identifier().unwrap());
            assert!(cert.authority_key_identifier().unwrap().is_none());
        }

        #[test]
        fn good_cert_has_no_crl_distribution_point_uris() {
            let cert = good_cert();

            // good.pem carries no CRL-DP extension, so no fullName URIs.
            assert!(!cert.has_crl_distribution_points().unwrap());
            assert!(cert.crl_distribution_point_uris().unwrap().is_empty());
        }

        #[test]
        fn good_cert_has_no_subject_email_address() {
            let cert = good_cert();

            assert!(cert.subject_email_addresses().unwrap().is_empty());
        }

        #[test]
        fn good_cert_subject_country_names_matches_values() {
            let cert = good_cert();

            // good.pem has no countryName; the S/MIME-facing alias agrees with
            // the existing BR-facing accessor it delegates to.
            assert!(cert.subject_country_names().unwrap().is_empty());
            assert_eq!(
                cert.subject_country_names().unwrap(),
                cert.subject_country_values().unwrap()
            );
        }
    }

    mod feature11_ev_accessors {
        use super::*;

        /// Loads the workspace `testdata/good.pem` fixture: a non-EV BR-compliant
        /// TLS leaf — no `certificatePolicies` extension, no EV subject identity
        /// attributes (organizationName / businessCategory / jurisdiction country
        /// / subject serialNumber / organizationIdentifier), and a single
        /// non-wildcard SAN `dNSName`. The negative/empty case for every EV
        /// accessor; positive coverage comes from the EV fixtures (task 04).
        fn good_cert() -> Cert {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
            let bytes = std::fs::read(path).unwrap();
            let mut certs = Cert::from_pem(&bytes).unwrap();
            certs.remove(0)
        }

        #[test]
        fn good_cert_has_no_certificate_policy_oids() {
            let cert = good_cert();

            // good.pem is a non-EV leaf: no certificatePolicies extension, so it
            // is not in EV scope.
            assert!(cert.certificate_policy_oids().unwrap().is_empty());
        }

        #[test]
        fn good_cert_has_no_organization_name() {
            let cert = good_cert();

            assert!(cert.subject_organization_names().unwrap().is_empty());
        }

        #[test]
        fn good_cert_has_no_business_category() {
            let cert = good_cert();

            assert!(cert.subject_business_category().unwrap().is_empty());
        }

        #[test]
        fn good_cert_has_no_jurisdiction_country() {
            let cert = good_cert();

            assert!(cert.subject_jurisdiction_country().unwrap().is_empty());
        }

        #[test]
        fn good_cert_has_no_subject_serial_number_attribute() {
            let cert = good_cert();

            // The subject-DN serialNumber attribute is absent...
            assert!(cert.subject_serial_numbers().unwrap().is_empty());

            // ...while the certificate serial number (a distinct field) is still
            // present and positive — proving the two are not conflated.
            let summary = cert.serial_summary().unwrap();
            assert!(!summary.is_zero);
            assert!(!summary.is_negative);
        }

        #[test]
        fn good_cert_has_no_organization_identifier() {
            let cert = good_cert();

            assert!(cert.subject_organization_identifiers().unwrap().is_empty());
        }

        #[test]
        fn good_cert_has_no_wildcard_san_names() {
            let cert = good_cert();

            // good.pem's single SAN dNSName (good.example.com) is not a wildcard.
            assert!(cert.san_wildcard_dns_names().unwrap().is_empty());
            assert_eq!(
                cert.san_dns_names().unwrap(),
                vec!["good.example.com".to_string()],
                "the underlying SAN dNSName is the non-wildcard CN"
            );
        }
    }

    mod feature13_pqc_accessors {
        use super::*;

        /// Loads the workspace `testdata/good.pem` fixture: an RSA-2048 BR-clean
        /// TLS leaf — the negative/regression case for the PQC additions (it must
        /// stay `PublicKeyAlg::Rsa`, with a present SPKI parameters field and a
        /// non-empty raw key, and no PQC reclassification).
        fn good_cert() -> Cert {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
            let bytes = std::fs::read(path).unwrap();
            let mut certs = Cert::from_pem(&bytes).unwrap();
            certs.remove(0)
        }

        #[test]
        fn good_cert_is_still_rsa_not_reclassified_as_pqc() {
            let cert = good_cert();

            // Regression: the PQC arc additions must not shift an RSA key.
            assert_eq!(cert.public_key_algorithm().unwrap(), PublicKeyAlg::Rsa);
        }

        #[test]
        fn good_cert_rsa_spki_has_present_parameters() {
            let cert = good_cert();

            // rsaEncryption carries an explicit NULL parameters field, so the
            // presence predicate reports `true`.
            assert!(cert.spki_algorithm_parameters_present().unwrap());
        }

        #[test]
        fn good_cert_signature_parameters_present_is_readable() {
            let cert = good_cert();

            // sha256WithRSAEncryption also carries an explicit NULL parameters
            // field; the accessor returns without panicking.
            assert!(cert.signature_algorithm_parameters_present().unwrap());
        }

        #[test]
        fn good_cert_raw_public_key_len_is_nonzero() {
            let cert = good_cert();

            // The raw SPKI BIT STRING value (a 2048-bit RSA SPKI SEQUENCE) is far
            // from empty; we only assert it is read without panicking.
            assert!(cert.public_key_raw_len().unwrap() > 0);
        }

        #[test]
        fn good_cert_key_usage_is_absent_so_no_view() {
            let cert = good_cert();

            // good.pem has no KeyUsage extension; the new bits are only reachable
            // through a present view, so there is nothing to read here.
            assert!(cert.key_usage().unwrap().is_none());
        }
    }

    mod classify_pqc_oid {
        use super::super::{classify_pqc_oid, slh_dsa_param_set_name};
        use super::{PqcParamSet, PublicKeyAlg};

        #[test]
        fn ml_dsa_slots_map_to_known_param_sets() {
            assert_eq!(
                classify_pqc_oid("2.16.840.1.101.3.4.3.17"),
                Some(PublicKeyAlg::MlDsa(PqcParamSet::Known("ML-DSA-44")))
            );
            assert_eq!(
                classify_pqc_oid("2.16.840.1.101.3.4.3.18"),
                Some(PublicKeyAlg::MlDsa(PqcParamSet::Known("ML-DSA-65")))
            );
            assert_eq!(
                classify_pqc_oid("2.16.840.1.101.3.4.3.19"),
                Some(PublicKeyAlg::MlDsa(PqcParamSet::Known("ML-DSA-87")))
            );
        }

        #[test]
        fn slh_dsa_published_slots_map_to_known_param_sets() {
            // First and last of the 12 published SLH-DSA parameter sets.
            assert_eq!(
                classify_pqc_oid("2.16.840.1.101.3.4.3.20"),
                Some(PublicKeyAlg::SlhDsa(PqcParamSet::Known(
                    "SLH-DSA-SHA2-128s"
                )))
            );
            assert_eq!(
                classify_pqc_oid("2.16.840.1.101.3.4.3.31"),
                Some(PublicKeyAlg::SlhDsa(PqcParamSet::Known(
                    "SLH-DSA-SHAKE-256f"
                )))
            );
        }

        #[test]
        fn slh_dsa_reserved_unassigned_slots_are_unknown_arc_members() {
            // .32..=.35 lie in the reserved SLH-DSA span but name no published
            // parameter set: still an SLH-DSA variant, carrying Unknown so the
            // gate engages and pqc_algorithm_known can flag it.
            for slot in 32..=35 {
                let dotted = format!("2.16.840.1.101.3.4.3.{slot}");
                assert_eq!(
                    classify_pqc_oid(&dotted),
                    Some(PublicKeyAlg::SlhDsa(PqcParamSet::Unknown(dotted.clone()))),
                    "slot .{slot} should be an unknown SLH-DSA arc member"
                );
            }
        }

        #[test]
        fn oids_outside_both_arcs_are_not_pqc() {
            // RSA / EC OIDs and a low/high arc neighbour outside .17..=.35.
            assert_eq!(classify_pqc_oid("1.2.840.113549.1.1.1"), None);
            assert_eq!(classify_pqc_oid("1.2.840.10045.2.1"), None);
            assert_eq!(classify_pqc_oid("2.16.840.1.101.3.4.3.16"), None);
            assert_eq!(classify_pqc_oid("2.16.840.1.101.3.4.3.36"), None);
        }

        #[test]
        fn deeper_sub_arc_is_not_a_pqc_algorithm() {
            // A longer OID under an assigned slot is not itself an algorithm OID.
            assert_eq!(classify_pqc_oid("2.16.840.1.101.3.4.3.17.1"), None);
        }

        #[test]
        fn malformed_arc_suffix_is_not_pqc() {
            // A non-numeric trailing component cannot be a slot number.
            assert_eq!(classify_pqc_oid("2.16.840.1.101.3.4.3.xx"), None);
        }

        #[test]
        fn slh_dsa_name_table_covers_published_range_only() {
            assert!(slh_dsa_param_set_name(19).is_none());
            assert!(slh_dsa_param_set_name(20).is_some());
            assert!(slh_dsa_param_set_name(31).is_some());
            assert!(slh_dsa_param_set_name(32).is_none());
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

    mod feature08_inspection_accessors {
        use super::*;

        /// Loads the workspace `testdata/good.pem` fixture: an RSA-2048 / SHA-256
        /// BR-compliant TLS leaf with `CN=good.example.com`, a SAN carrying one
        /// `dNSName` (good.example.com), the serverAuth EKU, and **no** KeyUsage
        /// extension.
        fn good_cert() -> Cert {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/good.pem");
            let bytes = std::fs::read(path).unwrap();
            let mut certs = Cert::from_pem(&bytes).unwrap();
            certs.remove(0)
        }

        #[test]
        fn good_cert_subject_dn_contains_common_name() {
            let cert = good_cert();

            let subject = cert.subject_rfc4514().unwrap();

            assert!(
                subject.contains("CN=good.example.com"),
                "subject DN should render the CN, got: {subject}"
            );
        }

        #[test]
        fn good_cert_issuer_dn_is_non_empty() {
            let cert = good_cert();

            let issuer = cert.issuer_rfc4514().unwrap();

            assert!(!issuer.is_empty(), "issuer DN should render to a string");
        }

        #[test]
        fn good_cert_serial_hex_is_uppercase_colon_separated() {
            let cert = good_cert();

            let hex = cert.serial_hex().unwrap();
            let octets = cert.serial_der_octets().unwrap();

            // One two-digit group per octet, joined by ':'.
            assert_eq!(hex.split(':').count(), octets.len());
            assert!(
                hex.chars().all(|c| c.is_ascii_hexdigit() || c == ':'),
                "serial hex should be hex digits and colons, got: {hex}"
            );
            assert!(
                hex.chars()
                    .filter(|c| c.is_ascii_alphabetic())
                    .all(|c| c.is_ascii_uppercase()),
                "serial hex letters should be uppercase, got: {hex}"
            );
            // Spot-check the formatting against the raw octets.
            let expected: Vec<String> = octets.iter().map(|b| format!("{b:02X}")).collect();
            assert_eq!(hex, expected.join(":"));
        }

        #[test]
        fn good_cert_signature_algorithm_is_named_sha256_rsa() {
            let cert = good_cert();

            let alg = cert.signature_algorithm().unwrap();

            assert_eq!(alg.oid, "1.2.840.113549.1.1.11");
            assert_eq!(alg.name.as_deref(), Some("sha256WithRSAEncryption"));
        }

        #[test]
        fn good_cert_public_key_info_is_rsa_2048() {
            let cert = good_cert();

            let info = cert.public_key_info().unwrap();

            assert_eq!(info.algorithm.oid, "1.2.840.113549.1.1.1");
            assert_eq!(info.key_bits, Some(2048), "RSA-2048 modulus");
            assert!(info.curve.is_none(), "RSA key has no named curve");
        }

        #[test]
        fn good_cert_has_no_key_usage_bits() {
            let cert = good_cert();

            // good.pem deliberately carries NO KeyUsage extension.
            assert!(
                cert.key_usage_bits().unwrap().is_none(),
                "good.pem has no KeyUsage extension"
            );
        }

        #[test]
        fn good_cert_san_entries_carry_the_dns_name() {
            let cert = good_cert();

            let san = cert.san_entries().unwrap().unwrap();

            assert_eq!(
                san.entries,
                vec![GeneralNameView {
                    kind: "DNS".to_string(),
                    value: "good.example.com".to_string(),
                }],
                "good.pem's SAN carries one dNSName equal to the CN"
            );
        }
    }

    mod pqc_name_for_oid {
        use super::super::pqc_name_for_oid;

        #[test]
        fn known_slh_dsa_slot_resolves_to_fips_name() {
            assert_eq!(
                pqc_name_for_oid("2.16.840.1.101.3.4.3.20").as_deref(),
                Some("SLH-DSA-SHA2-128s")
            );
        }

        #[test]
        fn known_ml_dsa_slot_resolves_to_fips_name() {
            assert_eq!(
                pqc_name_for_oid("2.16.840.1.101.3.4.3.18").as_deref(),
                Some("ML-DSA-65")
            );
        }

        #[test]
        fn unassigned_pqc_slot_has_no_name() {
            // .32..=.35 are reserved-but-unassigned SLH-DSA slots: no name.
            assert!(pqc_name_for_oid("2.16.840.1.101.3.4.3.32").is_none());
        }

        #[test]
        fn non_pqc_oid_has_no_name() {
            assert!(pqc_name_for_oid("1.2.840.113549.1.1.1").is_none());
        }
    }

    mod general_name_view {
        use super::super::general_name_view;
        use x509_parser::extensions::GeneralName;

        #[test]
        fn dns_name_renders_kind_and_value() {
            let view = general_name_view(&GeneralName::DNSName("example.com"));

            assert_eq!(view.kind, "DNS");
            assert_eq!(view.value, "example.com");
        }

        #[test]
        fn email_name_renders_kind_and_value() {
            let view = general_name_view(&GeneralName::RFC822Name("a@example.com"));

            assert_eq!(view.kind, "email");
            assert_eq!(view.value, "a@example.com");
        }

        #[test]
        fn ipv4_address_renders_dotted_quad() {
            let view = general_name_view(&GeneralName::IPAddress(&[10, 0, 0, 1]));

            assert_eq!(view.kind, "IP");
            assert_eq!(view.value, "10.0.0.1");
        }

        #[test]
        fn odd_length_ip_falls_back_to_hex() {
            let view = general_name_view(&GeneralName::IPAddress(&[0x0A, 0xFF, 0x01]));

            assert_eq!(view.kind, "IP");
            assert_eq!(view.value, "0A:FF:01");
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
