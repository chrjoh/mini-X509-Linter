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
use x509_parser::certificate::X509Certificate;
use x509_parser::pem::Pem;
use x509_parser::prelude::FromDer;
use x509_parser::time::ASN1Time;

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

    /// The raw DER bytes backing this certificate.
    pub fn der_bytes(&self) -> &[u8] {
        &self.der
    }
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
}
