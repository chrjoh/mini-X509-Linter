//! PEM-bundle writer for the `--save` capability (feature 07, `fetch`).
//!
//! When `--from-host` fetches a chain, `--save <path>` writes the full presented
//! chain — leaf first, then intermediates in presentation order — to disk as a
//! single PEM bundle so it can be archived, diffed, or re-linted later via the
//! normal `<PATH>` input.
//!
//! The captured DER bytes are written **with no transformation**: each cert is
//! base64-encoded (standard RFC 4648 alphabet) and wrapped in
//! `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` at 64-char lines.
//!
//! ## Base64 source
//!
//! The CLI has no base64/PEM crate in its dependency tree (only `linter`,
//! `clap`, `anyhow`, `serde_json`). Rather than pull a new dependency for a
//! trivial encode, the standard base64 alphabet is hand-rolled below.
//!
//! ## Overwrite policy
//!
//! Writing refuses to clobber an existing file unless `force` is set; the parent
//! directory must already exist (it is not created). Files are written `0o644`
//! (certs are public, not secret). All IO failures map to a clear, generic
//! `anyhow` error so no internal detail leaks.

#![cfg(feature = "fetch")]

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

/// The standard base64 alphabet (RFC 4648, table 1).
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes `data` as standard base64 (RFC 4648) with `=` padding.
fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;

        out.push(BASE64_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(BASE64_ALPHABET[((n >> 12) & 0x3f) as usize] as char);

        if chunk.len() > 1 {
            out.push(BASE64_ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(BASE64_ALPHABET[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }

    out
}

/// Encodes a single DER certificate as one PEM block, base64 wrapped at 64 cols.
fn der_to_pem_block(der: &[u8]) -> String {
    let b64 = base64_encode(der);
    let mut out = String::with_capacity(b64.len() + 64);
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        // `b64` is ASCII, so chunking on byte boundaries is safe.
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Encodes the presented chain (leaf first, then intermediates in order) as a
/// single concatenated PEM bundle.
pub fn encode_chain_pem(leaf_der: &[u8], intermediates_der: &[Vec<u8>]) -> String {
    let mut out = der_to_pem_block(leaf_der);
    for der in intermediates_der {
        out.push_str(&der_to_pem_block(der));
    }
    out
}

/// Writes the presented chain as a PEM bundle to `path`.
///
/// The bundle is `leaf_der` followed by each entry of `intermediates_der`, in
/// order. The captured DER is re-encoded as PEM with no transformation.
///
/// # Overwrite policy
///
/// If `path` already exists and `force` is `false`, this refuses to overwrite
/// and returns an error. The parent directory must already exist; it is not
/// created.
///
/// # Errors
///
/// Returns a generic error if `path` exists and `force` is not set, if the
/// parent directory is missing, or if the write (or permission set) fails. No
/// internal IO detail is leaked beyond the path the user supplied.
pub fn save_chain(
    path: &Path,
    leaf_der: &[u8],
    intermediates_der: &[Vec<u8>],
    force: bool,
) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "refusing to overwrite existing file: {} (pass --force to overwrite)",
            path.display()
        );
    }

    // The parent directory must already exist; we do not create it. An empty
    // parent (e.g. a bare filename) means the current directory, which exists.
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.is_dir()
    {
        bail!(
            "parent directory does not exist: {} (create it first)",
            parent.display()
        );
    }

    let pem = encode_chain_pem(leaf_der, intermediates_der);
    fs::write(path, pem.as_bytes())
        .with_context(|| format!("failed to write certificate bundle to {}", path.display()))?;

    // Certs are public, not secret: 0o644 is fine.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    mod base64_encode {
        use super::*;

        #[test]
        fn encodes_rfc4648_test_vectors() {
            // From RFC 4648 section 10.
            assert_eq!(base64_encode(b""), "");
            assert_eq!(base64_encode(b"f"), "Zg==");
            assert_eq!(base64_encode(b"fo"), "Zm8=");
            assert_eq!(base64_encode(b"foo"), "Zm9v");
            assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
            assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
            assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        }

        #[test]
        fn encodes_all_byte_values() {
            // Exercises the +/ alphabet tail and high bits.
            let data: Vec<u8> = (0u8..=255).collect();
            let encoded = base64_encode(&data);
            assert_eq!(decode_base64(&encoded), data);
        }
    }

    mod encode_chain_pem {
        use super::*;

        #[test]
        fn round_trips_leaf_only() {
            let leaf = sample_der(0x11, 200);
            let pem = encode_chain_pem(&leaf, &[]);

            let blocks = parse_pem_blocks(&pem);
            assert_eq!(blocks.len(), 1);
            assert_eq!(blocks[0], leaf);
        }

        #[test]
        fn round_trips_leaf_and_intermediates_in_order() {
            let leaf = sample_der(0x01, 50);
            let int1 = sample_der(0x02, 130);
            let int2 = sample_der(0x03, 64);
            let pem = encode_chain_pem(&leaf, &[int1.clone(), int2.clone()]);

            let blocks = parse_pem_blocks(&pem);
            assert_eq!(blocks.len(), 3);
            assert_eq!(blocks[0], leaf, "leaf must be first");
            assert_eq!(blocks[1], int1);
            assert_eq!(blocks[2], int2);
        }

        #[test]
        fn wraps_base64_at_64_columns() {
            let der = sample_der(0x42, 300);
            let pem = encode_chain_pem(&der, &[]);

            for line in pem.lines() {
                if line.starts_with("-----") {
                    continue;
                }
                assert!(line.len() <= 64, "base64 line exceeds 64 cols: {line:?}");
            }
        }
    }

    mod save_chain {
        use super::*;

        #[test]
        fn writes_a_re_parseable_bundle() {
            let dir = temp_dir("save-write");
            let path = dir.join("chain.pem");
            let leaf = sample_der(0x01, 100);
            let int = sample_der(0x02, 80);

            save_chain(&path, &leaf, std::slice::from_ref(&int), false).unwrap();

            let written = fs::read(&path).unwrap();
            let blocks = parse_pem_blocks(std::str::from_utf8(&written).unwrap());
            assert_eq!(blocks, vec![leaf, int]);

            fs::remove_dir_all(&dir).ok();
        }

        #[test]
        fn refuses_to_overwrite_without_force() {
            let dir = temp_dir("save-refuse");
            let path = dir.join("chain.pem");
            fs::write(&path, b"existing").unwrap();

            let err = save_chain(&path, &sample_der(0x01, 10), &[], false).unwrap_err();
            assert!(err.to_string().contains("refusing to overwrite"));
            // The pre-existing file is untouched.
            assert_eq!(fs::read(&path).unwrap(), b"existing");

            fs::remove_dir_all(&dir).ok();
        }

        #[test]
        fn overwrites_with_force() {
            let dir = temp_dir("save-force");
            let path = dir.join("chain.pem");
            fs::write(&path, b"existing").unwrap();

            let leaf = sample_der(0x07, 40);
            save_chain(&path, &leaf, &[], true).unwrap();

            let blocks = parse_pem_blocks(std::str::from_utf8(&fs::read(&path).unwrap()).unwrap());
            assert_eq!(blocks, vec![leaf]);

            fs::remove_dir_all(&dir).ok();
        }

        #[test]
        fn errors_when_parent_directory_missing() {
            let dir = temp_dir("save-noparent");
            let path = dir.join("does-not-exist").join("chain.pem");

            let err = save_chain(&path, &sample_der(0x01, 10), &[], false).unwrap_err();
            assert!(err.to_string().contains("parent directory does not exist"));

            fs::remove_dir_all(&dir).ok();
        }

        #[cfg(unix)]
        #[test]
        fn sets_0o644_permissions() {
            use std::os::unix::fs::PermissionsExt;

            let dir = temp_dir("save-perms");
            let path = dir.join("chain.pem");
            save_chain(&path, &sample_der(0x01, 10), &[], false).unwrap();

            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);

            fs::remove_dir_all(&dir).ok();
        }
    }

    // --- Test helpers -------------------------------------------------------

    /// Builds deterministic pseudo-DER bytes (content is opaque to the writer).
    fn sample_der(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
    }

    /// Creates and returns a unique temp directory under the system temp dir.
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("mini-x509-{tag}-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Parses every `-----BEGIN CERTIFICATE-----` block out of `pem`, returning
    /// the decoded DER of each, in order.
    fn parse_pem_blocks(pem: &str) -> Vec<Vec<u8>> {
        let mut blocks = Vec::new();
        let mut current: Option<String> = None;
        for line in pem.lines() {
            match line {
                "-----BEGIN CERTIFICATE-----" => current = Some(String::new()),
                "-----END CERTIFICATE-----" => {
                    if let Some(b64) = current.take() {
                        blocks.push(decode_base64(&b64));
                    }
                }
                other => {
                    if let Some(buf) = current.as_mut() {
                        buf.push_str(other);
                    }
                }
            }
        }
        blocks
    }

    /// Minimal standard-base64 decoder for the round-trip tests.
    fn decode_base64(s: &str) -> Vec<u8> {
        fn val(c: u8) -> Option<u32> {
            match c {
                b'A'..=b'Z' => Some((c - b'A') as u32),
                b'a'..=b'z' => Some((c - b'a' + 26) as u32),
                b'0'..=b'9' => Some((c - b'0' + 52) as u32),
                b'+' => Some(62),
                b'/' => Some(63),
                _ => None,
            }
        }

        let cleaned: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        let mut out = Vec::new();
        for chunk in cleaned.chunks(4) {
            let pad = chunk.iter().filter(|&&b| b == b'=').count();
            let mut n = 0u32;
            for &c in chunk {
                n = (n << 6) | val(c).unwrap_or(0);
            }
            // Each 4-char group yields 3 bytes minus the padding count.
            out.push((n >> 16) as u8);
            if pad < 2 {
                out.push((n >> 8) as u8);
            }
            if pad < 1 {
                out.push(n as u8);
            }
        }
        out
    }
}
