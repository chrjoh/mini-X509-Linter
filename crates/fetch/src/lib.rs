//! Blocking TLS certificate retrieval for the mini-X509-Linter.
//!
//! This crate performs a **blocking** TLS handshake against a live host and
//! returns the certificate chain the server presented — leaf plus intermediates,
//! in DER — together with a separate [`VerificationVerdict`] describing whether
//! that chain chains to a trusted root.
//!
//! It is deliberately split into two passes:
//!
//! 1. A handshake that uses a private, accept-any **capture verifier**. This lets
//!    the handshake complete even for expired / self-signed / untrusted certs so
//!    the chain can always be extracted for linting and archiving.
//! 2. A separate verification pass using a real [`rustls::client::WebPkiServerVerifier`]
//!    over the Mozilla [`webpki_roots`] store, producing the [`VerificationVerdict`].
//!
//! The capture verifier is private to this crate and exists *only* for chain
//! extraction. See the `// SECURITY:` note on the internal `CaptureVerifier`; it
//! must never be reused for any trust decision.
//!
//! This crate does **not** depend on the `linter` crate; the CLI wires the two
//! together.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rustls::ClientConnection;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

/// The default TLS port used when the target omits an explicit port.
pub const DEFAULT_PORT: u16 = 443;

/// Errors that can occur while resolving, connecting to, or handshaking with a
/// TLS host, or while validating the requested target.
///
/// Messages are intentionally generic — they describe *what* failed (connect,
/// handshake, timeout, parse) without leaking internal detail.
#[derive(thiserror::Error, Debug)]
pub enum FetchError {
    /// The `host[:port]` target string was malformed (empty host, bad port,
    /// stray characters, etc.).
    #[error("invalid target: {0}")]
    InvalidTarget(String),

    /// The port was outside the valid `1..=65535` range (e.g. `0`).
    #[error("invalid port: must be between 1 and 65535")]
    InvalidPort,

    /// The host is an IP address but no SNI was supplied. SNI cannot be derived
    /// from an IP, so the caller must provide one explicitly.
    #[error("an explicit SNI is required when connecting to an IP address")]
    SniRequiredForIp,

    /// The supplied (or derived) SNI string was not a valid DNS name.
    #[error("invalid SNI: not a valid DNS name")]
    InvalidSni,

    /// The target resolved to a private, loopback, or otherwise non-global
    /// address and the SSRF guard rejected it.
    #[error("target address is not permitted by the SSRF guard")]
    BlockedAddress,

    /// DNS resolution produced no usable address for the target.
    #[error("could not resolve target host")]
    Resolution,

    /// Establishing the TCP connection failed (refused, unreachable, etc.).
    #[error("could not connect to target host")]
    Connect,

    /// The connection or handshake did not complete within the timeout.
    #[error("connection timed out")]
    Timeout,

    /// The TLS handshake failed (protocol error, the server closed the
    /// connection, the presented certs were unparseable, etc.).
    #[error("TLS handshake failed")]
    Handshake,

    /// The handshake completed but the server presented no certificate.
    #[error("server presented no certificate")]
    EmptyChain,

    /// The rustls crypto provider could not be initialized.
    #[error("TLS provider initialization failed")]
    Provider,
}

/// Whether the presented chain chains to a trusted root.
///
/// This is reported alongside the captured chain and is *independent* of whether
/// the chain was successfully captured: an [`Invalid`](VerificationVerdict::Invalid)
/// verdict never prevents the chain from being returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationVerdict {
    /// The chain is valid for the requested name and chains to a trusted root.
    Valid,
    /// The chain failed verification; `reason` is a short, generic explanation.
    Invalid {
        /// A short, human-readable reason the verification failed.
        reason: String,
    },
}

/// The certificate chain a host presented, plus the verification verdict.
///
/// `leaf_der` is the end-entity certificate; `intermediates_der` holds any
/// intermediate certificates in the order the server sent them. Both are raw DER.
#[derive(Debug, Clone)]
pub struct FetchedChain {
    /// DER bytes of the end-entity (leaf) certificate.
    pub leaf_der: Vec<u8>,
    /// DER bytes of each intermediate certificate, in presentation order.
    pub intermediates_der: Vec<Vec<u8>>,
    /// The verdict from verifying the presented chain against a trusted root store.
    pub verdict: VerificationVerdict,
}

/// Classification of a parsed host: a DNS hostname or a literal IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKind {
    /// A DNS hostname (SNI can be derived from it).
    Hostname(String),
    /// A literal IPv4/IPv6 address (SNI cannot be derived; must be supplied).
    Ip(IpAddr),
}

/// A validated connection target: a host (hostname or IP) and a port.
///
/// Construct one with [`Target::parse`], which enforces the `host[:port]` shape,
/// applies the [`DEFAULT_PORT`] when the port is omitted, and validates the port
/// range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    host: HostKind,
    port: u16,
}

impl Target {
    /// Parse a `host[:port]` target string.
    ///
    /// The host may be a DNS hostname or a literal IPv4/IPv6 address. IPv6
    /// literals with an explicit port must be bracketed (`[::1]:443`); a bare
    /// IPv6 literal (`::1`) is accepted and uses [`DEFAULT_PORT`]. When the port
    /// is omitted, [`DEFAULT_PORT`] (443) is used.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::InvalidTarget`] if the string is empty or malformed,
    /// and [`FetchError::InvalidPort`] if the port is not in `1..=65535`.
    pub fn parse(target: &str) -> Result<Self, FetchError> {
        let target = target.trim();
        if target.is_empty() {
            return Err(FetchError::InvalidTarget("empty target".to_string()));
        }

        let (host_str, port) = split_host_port(target)?;
        if host_str.is_empty() {
            return Err(FetchError::InvalidTarget("empty host".to_string()));
        }

        let host = classify_host(host_str);
        Ok(Self { host, port })
    }

    /// The classified host (hostname or IP).
    #[must_use]
    pub fn host(&self) -> &HostKind {
        &self.host
    }

    /// The resolved port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The host as a string, suitable for DNS resolution / socket addressing.
    fn host_string(&self) -> String {
        match &self.host {
            HostKind::Hostname(h) => h.clone(),
            HostKind::Ip(ip) => ip.to_string(),
        }
    }
}

/// Split a `host[:port]` string into its host and port parts, applying the
/// default port and validating the port range.
fn split_host_port(target: &str) -> Result<(&str, u16), FetchError> {
    // Bracketed IPv6 form: `[addr]` or `[addr]:port`.
    if let Some(rest) = target.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| FetchError::InvalidTarget("unterminated IPv6 bracket".to_string()))?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = if after.is_empty() {
            DEFAULT_PORT
        } else if let Some(p) = after.strip_prefix(':') {
            parse_port(p)?
        } else {
            return Err(FetchError::InvalidTarget(
                "unexpected characters after IPv6 bracket".to_string(),
            ));
        };
        return Ok((host, port));
    }

    // A bare IPv6 literal (more than one colon, no brackets) — no port allowed.
    if target.matches(':').count() > 1 {
        if target.parse::<IpAddr>().is_ok() {
            return Ok((target, DEFAULT_PORT));
        }
        return Err(FetchError::InvalidTarget(
            "ambiguous host (bracket IPv6 literals to add a port)".to_string(),
        ));
    }

    // hostname or IPv4, optionally with `:port`.
    match target.rsplit_once(':') {
        Some((host, port)) => Ok((host, parse_port(port)?)),
        None => Ok((target, DEFAULT_PORT)),
    }
}

/// Parse and range-check a port string.
fn parse_port(port: &str) -> Result<u16, FetchError> {
    let value: u32 = port
        .parse()
        .map_err(|_| FetchError::InvalidTarget("non-numeric port".to_string()))?;
    if !(1..=u32::from(u16::MAX)).contains(&value) {
        return Err(FetchError::InvalidPort);
    }
    // The range check above guarantees this fits in u16.
    u16::try_from(value).map_err(|_| FetchError::InvalidPort)
}

/// Classify a host string as a literal IP address or a DNS hostname.
fn classify_host(host: &str) -> HostKind {
    match host.parse::<IpAddr>() {
        Ok(ip) => HostKind::Ip(ip),
        Err(_) => HostKind::Hostname(host.to_string()),
    }
}

/// Resolve the SNI [`ServerName`] for a target according to the SNI rules.
///
/// - Hostname target: derive the SNI from the hostname unless `sni` overrides it.
/// - IP target: SNI cannot be derived, so an explicit `sni` is **required**.
///
/// # Errors
///
/// Returns [`FetchError::SniRequiredForIp`] for an IP target with no `sni`, and
/// [`FetchError::InvalidSni`] if the supplied (or derived) name is not a valid
/// DNS name.
fn resolve_sni(target: &Target, sni: Option<&str>) -> Result<ServerName<'static>, FetchError> {
    let name = match (&target.host, sni) {
        // Explicit override always wins.
        (_, Some(name)) => name.to_string(),
        (HostKind::Hostname(host), None) => host.clone(),
        (HostKind::Ip(_), None) => return Err(FetchError::SniRequiredForIp),
    };

    ServerName::try_from(name).map_err(|_| FetchError::InvalidSni)
}

/// Returns `true` if `ip` is a private, loopback, link-local, or otherwise
/// non-globally-routable address that the SSRF guard should reject.
fn is_blocked_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                // 100.64.0.0/10 (CGNAT shared address space).
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // Unique local addresses fc00::/7.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local fe80::/10.
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped: re-check the embedded v4 address.
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|m| is_blocked_address(&IpAddr::V4(m)))
        }
    }
}

/// Fetch the certificate chain presented by `target` over a blocking TLS
/// handshake, plus a separate verification verdict.
///
/// The leaf and intermediates are captured **as presented**, even if the chain
/// is expired, self-signed, or otherwise untrusted, so the result can always be
/// linted and archived. Whether the chain is actually trusted is reported
/// separately in [`FetchedChain::verdict`].
///
/// `sni` overrides the SNI derived from a hostname target and is **required**
/// for an IP target. `timeout` bounds the combined TCP connect and TLS
/// handshake.
///
/// When `block_private_addresses` is `true`, the resolved address is checked
/// against an SSRF guard and private/loopback/link-local targets are rejected
/// with [`FetchError::BlockedAddress`].
///
/// # Errors
///
/// Returns a [`FetchError`] if the target is invalid, the SNI rules are not
/// satisfied, the address is blocked, DNS resolution fails, the TCP connection
/// fails or times out, or the TLS handshake fails. A *verification* failure does
/// **not** produce an error: it is surfaced as [`VerificationVerdict::Invalid`].
pub fn fetch_chain(
    target: &Target,
    sni: Option<&str>,
    timeout: Duration,
    block_private_addresses: bool,
) -> Result<FetchedChain, FetchError> {
    let server_name = resolve_sni(target, sni)?;
    let provider = crypto_provider()?;

    // Resolve and pick an address, applying the SSRF guard if requested.
    let addr = resolve_address(target, block_private_addresses)?;

    // Connect with the timeout applied to the TCP connect.
    let mut sock = TcpStream::connect_timeout(&addr, timeout).map_err(|e| {
        if e.kind() == std::io::ErrorKind::TimedOut {
            FetchError::Timeout
        } else {
            FetchError::Connect
        }
    })?;
    // The same timeout bounds read/write during the handshake below.
    sock.set_read_timeout(Some(timeout))
        .and_then(|()| sock.set_write_timeout(Some(timeout)))
        .map_err(|_| FetchError::Connect)?;

    // Build a client config whose ONLY verifier is the capture verifier.
    let capture = Arc::new(capture::CaptureVerifier::new(provider.clone()));
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|_| FetchError::Provider)?
        .dangerous()
        .with_custom_certificate_verifier(capture.clone())
        .with_no_client_auth();

    let mut conn = ClientConnection::new(Arc::new(config), server_name.clone())
        .map_err(|_| FetchError::Handshake)?;

    drive_handshake(&mut conn, &mut sock)?;

    // Capture the chain the verifier recorded during the handshake.
    let presented = capture.take_chain().ok_or(FetchError::EmptyChain)?;
    let (leaf, intermediates) = presented.split_first().ok_or(FetchError::EmptyChain)?;
    let leaf_der = leaf.to_vec();
    let intermediates_der: Vec<Vec<u8>> = intermediates.iter().map(|c| c.to_vec()).collect();

    // Separate, real verification pass — fail-closed: any problem => Invalid.
    let verdict = verify_chain(&provider, leaf, intermediates, &server_name);

    Ok(FetchedChain {
        leaf_der,
        intermediates_der,
        verdict,
    })
}

/// Resolve a target to a single socket address, honoring the SSRF guard.
fn resolve_address(
    target: &Target,
    block_private_addresses: bool,
) -> Result<SocketAddr, FetchError> {
    let host = target.host_string();
    let mut chosen: Option<SocketAddr> = None;
    let mut blocked_any = false;

    for addr in (host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|_| FetchError::Resolution)?
    {
        if block_private_addresses && is_blocked_address(&addr.ip()) {
            blocked_any = true;
            continue;
        }
        chosen = Some(addr);
        break;
    }

    match chosen {
        Some(addr) => Ok(addr),
        None if blocked_any => Err(FetchError::BlockedAddress),
        None => Err(FetchError::Resolution),
    }
}

/// Drive a blocking rustls handshake over `sock` to completion.
fn drive_handshake(conn: &mut ClientConnection, sock: &mut TcpStream) -> Result<(), FetchError> {
    while conn.is_handshaking() {
        if conn.wants_write() {
            conn.write_tls(sock).map_err(map_io)?;
            continue;
        }
        if conn.wants_read() {
            let n = conn.read_tls(sock).map_err(map_io)?;
            if n == 0 {
                // Peer closed before the handshake completed.
                return Err(FetchError::Handshake);
            }
            conn.process_new_packets()
                .map_err(|_| FetchError::Handshake)?;
            continue;
        }
        // Neither side wants I/O but we are still handshaking: nothing to do.
        break;
    }

    // Flush any final handshake data.
    if conn.wants_write() {
        conn.write_tls(sock).map_err(map_io)?;
        sock.flush().map_err(map_io)?;
    }
    Ok(())
}

/// Map a handshake I/O error to a [`FetchError`], distinguishing timeouts.
fn map_io(e: std::io::Error) -> FetchError {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => FetchError::Timeout,
        _ => FetchError::Handshake,
    }
}

/// Run the real verification pass against the Mozilla root store.
///
/// This is fail-closed: any error (builder, parse, or verification) yields
/// [`VerificationVerdict::Invalid`] — a problem is never silently treated as valid.
fn verify_chain(
    provider: &Arc<CryptoProvider>,
    leaf: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
) -> VerificationVerdict {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let verifier = match WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    {
        Ok(v) => v,
        Err(_) => {
            return VerificationVerdict::Invalid {
                reason: "could not build certificate verifier".to_string(),
            };
        }
    };

    let now = UnixTime::since_unix_epoch(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO),
    );

    match verifier.verify_server_cert(leaf, intermediates, server_name, &[], now) {
        Ok(_) => VerificationVerdict::Valid,
        Err(e) => VerificationVerdict::Invalid {
            reason: describe_verify_error(&e),
        },
    }
}

/// Map a rustls verification error to a short, generic reason string.
fn describe_verify_error(err: &rustls::Error) -> String {
    use rustls::CertificateError;
    use rustls::Error::InvalidCertificate;

    match err {
        InvalidCertificate(CertificateError::Expired) => "certificate has expired".to_string(),
        InvalidCertificate(CertificateError::NotValidYet) => {
            "certificate is not yet valid".to_string()
        }
        InvalidCertificate(CertificateError::UnknownIssuer) => {
            "issuer is not a trusted root".to_string()
        }
        InvalidCertificate(CertificateError::NotValidForName) => {
            "certificate is not valid for the requested name".to_string()
        }
        InvalidCertificate(CertificateError::BadEncoding) => {
            "certificate encoding is invalid".to_string()
        }
        InvalidCertificate(_) => "certificate is not trusted".to_string(),
        _ => "chain verification failed".to_string(),
    }
}

/// Obtain a `ring`-backed crypto provider.
///
/// Prefers the process default if one is installed (the CLI / tests may install
/// it once), otherwise falls back to a fresh `ring` provider so the crate works
/// standalone without any global setup.
fn crypto_provider() -> Result<Arc<CryptoProvider>, FetchError> {
    if let Some(p) = CryptoProvider::get_default() {
        return Ok(p.clone());
    }
    // SECURITY: this is the `ring` provider chosen for A03 supply-chain reasons
    // (no aws-lc-rs C/cmake build dependency). Installing it as the process
    // default is best-effort; if another caller won the race we fall back to
    // whatever is now installed (or, failing that, a fresh ring provider).
    let provider = rustls::crypto::ring::default_provider();
    match provider.install_default() {
        Ok(()) => CryptoProvider::get_default()
            .cloned()
            .ok_or(FetchError::Provider),
        // Another provider was already installed; prefer it for consistency,
        // otherwise use a fresh ring provider.
        Err(_) => Ok(CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))),
    }
}

mod capture {
    use std::sync::{Arc, Mutex};

    use rustls::DigitallySignedStruct;
    use rustls::SignatureScheme;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

    /// An accept-any server-certificate verifier that records the presented chain.
    ///
    /// SECURITY: this verifier intentionally performs **no trust evaluation** of
    /// the certificate chain — it accepts ANY chain so the handshake completes and
    /// the presented certificates can be captured for extraction. It exists ONLY
    /// to capture the chain and MUST NEVER be reused for any trust decision. It is
    /// kept private to this crate and is never exported. The real trust decision is
    /// made separately by `WebPkiServerVerifier` in `verify_chain`.
    ///
    /// It still verifies the handshake *signature* against the presented leaf key
    /// using the crypto provider, so the peer genuinely holds the corresponding
    /// private key — only the chain-of-trust check is skipped.
    #[derive(Debug)]
    pub(crate) struct CaptureVerifier {
        provider: Arc<CryptoProvider>,
        chain: Mutex<Option<Vec<CertificateDer<'static>>>>,
    }

    impl CaptureVerifier {
        pub(crate) fn new(provider: Arc<CryptoProvider>) -> Self {
            Self {
                provider,
                chain: Mutex::new(None),
            }
        }

        /// Take the captured chain (leaf first), if the handshake recorded one.
        pub(crate) fn take_chain(&self) -> Option<Vec<CertificateDer<'static>>> {
            self.chain.lock().ok().and_then(|mut g| g.take())
        }
    }

    impl ServerCertVerifier for CaptureVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            // SECURITY: capture only — record the chain and accept unconditionally.
            // Trust is evaluated elsewhere (verify_chain), never here.
            let mut captured = Vec::with_capacity(1 + intermediates.len());
            captured.push(end_entity.clone().into_owned());
            captured.extend(intermediates.iter().map(|c| c.clone().into_owned()));
            if let Ok(mut g) = self.chain.lock() {
                *g = Some(captured);
            }
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod target_parse {
        use super::*;

        #[test]
        fn defaults_port_to_443_for_bare_hostname() {
            let t = Target::parse("example.com").unwrap();
            assert_eq!(t.port(), DEFAULT_PORT);
            assert_eq!(t.host(), &HostKind::Hostname("example.com".to_string()));
        }

        #[test]
        fn parses_explicit_port() {
            let t = Target::parse("example.com:8443").unwrap();
            assert_eq!(t.port(), 8443);
            assert_eq!(t.host(), &HostKind::Hostname("example.com".to_string()));
        }

        #[test]
        fn classifies_ipv4_host_as_ip() {
            let t = Target::parse("192.0.2.10:443").unwrap();
            assert!(matches!(t.host(), HostKind::Ip(IpAddr::V4(_))));
            assert_eq!(t.port(), 443);
        }

        #[test]
        fn parses_bare_ipv6_literal_with_default_port() {
            let t = Target::parse("2001:db8::1").unwrap();
            assert!(matches!(t.host(), HostKind::Ip(IpAddr::V6(_))));
            assert_eq!(t.port(), DEFAULT_PORT);
        }

        #[test]
        fn parses_bracketed_ipv6_with_port() {
            let t = Target::parse("[2001:db8::1]:8443").unwrap();
            assert!(matches!(t.host(), HostKind::Ip(IpAddr::V6(_))));
            assert_eq!(t.port(), 8443);
        }

        #[test]
        fn parses_bracketed_ipv6_without_port() {
            let t = Target::parse("[::1]").unwrap();
            assert!(matches!(t.host(), HostKind::Ip(IpAddr::V6(_))));
            assert_eq!(t.port(), DEFAULT_PORT);
        }

        #[test]
        fn trims_surrounding_whitespace() {
            let t = Target::parse("  example.com  ").unwrap();
            assert_eq!(t.host(), &HostKind::Hostname("example.com".to_string()));
        }

        #[test]
        fn rejects_empty_target() {
            let err = Target::parse("").unwrap_err();
            assert!(matches!(err, FetchError::InvalidTarget(_)));
        }

        #[test]
        fn rejects_empty_host_with_port() {
            let err = Target::parse(":443").unwrap_err();
            assert!(matches!(err, FetchError::InvalidTarget(_)));
        }

        #[test]
        fn rejects_port_zero() {
            let err = Target::parse("example.com:0").unwrap_err();
            assert!(matches!(err, FetchError::InvalidPort));
        }

        #[test]
        fn rejects_port_above_u16_max() {
            let err = Target::parse("example.com:70000").unwrap_err();
            assert!(matches!(err, FetchError::InvalidPort));
        }

        #[test]
        fn rejects_non_numeric_port() {
            let err = Target::parse("example.com:https").unwrap_err();
            assert!(matches!(err, FetchError::InvalidTarget(_)));
        }

        #[test]
        fn rejects_unterminated_ipv6_bracket() {
            let err = Target::parse("[2001:db8::1").unwrap_err();
            assert!(matches!(err, FetchError::InvalidTarget(_)));
        }

        #[test]
        fn accepts_minimum_and_maximum_ports() {
            assert_eq!(Target::parse("example.com:1").unwrap().port(), 1);
            assert_eq!(Target::parse("example.com:65535").unwrap().port(), 65535);
        }
    }

    mod sni_rules {
        use super::*;

        #[test]
        fn derives_sni_from_hostname() {
            let t = Target::parse("example.com").unwrap();
            let name = resolve_sni(&t, None).unwrap();
            assert_eq!(name.to_str(), "example.com");
        }

        #[test]
        fn explicit_sni_overrides_hostname() {
            let t = Target::parse("example.com").unwrap();
            let name = resolve_sni(&t, Some("override.example")).unwrap();
            assert_eq!(name.to_str(), "override.example");
        }

        #[test]
        fn ip_target_requires_explicit_sni() {
            let t = Target::parse("192.0.2.10:443").unwrap();
            let err = resolve_sni(&t, None).unwrap_err();
            assert!(matches!(err, FetchError::SniRequiredForIp));
        }

        #[test]
        fn ip_target_accepts_explicit_sni() {
            let t = Target::parse("192.0.2.10:443").unwrap();
            let name = resolve_sni(&t, Some("example.com")).unwrap();
            assert_eq!(name.to_str(), "example.com");
        }

        #[test]
        fn rejects_invalid_sni() {
            let t = Target::parse("192.0.2.10:443").unwrap();
            let err = resolve_sni(&t, Some("not a dns name!")).unwrap_err();
            assert!(matches!(err, FetchError::InvalidSni));
        }
    }

    mod ssrf_guard {
        use super::*;
        use std::net::{Ipv4Addr, Ipv6Addr};

        #[test]
        fn blocks_loopback_v4() {
            assert!(is_blocked_address(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        }

        #[test]
        fn blocks_private_v4_ranges() {
            assert!(is_blocked_address(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
            assert!(is_blocked_address(&IpAddr::V4(Ipv4Addr::new(
                192, 168, 1, 1
            ))));
            assert!(is_blocked_address(&IpAddr::V4(Ipv4Addr::new(
                172, 16, 0, 1
            ))));
        }

        #[test]
        fn blocks_link_local_v4() {
            assert!(is_blocked_address(&IpAddr::V4(Ipv4Addr::new(
                169, 254, 1, 1
            ))));
        }

        #[test]
        fn blocks_cgnat_shared_space() {
            assert!(is_blocked_address(&IpAddr::V4(Ipv4Addr::new(
                100, 64, 0, 1
            ))));
        }

        #[test]
        fn allows_global_v4() {
            assert!(!is_blocked_address(&IpAddr::V4(Ipv4Addr::new(
                93, 184, 216, 34
            ))));
        }

        #[test]
        fn blocks_loopback_and_local_v6() {
            assert!(is_blocked_address(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
            assert!(is_blocked_address(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
            // Unique local fc00::/7.
            assert!(is_blocked_address(&"fd00::1".parse().unwrap()));
            // Link-local fe80::/10.
            assert!(is_blocked_address(&"fe80::1".parse().unwrap()));
        }

        #[test]
        fn blocks_ipv4_mapped_loopback() {
            assert!(is_blocked_address(&"::ffff:127.0.0.1".parse().unwrap()));
        }

        #[test]
        fn allows_global_v6() {
            assert!(!is_blocked_address(
                &"2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()
            ));
        }
    }

    mod error_messages {
        use super::*;

        #[test]
        fn messages_are_generic_and_nonempty() {
            // Spot-check that the Display impls are wired and leak no internals.
            assert_eq!(FetchError::Timeout.to_string(), "connection timed out");
            assert_eq!(
                FetchError::Connect.to_string(),
                "could not connect to target host"
            );
            assert_eq!(FetchError::Handshake.to_string(), "TLS handshake failed");
            assert_eq!(
                FetchError::SniRequiredForIp.to_string(),
                "an explicit SNI is required when connecting to an IP address"
            );
            assert_eq!(
                FetchError::BlockedAddress.to_string(),
                "target address is not permitted by the SSRF guard"
            );
        }
    }

    mod verdict {
        use super::*;

        #[test]
        fn invalid_carries_reason() {
            let v = VerificationVerdict::Invalid {
                reason: "issuer is not a trusted root".to_string(),
            };
            assert_ne!(v, VerificationVerdict::Valid);
        }
    }
}
