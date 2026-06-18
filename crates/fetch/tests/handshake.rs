//! Hermetic handshake tests for the `fetch` crate.
//!
//! These stand up a real `rustls` TLS server on an ephemeral `127.0.0.1` port,
//! in-process, on a background thread, and drive [`fetch::fetch_chain`] against
//! it. No real network is touched: certs are minted at test time with `rcgen`
//! and the server lives and dies inside the test.
//!
//! The crate's value proposition is *capture regardless of trust*: the served
//! cert is self-signed and not in any root store, so the verification verdict is
//! [`fetch::VerificationVerdict::Invalid`], yet the chain must still be captured.
//! That separation — capture succeeds even when verification fails — is the core
//! property under test here.
//!
//! Conventions: SIFER, `.unwrap()` / `.unwrap_err()` per
//! `.claude/rules/rust-testing-core.md`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::{ServerConfig, ServerConnection};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use fetch::{Target, VerificationVerdict, fetch_chain};

/// A running in-process TLS server fixture bound to an ephemeral loopback port.
///
/// It accepts exactly one connection, completes the TLS handshake, presents the
/// configured chain, then closes. The background thread is joined on drop so the
/// fixture tears down deterministically at the end of the test.
struct TestServer {
    port: u16,
    /// The DER of the cert(s) the server is configured to present (leaf first).
    presented_der: Vec<Vec<u8>>,
    handle: Option<JoinHandle<()>>,
}

impl TestServer {
    /// Spawn a server that presents `cert_chain` (leaf first) with `key`.
    fn spawn(cert_chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Self {
        // Best-effort: install the ring provider so the server config builder has
        // a default. The fetch crate installs the same provider; install is
        // idempotent and races are harmless.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let presented_der = cert_chain.iter().map(|c| c.as_ref().to_vec()).collect();

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("server config must build from the in-test cert/key");
        let config = Arc::new(config);

        // Bind first (on the test thread) so the port is known before we return.
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("must bind an ephemeral port");
        let port = listener
            .local_addr()
            .expect("listener has a local addr")
            .port();

        // Signal readiness so the test never races the accept loop.
        let (ready_tx, ready_rx) = mpsc::channel::<()>();

        let handle = std::thread::spawn(move || {
            // We are ready to accept as soon as the thread is running.
            let _ = ready_tx.send(());
            if let Ok((stream, _peer)) = listener.accept() {
                serve_one(stream, config);
            }
        });

        // Wait until the accept thread is live (bounded so a bug can't hang CI).
        let _ = ready_rx.recv_timeout(Duration::from_secs(5));

        Self {
            port,
            presented_der,
            handle: Some(handle),
        }
    }

    /// The `host:port` target string for this server.
    fn target(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // The accept thread exits after serving one connection (or on bind/accept
        // error). If a test never connected, nudge it by making a throwaway
        // connection so `accept()` returns and the thread can finish.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Complete one server-side TLS handshake, then drain/close.
fn serve_one(mut stream: TcpStream, config: Arc<ServerConfig>) {
    let mut conn = match ServerConnection::new(config) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Drive the handshake to completion using the blocking stream adapter.
    let mut tls = rustls::Stream::new(&mut conn, &mut stream);
    // A read forces the handshake; the client sends no app data, so EOF/err is
    // expected and fine — the cert has already been presented during handshake.
    let mut buf = [0u8; 16];
    let _ = tls.read(&mut buf);
    let _ = tls.flush();
}

/// Mint a self-signed leaf for `localhost`, returning (DER, key).
fn self_signed_localhost() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let kp = KeyPair::generate().expect("keypair generation must succeed");
    let mut params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("params must build");
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    let cert = params.self_signed(&kp).expect("self-sign must succeed");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp.serialize_der()));
    (cert_der, key_der)
}

/// Mint a (leaf, intermediate-CA) pair where the leaf is signed by the CA.
/// Returns (leaf_der, ca_der, leaf_key) so the server can present leaf + CA.
fn leaf_signed_by_ca() -> (
    CertificateDer<'static>,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
) {
    let ca_kp = KeyPair::generate().expect("CA keypair must generate");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params must build");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "mini-x509 test intermediate CA");
    let ca = ca_params
        .clone()
        .self_signed(&ca_kp)
        .expect("CA self-sign must succeed");
    let issuer = Issuer::new(ca_params, ca_kp);

    let leaf_kp = KeyPair::generate().expect("leaf keypair must generate");
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params must build");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    let leaf = leaf_params
        .signed_by(&leaf_kp, &issuer)
        .expect("leaf signing must succeed");

    let leaf_der = CertificateDer::from(leaf.der().to_vec());
    let ca_der = CertificateDer::from(ca.der().to_vec());
    let leaf_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_kp.serialize_der()));
    (leaf_der, ca_der, leaf_key)
}

mod leaf_only {
    use super::*;

    #[test]
    fn captures_self_signed_leaf_der() {
        // Setup: a server presenting a single self-signed leaf.
        let (cert, key) = self_signed_localhost();
        let server = TestServer::spawn(vec![cert], key);
        let expected_leaf = server.presented_der[0].clone();
        let target = Target::parse(&server.target()).unwrap();

        // Invoke: SSRF guard disabled (loopback is the whole point of the test),
        // SNI supplied because the target is an IP literal.
        let chain = fetch_chain(&target, Some("localhost"), Duration::from_secs(5), false).unwrap();

        // Find + Expect: the captured leaf is byte-identical to what we served.
        assert_eq!(
            chain.leaf_der, expected_leaf,
            "captured leaf DER must match the served cert"
        );
        assert!(
            chain.intermediates_der.is_empty(),
            "a leaf-only server presents no intermediates"
        );
    }

    #[test]
    fn verdict_is_invalid_for_untrusted_self_signed() {
        // Setup: self-signed cert that chains to no trusted root.
        let (cert, key) = self_signed_localhost();
        let server = TestServer::spawn(vec![cert], key);
        let target = Target::parse(&server.target()).unwrap();

        // Invoke.
        let chain = fetch_chain(&target, Some("localhost"), Duration::from_secs(5), false).unwrap();

        // Expect: capture succeeded *and* the verdict is Invalid (fail-closed).
        assert!(
            !chain.leaf_der.is_empty(),
            "the chain is captured even when verification fails"
        );
        let reason = match chain.verdict {
            VerificationVerdict::Invalid { reason } => reason,
            VerificationVerdict::Valid => panic!("a self-signed leaf must not verify as valid"),
        };
        assert!(!reason.is_empty(), "the Invalid verdict carries a reason");
    }
}

mod with_intermediate {
    use super::*;

    #[test]
    fn captures_intermediate_when_server_presents_one() {
        // Setup: server presents leaf + its issuing (intermediate) CA.
        let (leaf, ca, leaf_key) = leaf_signed_by_ca();
        let server = TestServer::spawn(vec![leaf, ca], leaf_key);
        let expected_leaf = server.presented_der[0].clone();
        let expected_ca = server.presented_der[1].clone();
        let target = Target::parse(&server.target()).unwrap();

        // Invoke.
        let chain = fetch_chain(&target, Some("localhost"), Duration::from_secs(5), false).unwrap();

        // Expect: leaf + exactly one intermediate, both byte-identical, in order.
        assert_eq!(chain.leaf_der, expected_leaf, "leaf DER must match");
        assert_eq!(
            chain.intermediates_der.len(),
            1,
            "the single presented intermediate must be captured"
        );
        assert_eq!(
            chain.intermediates_der[0], expected_ca,
            "intermediate DER must match the served CA"
        );

        // Still untrusted (the CA is not a public root): verdict is Invalid.
        assert!(matches!(chain.verdict, VerificationVerdict::Invalid { .. }));
    }
}

mod sni {
    use super::*;

    #[test]
    fn explicit_sni_is_honored_for_ip_target() {
        // An IP/loopback target *requires* an explicit SNI; supplying it lets the
        // handshake (and capture) complete.
        let (cert, key) = self_signed_localhost();
        let server = TestServer::spawn(vec![cert], key);
        let target = Target::parse(&server.target()).unwrap();

        let chain = fetch_chain(&target, Some("localhost"), Duration::from_secs(5), false).unwrap();

        assert!(
            !chain.leaf_der.is_empty(),
            "supplying SNI for an IP target lets capture proceed"
        );
    }

    #[test]
    fn ip_target_without_sni_errors_before_connecting() {
        // No server needed: the SNI rule is enforced before any I/O. Point at an
        // address that is never contacted.
        let target = Target::parse("127.0.0.1:1").unwrap();
        let err = fetch_chain(&target, None, Duration::from_secs(5), false).unwrap_err();
        assert!(matches!(err, fetch::FetchError::SniRequiredForIp));
    }
}

mod connection_errors {
    use super::*;

    #[test]
    fn connection_refused_on_unused_port_is_generic_error() {
        // Bind then immediately drop a listener to obtain a port nothing listens
        // on, keeping the test fully local and fast (connect refuses at once).
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = Target::parse(&format!("127.0.0.1:{port}")).unwrap();
        let err =
            fetch_chain(&target, Some("localhost"), Duration::from_secs(2), false).unwrap_err();

        // A refused/timed-out connect surfaces a generic connect/timeout error —
        // never a panic, never an Ok.
        assert!(
            matches!(err, fetch::FetchError::Connect | fetch::FetchError::Timeout),
            "expected Connect/Timeout, got {err:?}"
        );
    }
}
