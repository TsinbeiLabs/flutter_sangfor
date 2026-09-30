//! Loopback handshake tests: a real `rustls` server on 127.0.0.1, a real
//! client, and the pin policy in between.
//!
//! The certificate is a throwaway self-signed ECDSA leaf generated for this
//! suite. It is trusted by nothing, pins nothing outside this file, and its
//! private key protects no system; embedding it keeps the tests free of `rcgen`
//! and of any C toolchain while still exercising a real handshake with real
//! signature verification.
//!
//! The server speaks a tiny length-prefixed echo (4-byte big-endian length,
//! then that many bytes, reflected back). Draining before responding is
//! deliberate: a concurrent echo would need the client to read and write at the
//! same time, and a `rustls` connection cannot be split across threads.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use sangfor_core::crypto;

use crate::channel::TlsChannel;
use crate::provider;
use crate::trust::TrustPolicy;

const CERTIFICATE_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIBZDCCAQugAwIBAgIUFVAQezXKcGdWdG3sBlqpEGsrnzQwCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2VydDAgFw03NTAxMDEwMDAw
MDBaGA80MDk2MDEwMTAwMDAwMFowITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWdu
ZWQgY2VydDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBvpQYxlrLls8M9D5lrm
nMMUNGazcDKetJX2Ic1KxTIC2hFaJUJQXJgwv49lwIM89TIVUHYMnG5GZB5T+evO
N7OjHzAdMBsGA1UdEQQUMBKCEGFUcnVzdCB0ZXN0IG5vZGUwCgYIKoZIzj0EAwID
RwAwRAIgaD7evDoUKOZ+czmH5x3ebO6UdjIkJ1X5RJ+SgZNkeg0CIFpP0Ugw+vfx
cPEjay48xxZd+kQfdbdCrT+MMT3zAd1z
-----END CERTIFICATE-----
";

const PRIVATE_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgngZaAVPjCG1x9M5h
igUdP9JTJdbgbBsr0riESjVnyzqhRANCAAQb6UGMZay5bPDPQ+Za5pzDFDRms3Ay
nrSV9iHNSsUyAtoRWiVCUFyYML+PZcCDPPUyFVB2DJxuRmQeU/nrzjez
-----END PRIVATE KEY-----
";

fn certificate_der() -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(CERTIFICATE_PEM.as_bytes()).expect("valid test certificate")
}

fn pin() -> String {
    crypto::certificate_digest(certificate_der().as_ref())
}

fn server_config() -> ServerConfig {
    let key = PrivateKeyDer::from_pem_slice(PRIVATE_KEY_PEM.as_bytes()).expect("valid test key");
    ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("rustls accepts its own defaults")
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der()], key)
        .expect("the test certificate matches the test key")
}

/// One connection, one echo, then the thread ends. Both sides time out rather
/// than hanging the suite if a handshake stalls.
struct Server {
    port: u16,
    worker: JoinHandle<String>,
}

impl Server {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = listener.local_addr().expect("a local address").port();
        let worker = thread::spawn(move || {
            let (socket, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) => return format!("accept failed: {error}"),
            };
            match serve(socket) {
                Ok(summary) => summary,
                Err(error) => format!("server error: {error}"),
            }
        });
        Self { port, worker }
    }

    /// Ends the connection and reports what the server saw.
    fn finish(self) -> String {
        self.worker
            .join()
            .unwrap_or_else(|_| "the server thread panicked".to_string())
    }
}

fn serve(socket: TcpStream) -> Result<String, String> {
    socket
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|error| error.to_string())?;
    let connection =
        ServerConnection::new(Arc::new(server_config())).map_err(|error| error.to_string())?;
    let mut stream = StreamOwned::new(connection, socket);

    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|error| error.to_string())?;
    let length = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&payload)
        .map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;
    Ok(format!("echoed {length} bytes"))
}

fn connect(port: u16, policy: &TrustPolicy) -> std::io::Result<TlsChannel> {
    TlsChannel::connect("127.0.0.1", port, policy, Duration::from_secs(20))
}

/// Sends [payload] and checks it comes back byte for byte.
fn round_trip(channel: &mut TlsChannel, payload: &[u8]) {
    let mut header = [0_u8; 4];
    header.copy_from_slice(&(payload.len() as u32).to_be_bytes());
    channel.write_all(&header).expect("write the length prefix");
    channel.write_all(payload).expect("write the payload");
    channel.flush().expect("flush");
    let mut echoed = vec![0_u8; payload.len()];
    channel.read_exact(&mut echoed).expect("read the echo");
    assert_eq!(echoed, payload, "the echo does not match");
}

#[test]
fn a_pinned_leaf_completes_the_handshake() {
    let server = Server::start();
    let mut channel = connect(server.port, &TrustPolicy::pinned(vec![pin()]))
        .expect("the pin matches, so the handshake completes");
    assert_eq!(
        channel.peer_certificate_digest(),
        Some(pin().as_str()),
        "the channel should report the digest it verified"
    );
    round_trip(&mut channel, b"hello node");
    drop(channel);
    assert_eq!(server.finish(), "echoed 10 bytes");
}

#[test]
fn a_leaf_that_is_not_pinned_is_refused() {
    let server = Server::start();
    let error = connect(server.port, &TrustPolicy::pinned(vec!["0".repeat(64)]))
        .expect_err("an unpinned leaf must be refused");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    let message = error.to_string();
    assert!(
        message.contains("is not pinned"),
        "the refusal should say so: {message}"
    );
    assert!(
        message.contains(&pin()),
        "the refusal should carry the observed digest {}: {message}",
        pin()
    );
    assert!(
        message.contains("127.0.0.1"),
        "the refusal should name the peer: {message}"
    );
    let _ = server.finish();
}

#[test]
fn pins_are_case_insensitive() {
    let server = Server::start();
    let lowercase = pin().to_ascii_lowercase();
    let mut channel = connect(server.port, &TrustPolicy::pinned(vec![lowercase]))
        .expect("the gateway may publish digests in either case");
    round_trip(&mut channel, b"case");
    drop(channel);
    assert_eq!(server.finish(), "echoed 4 bytes");
}

#[test]
fn no_pins_are_accepted_when_the_policy_allows_it() {
    let server = Server::start();
    let mut channel = connect(server.port, &TrustPolicy::opportunistic())
        .expect("the Swift and Dart planes accept a node with no pin material");
    round_trip(&mut channel, b"x");
    drop(channel);
    assert_eq!(server.finish(), "echoed 1 bytes");
}

#[test]
fn no_pins_are_refused_when_the_policy_fails_closed() {
    let server = Server::start();
    let error = connect(server.port, &TrustPolicy::default())
        .expect_err("an empty pin list with accept_unpinned = false must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        error.to_string().contains("fails closed"),
        "unexpected refusal message: {error}"
    );
    let _ = server.finish();
}

#[test]
fn a_payload_larger_than_one_record_survives() {
    let server = Server::start();
    let mut channel =
        connect(server.port, &TrustPolicy::pinned(vec![pin()])).expect("the pin matches");
    // Well past the 16 KB record limit, so both directions fragment.
    let payload: Vec<u8> = (0..200_000_u32).map(|index| (index % 251) as u8).collect();
    round_trip(&mut channel, &payload);
    drop(channel);
    assert_eq!(server.finish(), "echoed 200000 bytes");
}

#[test]
fn the_leaf_digest_is_the_pinned_value_not_a_chain_hash() {
    // Guards the rule the Swift plane encodes: the digest is over the leaf DER
    // exactly as presented, base64-encoded then salted. Recomputing it here
    // from the same PEM the server loads means a change to either side fails.
    let der = certificate_der();
    let expected = crypto::hex_upper(&crypto::sha256_str(&format!(
        "{}{}",
        base64_of(der.as_ref()),
        crypto::CERTIFICATE_DIGEST_SALT
    )));
    assert_eq!(crypto::certificate_digest(der.as_ref()), expected);
}

fn base64_of(der: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(der)
}
