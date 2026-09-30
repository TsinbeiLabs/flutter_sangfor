//! TLS transport for the tunnel, on `rustls` with the pure-Rust RustCrypto
//! provider.
//!
//! The provider choice is load-bearing rather than aesthetic: `ring` and
//! `aws-lc-rs` both need a C toolchain for every target, and this stack has to
//! cross-compile to `aarch64-unknown-linux-ohos` with nothing but the NDK
//! linker. Keeping crypto in pure Rust is what lets the OHOS and Android builds
//! stay a plain `cargo build`, the same reason [`sangfor_core::crypto`] uses
//! RustCrypto for SHA-256/HMAC.
//!
//! # Verification model
//!
//! aTrust nodes present certificates the platform trust store rejects, so this
//! crate does **not** chain to root CAs. It pins: the leaf certificate's
//! identity digest — `upper_hex(sha256(base64(der) + salt))`, computed by
//! [`sangfor_core::crypto::certificate_digest`] — must be one of the digests the
//! control plane collected during login. That is the same rule
//! `SangforTlsChannel.swift` and the Dart client apply, so all three agree on
//! what a trusted node looks like.
//!
//! Deployments that advertise no anti-MITM material leave the pin list empty.
//! [`TrustPolicy::accept_unpinned`] decides what happens then, defaulting to
//! `true` to match the existing out-of-process data plane. Hosts that would
//! rather fail closed set it to `false`; see the field's docs for the
//! trade-off.
//!
//! # Not supported
//!
//! GM/T (SM2/SM4) cipher suites. The gateway may advertise an SM2 encryption
//! certificate as *pin material*, and that digest is honoured, but an actual
//! SM2 handshake is not possible here — and is not possible in the Dart or
//! Swift data planes either, so this is not a regression.

pub mod channel;
pub mod trust;

#[cfg(test)]
mod tests;

use std::sync::{Arc, OnceLock};

use rustls::crypto::CryptoProvider;
use rustls::ClientConfig;

pub use channel::{handshake, Handshake, TlsChannel};
pub use trust::{PinVerifier, TrustPolicy, Verdict};

/// The process-wide RustCrypto provider.
///
/// Built once: constructing it allocates the cipher-suite and key-exchange
/// tables, and a tunnel process wants exactly one copy.
#[must_use]
pub fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    Arc::clone(PROVIDER.get_or_init(|| Arc::new(rustls_rustcrypto::provider())))
}

/// A client configuration that pins with [policy] and offers no client
/// certificate, matching what the Dart and Swift channels negotiate.
///
/// Returned as an `Arc` because that is what `rustls::ClientConnection::new`
/// takes, and a host that dials many nodes from one policy shares one config.
///
/// No ALPN is offered: the gateway's tunnel endpoint is a raw TLS byte stream,
/// and advertising `h2` or `http/1.1` invites a server that switches protocols.
#[must_use]
pub fn client_config(policy: &TrustPolicy) -> Arc<ClientConfig> {
    let provider = provider();
    Arc::new(
        ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("rustls accepts its own default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(trust::PinVerifier::new(
                policy.clone(),
                provider,
            )))
            .with_no_client_auth(),
    )
}
