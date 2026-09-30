//! Certificate trust for tunnel nodes: the anti-MITM pin, and nothing else.

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

use sangfor_core::crypto;

/// How a node certificate is judged.
///
/// Built by the control plane from `ATrustAntiMitmData.certificateDigests`
/// (the `n` field of the session plan) and handed to the data plane, which
/// never learns how the digests were derived.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TrustPolicy {
    /// Salted SHA-256 identity digests, uppercase hex, as advertised by the
    /// gateway's anti-MITM data. Empty means the deployment published no
    /// pinning material.
    pub pins: Vec<String>,

    /// What to do when [`Self::pins`] is empty.
    ///
    /// `true` (the default) mirrors `SangforTlsChannel.swift` and the Dart
    /// client: aTrust nodes commonly present self-signed certificates with no
    /// pinning material, and refusing them would break those deployments
    /// outright. `false` fails closed, which is the right choice for a
    /// deployment that always advertises digests.
    ///
    /// This flag has no effect when pins are present: a pin list is always
    /// enforced.
    pub accept_unpinned: bool,
}

impl TrustPolicy {
    /// A policy that requires one of [pins] to match.
    #[must_use]
    pub fn pinned(pins: Vec<String>) -> Self {
        Self {
            pins,
            accept_unpinned: false,
        }
    }

    /// A policy with no pins that accepts whatever the node presents. Only
    /// useful for deployments that publish no anti-MITM material, and for
    /// tests.
    #[must_use]
    pub fn opportunistic() -> Self {
        Self {
            pins: Vec::new(),
            accept_unpinned: true,
        }
    }

    /// Judges a DER certificate the way [`PinVerifier`] does, without a
    /// handshake. Exposed so a host can explain a rejection in its own terms
    /// and so the rule can be unit-tested against the golden fixture.
    #[must_use]
    pub fn judge(&self, der: &[u8]) -> Verdict {
        if self.pins.is_empty() {
            return if self.accept_unpinned {
                Verdict::AcceptedUnpinned
            } else {
                Verdict::RejectedNoPins
            };
        }
        if crypto::certificate_matches(der, &self.pins) {
            Verdict::AcceptedPinned
        } else {
            Verdict::RejectedDigestMismatch {
                actual: crypto::certificate_digest(der),
            }
        }
    }
}

/// Why a certificate was accepted or refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The leaf digest matched one of the advertised pins.
    AcceptedPinned,
    /// No pins were advertised and the policy allows that.
    AcceptedUnpinned,
    /// No pins were advertised and the policy fails closed.
    RejectedNoPins,
    /// Pins were advertised and none matched; `actual` is the leaf's digest,
    /// safe to log (it is a hash, not certificate material).
    RejectedDigestMismatch {
        /// The digest the node presented.
        actual: String,
    },
}

impl Verdict {
    /// True when the certificate may be used.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::AcceptedPinned | Self::AcceptedUnpinned)
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AcceptedPinned => f.write_str("certificate matches an anti-MITM pin"),
            Self::AcceptedUnpinned => {
                f.write_str("no anti-MITM pins advertised; accepted by policy")
            }
            Self::RejectedNoPins => {
                f.write_str("no anti-MITM pins advertised and the policy fails closed")
            }
            Self::RejectedDigestMismatch { actual } => {
                write!(f, "certificate digest {actual} is not pinned")
            }
        }
    }
}

/// The `rustls` verifier that applies a [`TrustPolicy`].
///
/// Chain building is replaced by pinning, but **handshake signatures are still
/// verified** against the certificate's own public key. That distinction is the
/// whole security argument: pinning proves the peer holds the private key for
/// the pinned certificate, so an attacker cannot complete the handshake even
/// though no root CA was consulted. Skipping the signature check would reduce
/// pinning to a label on an unauthenticated connection.
#[derive(Debug)]
pub struct PinVerifier {
    policy: TrustPolicy,
    provider: Arc<CryptoProvider>,
}

impl PinVerifier {
    /// Wraps [policy]; [provider] supplies the signature algorithms.
    #[must_use]
    pub fn new(policy: TrustPolicy, provider: Arc<CryptoProvider>) -> Self {
        Self { policy, provider }
    }

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> &TrustPolicy {
        &self.policy
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Only the leaf is pinned. Intermediates are ignored on purpose: the
        // gateway advertises the identity of the certificate the node presents,
        // not of whatever issued it, and aTrust deployments commonly use
        // self-signed leaves with no chain at all.
        let verdict = self.policy.judge(end_entity.as_ref());
        if verdict.is_accepted() {
            return Ok(ServerCertVerified::assertion());
        }
        Err(Error::General(verdict.to_string()))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
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
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
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
