//! Errors surfaced by the core.
//!
//! Deliberately small and string-carrying: these cross an FFI boundary as a
//! message, and the callers that matter (a packet tunnel extension, a
//! `VpnService`) can only log them or tear the tunnel down.

use std::fmt;

/// Anything that can go wrong inside the data plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A frame, packet, or document did not parse.
    Malformed(&'static str),
    /// The gateway rejected the tunnel handshake; the session is dead and the
    /// control plane has to log in again.
    TunnelAuthFailed(String),
    /// A per-flow authentication was rejected.
    FlowAuthFailed(String),
    /// A flow never authenticated in time.
    FlowAuthTimeout(String),
    /// The gateway stopped answering heartbeats.
    HeartbeatTimeout(u32),
    /// The transport closed or failed.
    ChannelClosed(String),
    /// The session plan could not be used.
    InvalidPlan(String),
    /// The TCP tunnel refused a dial.
    TcpTunnelRefused(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(what) => write!(f, "malformed {what}"),
            Error::TunnelAuthFailed(detail) => {
                // Kept word-for-word compatible with the Dart client: the app
                // maps this message onto "your session was replaced".
                write!(f, "L3 tunnel auth failed: {detail}")
            }
            Error::FlowAuthFailed(detail) => write!(f, "flow auth failed: {detail}"),
            Error::FlowAuthTimeout(detail) => write!(f, "flow auth timed out: {detail}"),
            Error::HeartbeatTimeout(misses) => {
                write!(f, "heartbeat timed out after {misses} misses")
            }
            Error::ChannelClosed(detail) => write!(f, "tunnel channel closed: {detail}"),
            Error::InvalidPlan(detail) => write!(f, "invalid session plan: {detail}"),
            Error::TcpTunnelRefused(detail) => write!(f, "tcp tunnel refused: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// True when the session itself is unusable and the control plane must
    /// re-authenticate rather than reconnect.
    #[must_use]
    pub fn is_fatal_for_session(&self) -> bool {
        matches!(self, Error::TunnelAuthFailed(_))
    }
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
