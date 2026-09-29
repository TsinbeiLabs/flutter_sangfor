//! The aTrust tunnel data plane: protocol framing, signing, packet codec,
//! conntrack, route matching, and userspace TCP termination.
//!
//! This crate performs **no I/O and has no platform dependencies**. Bytes go in
//! and bytes come out; transports, timers, and TUN devices live in
//! `sangfor-tun` and `sangfor-ffi`. That is what lets the same code run inside
//! an iOS packet tunnel extension, an Android `VpnService` process, an OHOS
//! extension ability, and a desktop daemon.
//!
//! Wire behaviour is pinned by
//! `packages/flutter_sangfor/test/fixtures/native_atrust.json`, which the Dart
//! reference implementation generates and `tests/golden.rs` consumes. The Swift
//! core is checked against the same file, so all three implementations agree by
//! construction rather than by re-deriving the protocol from a live gateway.

pub mod crypto;
pub mod error;
pub mod flow;
pub mod json;
pub mod l3;
pub mod packet;
pub mod plan;
pub mod plane;
pub mod route;
pub mod tcp_tunnel;
pub mod terminator;

pub use error::{Error, Result};

/// Protocol version byte shared by the L3 and TCP-tunnel framings.
pub const PROTOCOL_VERSION: u8 = 0x05;
