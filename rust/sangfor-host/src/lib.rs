//! The event loop that runs [`sangfor_core`] against real sockets and a real
//! packet device.
//!
//! [`sangfor_core::plane::DataPlane`] is a synchronous state machine: bytes go
//! in, [`PlaneEffect`]s come out, and it performs no I/O. This crate is the
//! other half — it owns the descriptor and the sockets, turns effects into
//! syscalls, and turns readiness into plane calls.
//!
//! # Shape
//!
//! Two threads, and the plane is touched by exactly one of them:
//!
//! - the **device reader** blocks in [`PacketDevice::read_packet`] and pushes
//!   packets over a bounded queue. It has to be its own thread because a wintun
//!   session cannot be polled by `mio`, and a TUN descriptor blocked in `read`
//!   would otherwise hold up socket readiness.
//! - the **host loop** owns the plane, every channel, and the write side of the
//!   device. It polls sockets with `mio`, drains the device queue, applies
//!   effects, and drives timers.
//!
//! Because the plane lives on one thread there is no mutex around it and no
//! lock ordering to reason about. Channel connects are the exception: a TLS
//! handshake takes long enough that doing it inline would stall every other
//! flow, so each one runs on a short-lived worker thread and reports back
//! through the same queue. Those threads never see the plane.
//!
//! # Backpressure
//!
//! Both queues are bounded and both shed rather than block. A device queue that
//! fills means the tunnel is behind the stack; blocking the reader would turn
//! that into an unbounded memory climb, which on iOS is an extension kill that
//! looks like a random VPN drop. Every shed packet is counted in
//! [`Statistics`].
//!
//! # Testing
//!
//! [`Connector`] is the seam. `tests/end_to_end.rs` runs the whole loop against
//! a [`sangfor_tun::LoopbackDevice`] and a fake gateway that replays the
//! recorded handshake from the golden fixture, so the data plane is exercised
//! end to end with no driver, no privileges, and no network.

#![forbid(unsafe_code)]

pub mod channel;
pub mod host;

pub use channel::{
    ByteChannel, Connector, OpenedChannel, PlainByteChannel, TlsByteChannel, TlsConnector,
};
pub use host::{
    wait_until, Host, HostConfig, HostEvent, HostHandle, HostObserver, RecordingObserver, Role,
    Statistics,
};
