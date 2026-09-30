//! Platform packet devices for [`sangfor_core`].
//!
//! A device is the seam between the operating system's network stack and the
//! protocol core: raw IP packets in, raw IP packets out. Every platform that
//! runs the core in its own tunnel process needs one, and they differ enough
//! that each is a separate feature:
//!
//! | Feature | Platform | What it wraps |
//! |---|---|---|
//! | `wintun` | Windows | the signed `wintun.dll` driver, loaded at runtime |
//! | `tun` | Linux | `/dev/net/tun` with `IFF_TUN \| IFF_NO_PI` |
//! | `fd` | Android, OHOS | a descriptor the platform service already opened |
//! | *(always)* | any | [`LoopbackDevice`], for tests and dry runs |
//!
//! iOS is deliberately absent. A packet tunnel extension keeps
//! `NEPacketTunnelFlow` and pumps bytes across the FFI boundary instead of
//! letting this crate own a utun: `setTunnelNetworkSettings` already provides
//! routes, DNS, `NEProxySettings`, and reasserting, and re-implementing that
//! would be a large amount of new unsafe code for no gain. See
//! `docs/rust-core.md` §4.
//!
//! # Safety
//!
//! Only [`wintun`], [`tun`], and [`fd`] contain `unsafe`, and each of those
//! modules is the smallest possible wrapper over a documented platform API. The
//! trait and the loopback device forbid `unsafe` outright.

pub mod device;

#[cfg(all(unix, any(feature = "tun", feature = "fd")))]
mod unix_io;

#[cfg(all(feature = "wintun", windows))]
pub mod wintun;

#[cfg(all(feature = "tun", target_os = "linux"))]
pub mod tun;

#[cfg(all(feature = "fd", unix))]
pub mod fd;

#[cfg(all(feature = "wintun", windows))]
pub use crate::wintun::WintunDevice;

#[cfg(all(feature = "tun", target_os = "linux"))]
pub use crate::tun::TunDevice;

#[cfg(all(feature = "fd", unix))]
pub use crate::fd::FdDevice;

pub use device::{LoopbackDevice, PacketDevice};
