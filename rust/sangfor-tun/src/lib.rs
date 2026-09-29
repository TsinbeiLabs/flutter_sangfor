//! Platform packet devices for [`sangfor_core`].
//!
//! Each device is feature-gated so the protocol core stays buildable on every
//! host: `wintun` (Windows), `tun` (Linux `/dev/net/tun`), and `fd` (a
//! descriptor handed over by an Android `VpnService` or an OHOS
//! `VpnExtensionAbility`).
//!
//! iOS is deliberately absent: a packet tunnel extension keeps
//! `NEPacketTunnelFlow` and pumps bytes across the FFI boundary instead of
//! letting this crate own a utun.

#![forbid(unsafe_code)]
