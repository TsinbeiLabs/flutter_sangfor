//! The tunnel process: [`sangfor_host`] plus a platform packet device, running
//! outside the UI process so the tunnel outlives the app.
//!
//! This is the binary that makes `docs/rust-core.md` §6 real for the desktops
//! and for Android/OHOS. On those platforms the data plane currently lives in
//! the Flutter process, so a swipe-away, an OEM memory reclaim, or a normal app
//! exit drops every connection. Here it lives in its own process, which the
//! platform keeps alive on its own terms.
//!
//! # Two documents, not one
//!
//! The **session plan** ([`sangfor_core::plan::SessionPlan`]) is written by the
//! Dart control plane and carries what the protocol needs: credentials, signing
//! key, node endpoints, published resources, anti-MITM pins. The **host
//! configuration** ([`config::HostConfig`]) is written by whatever launches this
//! process and carries what only the host knows: which device to open, what to
//! call the interface, which routes and DNS servers to install.
//!
//! Keeping them apart matters because which destinations belong in the tunnel is
//! a product decision — the app derives it from the gateway's published
//! resources *and* from the user's route policy and custom entries. Duplicating
//! that here would mean a second implementation of a rule users can change in a
//! settings screen, and the two would drift.
//!
//! # Safety
//!
//! [`netconfig`] excludes the gateway's own node endpoints from every route
//! before applying it. A route that captures a node sends the tunnel's traffic
//! into the tunnel; the result is a deadlock that presents as a network outage.
//! The control plane already excludes them, so this is defence in depth at the
//! last place the mistake can still be caught.

//! The one `unsafe` call in this crate is adopting a descriptor the platform
//! service handed over, in [`device::open`]; it is denied everywhere else.
#![deny(unsafe_code)]

pub mod cli;
pub mod config;
pub mod control;
pub mod device;
pub mod netconfig;
pub mod runtime;
pub mod transport;

pub use config::{DeviceKind, HostConfig};
pub use netconfig::InterfaceConfig;
pub use runtime::{Exit, RunError};
