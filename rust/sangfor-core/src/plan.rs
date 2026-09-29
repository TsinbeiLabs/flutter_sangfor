//! The session hand-off document.
//!
//! The control plane (Dart, in the app process) resolves everything the tunnel
//! needs — login, node choice, virtual IP, resource routes — and writes this
//! document where the data plane's process can read it: an App Group container
//! on iOS, a `VpnService` extra on Android, a file or an argument on the
//! desktops. The data plane cannot log in: it has no UI for secondary
//! challenges and no access to the credential store.
//!
//! The JSON keys are the contract with `ATrustSessionPlan` in Dart and Swift;
//! `tests/golden.rs` decodes the exact document the Dart implementation emits.

use std::collections::BTreeMap;

use crate::crypto::process_fingerprint;
use crate::error::{Error, Result};
use crate::l3::ProcessInfo;
use crate::route::{Route, RouteTable};

/// The schema version this build understands.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Everything the data plane needs to run a tunnel.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPlan {
    /// Bumped when a field is added that an older data plane could not ignore.
    pub schema_version: u32,
    /// Session id from login.
    pub sid: String,
    /// Device identity.
    pub device_id: String,
    /// Per-connection identity.
    pub connection_id: String,
    /// Account name.
    pub username: String,
    /// Base64 of the 32-byte request signing key.
    pub sign_key_base64: String,
    /// UI language tag.
    pub lang: String,
    /// Executable name reported to the gateway.
    pub process_name: String,
    /// Executable path; its SHA-256 is the fingerprint.
    pub process_path: String,
    /// Platform name as the gateway spells it.
    pub process_platform: String,
    /// Node endpoints per group, best candidate first (`host:port`).
    pub nodes: BTreeMap<String, Vec<String>>,
    /// The group the tunnel opens against.
    pub major_node_group: String,
    /// The published resource routes.
    pub routes: Vec<Route>,
    /// DNS servers the gateway advertised.
    pub dns_servers: Vec<String>,
    /// The assigned virtual IP, when the control plane already knows it.
    #[serde(default)]
    pub virtual_address: Option<String>,
    /// Anti-MITM pin digests (see [`crate::crypto::certificate_digest`]).
    #[serde(default)]
    pub certificate_digests: Vec<String>,
    /// Whether to accept a node certificate when no pins are available.
    #[serde(default = "default_accept_any_certificate")]
    pub accept_any_certificate: bool,
    /// Resolved IPv4 address to the host name the gateway published.
    #[serde(default)]
    pub dial_hosts: BTreeMap<String, String>,
    /// Heartbeat interval in seconds.
    #[serde(default = "default_heartbeat_seconds")]
    pub heartbeat_seconds: f64,
    /// Tunnel MTU.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

fn default_accept_any_certificate() -> bool {
    true
}

fn default_heartbeat_seconds() -> f64 {
    5.0
}

fn default_mtu() -> u16 {
    1400
}

impl SessionPlan {
    /// Decodes a document, rejecting a schema this build cannot honour.
    pub fn decode(document: &[u8]) -> Result<Self> {
        let plan: SessionPlan = serde_json::from_slice(document)
            .map_err(|_| Error::InvalidPlan("malformed JSON".into()))?;
        if plan.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(Error::InvalidPlan(format!(
                "schema {} is not supported",
                plan.schema_version
            )));
        }
        if plan.sign_key().is_none() {
            return Err(Error::InvalidPlan(
                "signKeyBase64 is not valid base64".into(),
            ));
        }
        Ok(plan)
    }

    /// The request signing key.
    #[must_use]
    pub fn sign_key(&self) -> Option<Vec<u8>> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(self.sign_key_base64.as_bytes())
            .ok()
    }

    /// The process identity reported with every signed request.
    #[must_use]
    pub fn process(&self) -> ProcessInfo {
        ProcessInfo {
            name: self.process_name.clone(),
            path: self.process_path.clone(),
            platform: self.process_platform.clone(),
        }
    }

    /// The process fingerprint the gateway binds the session to.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        process_fingerprint(&self.process_path)
    }

    /// The route table for this plan.
    #[must_use]
    pub fn route_table(&self) -> RouteTable {
        RouteTable::new(self.routes.clone())
    }

    /// The endpoint to dial for [node_group], falling back to the major group.
    #[must_use]
    pub fn node_endpoint(&self, node_group: &str) -> Option<(String, u16)> {
        let candidates = self
            .nodes
            .get(node_group)
            .or_else(|| self.nodes.get(&self.major_node_group))?;
        candidates
            .iter()
            .find_map(|candidate| parse_endpoint(candidate))
    }

    /// The host name to dial for a resolved address, when the resource was
    /// published as a domain.
    #[must_use]
    pub fn dial_host(&self, address: &str) -> Option<&str> {
        self.dial_hosts.get(address).map(String::as_str)
    }
}

/// Parses a `host:port` endpoint, defaulting to 441 like the reference client.
#[must_use]
pub fn parse_endpoint(text: &str) -> Option<(String, u16)> {
    if let Some(rest) = text.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        return match tail {
            "" => Some((host.to_string(), 441)),
            other => Some((host.to_string(), other.strip_prefix(':')?.parse().ok()?)),
        };
    }
    match text.rsplit_once(':') {
        Some((host, port)) => Some((host.to_string(), port.parse().ok()?)),
        None => Some((text.to_string(), 441)),
    }
}
