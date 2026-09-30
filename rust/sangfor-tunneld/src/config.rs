//! The host configuration document: what only the host knows.
//!
//! The session plan ([`sangfor_core::plan::SessionPlan`]) carries what the
//! protocol needs and is written by the Dart control plane. This document
//! carries what the *machine* needs — which device to open, what to name the
//! interface, which routes and DNS servers to install — and is written by
//! whoever launches the tunnel process.
//!
//! Keeping them apart is deliberate. Which destinations belong in the tunnel is
//! a product decision: the app derives it from the gateway's published
//! resources *and* from the user's own route policy and custom entries. None of
//! that belongs in a protocol library, and duplicating it here would mean two
//! implementations of a rule users can change in a settings screen.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Which packet device to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    /// Windows, on the signed wintun driver. Needs elevation.
    Wintun,
    /// Linux, creating `/dev/net/tun`. Needs `CAP_NET_ADMIN`.
    Tun,
    /// Android or OHOS, adopting a descriptor the platform service opened.
    Fd,
    /// An in-memory device. The tunnel runs and can be exercised, but nothing
    /// reaches the operating system's stack.
    Loopback,
}

impl Default for DeviceKind {
    /// The platform's own device, so a config that omits `device` still does
    /// the obvious thing.
    fn default() -> Self {
        if cfg!(windows) {
            Self::Wintun
        } else if cfg!(target_os = "linux") {
            Self::Tun
        } else {
            // Android and OHOS have no device to create: the descriptor arrives
            // from the service.
            Self::Fd
        }
    }
}

/// Everything the tunnel process needs beyond the session plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostConfig {
    /// The device to open.
    #[serde(default)]
    pub device: DeviceKind,

    /// Interface name: the wintun adapter name, or the tun device name.
    #[serde(default = "default_interface")]
    pub interface: String,

    /// The descriptor to adopt, for [`DeviceKind::Fd`].
    #[serde(default)]
    pub fd: Option<i32>,

    /// Path to `wintun.dll`, for [`DeviceKind::Wintun`]. Defaults to the
    /// normal Windows search order, which finds the copy staged beside the
    /// executable.
    #[serde(default)]
    pub wintun_dll: Option<PathBuf>,

    /// The address to assign. `None` uses the virtual IP the gateway assigns,
    /// which is what a normal session wants.
    #[serde(default)]
    pub address: Option<String>,

    /// The netmask for [Self::address]. A tunnel address is a point-to-point
    /// peer, so this defaults to a host mask.
    #[serde(default = "default_netmask")]
    pub netmask: String,

    /// A gateway to publish with the address. Normally `None`: the tunnel is
    /// not the default route, it carries the routes below.
    #[serde(default)]
    pub gateway: Option<String>,

    /// CIDR blocks to route through the tunnel, as the app computed them.
    #[serde(default)]
    pub routes: Vec<String>,

    /// DNS servers to set on the interface.
    #[serde(default)]
    pub dns_servers: Vec<String>,

    /// Interface MTU. Informational on Windows and Linux, where the device
    /// decides; the value that matters is the one in the session plan, which
    /// the terminator segments to.
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// Accept a node certificate when the session plan carries no anti-MITM
    /// digests. Defaults to true, matching the Swift and Dart planes; set false
    /// to fail closed on a deployment that always publishes digests.
    #[serde(default = "default_accept_unpinned")]
    pub accept_unpinned_certificate: bool,

    /// Seconds to wait for a TLS connect and handshake.
    #[serde(default = "default_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,

    /// A loopback port to serve the control protocol on, in addition to stdin.
    ///
    /// A service has no stdin, so this is how an app drives one. `None` leaves
    /// the socket closed and stdin as the only channel; `0` picks a free port,
    /// which the process then reports in its log.
    #[serde(default)]
    pub control_port: Option<u16>,

    /// The shared secret a control client must present for `status` and `stop`.
    ///
    /// `ping` never needs it, so a service manager can probe liveness first.
    /// Leaving this unset makes the control channel open to any local process,
    /// which the process warns about at startup. See [`crate::transport`] for
    /// what that does and does not expose.
    #[serde(default)]
    pub control_token: Option<String>,

    /// Where to write JSON status lines. `None` logs to stderr.
    #[serde(default)]
    pub log_path: Option<PathBuf>,
}

fn default_interface() -> String {
    "sangfor0".to_string()
}

fn default_netmask() -> String {
    "255.255.255.255".to_string()
}

fn default_mtu() -> u16 {
    1400
}

fn default_accept_unpinned() -> bool {
    true
}

fn default_connect_timeout_seconds() -> u64 {
    15
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            device: DeviceKind::default(),
            interface: default_interface(),
            fd: None,
            wintun_dll: None,
            address: None,
            netmask: default_netmask(),
            gateway: None,
            routes: Vec::new(),
            dns_servers: Vec::new(),
            mtu: default_mtu(),
            accept_unpinned_certificate: default_accept_unpinned(),
            connect_timeout_seconds: default_connect_timeout_seconds(),
            control_port: None,
            control_token: None,
            log_path: None,
        }
    }
}

impl HostConfig {
    /// Decodes a document.
    ///
    /// # Errors
    ///
    /// Returns the parse error, or the first validation failure from
    /// [`Self::validate`].
    pub fn decode(document: &[u8]) -> Result<Self, ConfigError> {
        let config: Self = serde_json::from_slice(document).map_err(|error| {
            ConfigError::Malformed(format!("the host configuration is not valid JSON: {error}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Checks the fields that a serializer cannot.
    ///
    /// # Errors
    ///
    /// Returns the first problem found. Failing here rather than at `netsh`
    /// matters: a bad route rejected by the operating system leaves the
    /// interface half-configured, and the error says nothing about which entry
    /// caused it.
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self.device {
            DeviceKind::Fd => {
                if self.fd.is_none() {
                    return Err(ConfigError::Malformed(
                        "device \"fd\" needs an \"fd\" to adopt".to_string(),
                    ));
                }
            }
            DeviceKind::Wintun | DeviceKind::Tun | DeviceKind::Loopback => {
                if self.interface.trim().is_empty() {
                    return Err(ConfigError::Malformed(
                        "the interface name is empty".to_string(),
                    ));
                }
            }
        }
        if self.interface.len() > 15 && matches!(self.device, DeviceKind::Tun) {
            return Err(ConfigError::Malformed(format!(
                "interface name {:?} exceeds the 15 byte kernel limit",
                self.interface
            )));
        }
        if self.connect_timeout_seconds == 0 {
            return Err(ConfigError::Malformed(
                "connectTimeoutSeconds must be at least 1".to_string(),
            ));
        }
        for route in &self.routes {
            parse_cidr(route).ok_or_else(|| {
                ConfigError::Malformed(format!("{route:?} is not an IPv4 CIDR block"))
            })?;
        }
        for server in &self.dns_servers {
            if sangfor_core::packet::parse_ipv4(server).is_none() {
                return Err(ConfigError::Malformed(format!(
                    "{server:?} is not an IPv4 address"
                )));
            }
        }
        if let Some(address) = &self.address {
            if sangfor_core::packet::parse_ipv4(address).is_none() {
                return Err(ConfigError::Malformed(format!(
                    "{address:?} is not an IPv4 address"
                )));
            }
        }
        Ok(())
    }
}

/// Why a host configuration was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The document could not be read or parsed, or a field is unusable.
    Malformed(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parses `a.b.c.d/n` into a network address and prefix, masking off any host
/// bits so `10.1.2.3/16` and `10.1.0.0/16` mean the same block.
#[must_use]
pub fn parse_cidr(text: &str) -> Option<(u32, u8)> {
    let (address, prefix) = text.split_once('/')?;
    let network = sangfor_core::packet::parse_ipv4(address)?;
    let prefix: u8 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    Some((network & prefix_mask(prefix), prefix))
}

/// The mask with the top [prefix] bits set.
#[must_use]
pub fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_document_produces_working_defaults() {
        let config = HostConfig::decode(b"{}").expect("decodes");
        assert_eq!(config.interface, "sangfor0");
        assert_eq!(config.netmask, "255.255.255.255");
        assert_eq!(config.mtu, 1400);
        assert!(config.accept_unpinned_certificate);
        assert_eq!(config.connect_timeout_seconds, 15);
        assert!(config.address.is_none(), "the gateway assigns it");
        assert_eq!(
            config.device,
            if cfg!(windows) {
                DeviceKind::Wintun
            } else if cfg!(target_os = "linux") {
                DeviceKind::Tun
            } else {
                DeviceKind::Fd
            }
        );
    }

    #[test]
    fn the_document_uses_camel_case_like_the_session_plan() {
        let config = HostConfig::decode(
            br#"{"device":"loopback","interface":"Luotopia","dnsServers":["10.0.0.53"],
                 "routes":["10.1.0.0/16"],"acceptUnpinnedCertificate":false,
                 "connectTimeoutSeconds":30}"#,
        )
        .expect("decodes");
        assert_eq!(config.device, DeviceKind::Loopback);
        assert_eq!(config.interface, "Luotopia");
        assert_eq!(config.dns_servers, vec!["10.0.0.53".to_string()]);
        assert_eq!(config.routes, vec!["10.1.0.0/16".to_string()]);
        assert!(!config.accept_unpinned_certificate);
        assert_eq!(config.connect_timeout_seconds, 30);
    }

    #[test]
    fn an_unknown_field_is_rejected_rather_than_ignored() {
        // A typo in a route list would otherwise silently drop a destination
        // from the tunnel, which presents as "the VPN doesn't work for this
        // site" with nothing in the log.
        let error =
            HostConfig::decode(br#"{"routs":["10.0.0.0/8"]}"#).expect_err("misspelled field");
        assert!(
            error.to_string().contains("unknown field"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn an_fd_device_needs_an_fd() {
        let error = HostConfig::decode(br#"{"device":"fd"}"#).expect_err("no descriptor to adopt");
        assert!(error.to_string().contains("needs an \"fd\""), "{error}");
        assert!(HostConfig::decode(br#"{"device":"fd","fd":7}"#).is_ok());
    }

    #[test]
    fn a_route_that_is_not_a_cidr_block_is_rejected() {
        for bad in [
            r#"{"routes":["10.0.0.0"]}"#,
            r#"{"routes":["10.0.0.0/33"]}"#,
            r#"{"routes":["vpn.example.test"]}"#,
            r#"{"routes":["10.0.0.0/16/8"]}"#,
        ] {
            let error = HostConfig::decode(bad.as_bytes()).expect_err("not a CIDR block");
            assert!(
                error.to_string().contains("not an IPv4 CIDR block"),
                "{bad} should be rejected: {error}"
            );
        }
    }

    #[test]
    fn a_zero_connect_timeout_is_rejected() {
        let error = HostConfig::decode(br#"{"connectTimeoutSeconds":0}"#).expect_err("zero");
        assert!(error.to_string().contains("at least 1"), "{error}");
    }

    #[test]
    fn a_tun_interface_name_is_length_checked() {
        // The kernel's IFNAMSIZ is 16 including the NUL, so 15 is the limit.
        let long = "x".repeat(16);
        let document = format!(r#"{{"device":"tun","interface":"{long}"}}"#);
        let error = HostConfig::decode(document.as_bytes()).expect_err("too long");
        assert!(error.to_string().contains("15 byte"), "{error}");
        // The same name is fine for wintun, which has no such limit.
        let document = format!(r#"{{"device":"wintun","interface":"{long}"}}"#);
        assert!(HostConfig::decode(document.as_bytes()).is_ok());
    }

    #[test]
    fn a_cidr_masks_off_its_host_bits() {
        assert_eq!(parse_cidr("10.1.2.3/16"), Some((0x0a01_0000, 16)));
        assert_eq!(parse_cidr("10.1.0.0/16"), Some((0x0a01_0000, 16)));
        assert_eq!(parse_cidr("0.0.0.0/0"), Some((0, 0)));
        assert_eq!(parse_cidr("255.255.255.255/32"), Some((u32::MAX, 32)));
        assert_eq!(parse_cidr("10.0.0.0/33"), None);
        assert_eq!(parse_cidr("10.0.0.0"), None);
    }

    #[test]
    fn the_prefix_mask_handles_the_zero_and_full_cases() {
        assert_eq!(prefix_mask(0), 0);
        assert_eq!(prefix_mask(1), 0x8000_0000);
        assert_eq!(prefix_mask(8), 0xff00_0000);
        assert_eq!(prefix_mask(32), u32::MAX);
    }

    #[test]
    fn the_control_channel_is_off_unless_asked_for() {
        let config = HostConfig::decode(b"{}").expect("decodes");
        assert!(config.control_port.is_none());
        assert!(config.control_token.is_none());

        let config =
            HostConfig::decode(br#"{"controlPort":0,"controlToken":"s3cret"}"#).expect("decodes");
        assert_eq!(config.control_port, Some(0), "0 means pick a free port");
        assert_eq!(config.control_token.as_deref(), Some("s3cret"));
    }
}
