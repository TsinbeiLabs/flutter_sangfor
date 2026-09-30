//! Turning a configuration and a session plan into interface state.
//!
//! The safety-critical part is [`exclude_hosts`]: a route that captures one of
//! the gateway's own node endpoints sends the tunnel's traffic into the tunnel,
//! and the result is a deadlock that looks like a network outage. The control
//! plane already excludes them, so this is defence in depth — but this is the
//! process that actually calls `netsh`, so it is the last place the mistake can
//! be caught.

use std::io;

use sangfor_core::packet::{ipv4_text, parse_ipv4};
use sangfor_core::plan::{parse_endpoint, SessionPlan};

use crate::config::{parse_cidr, prefix_mask, HostConfig};

/// The resolved interface state, ready to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceConfig {
    /// The address to assign.
    pub address: String,
    /// Its netmask.
    pub netmask: String,
    /// A gateway to publish, if any.
    pub gateway: Option<String>,
    /// The CIDR blocks to route through the interface, already deduplicated and
    /// with the node endpoints excluded.
    pub routes: Vec<String>,
    /// DNS servers to set.
    pub dns_servers: Vec<String>,
    /// Blocks dropped because they would have captured a node endpoint.
    pub excluded: Vec<String>,
}

impl InterfaceConfig {
    /// Resolves [config] against [plan], using [virtual_ip] as the address when
    /// the config does not name one.
    ///
    /// [virtual_ip] is the address the gateway assigned, which is the one the
    /// tunnel must actually use: packets the plane emits carry it as their
    /// source, and an interface configured with a different address makes the
    /// stack drop them as martians.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::NoAddress`] when neither the config nor the
    /// gateway supplied one.
    pub fn resolve(
        config: &HostConfig,
        plan: &SessionPlan,
        virtual_ip: Option<&str>,
    ) -> Result<Self, NoAddress> {
        let address = match (&config.address, virtual_ip) {
            (Some(address), _) => address.clone(),
            (None, Some(address)) => address.to_string(),
            (None, None) => return Err(NoAddress),
        };
        let nodes = node_addresses(plan);
        let blocks = config
            .routes
            .iter()
            .filter_map(|route| parse_cidr(route))
            .collect::<Vec<_>>();
        let (kept, dropped) = partition_excluded(&blocks, &nodes);
        Ok(Self {
            address,
            netmask: config.netmask.clone(),
            gateway: config.gateway.clone(),
            routes: kept
                .iter()
                .map(|(network, prefix)| format!("{}/{}", ipv4_text(*network), prefix))
                .collect(),
            dns_servers: config.dns_servers.clone(),
            excluded: dropped
                .iter()
                .map(|(network, prefix)| format!("{}/{}", ipv4_text(*network), prefix))
                .collect(),
        })
    }
}

/// Neither the host configuration nor the gateway supplied an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoAddress;

impl std::fmt::Display for NoAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no address to assign: the host configuration has none and the gateway has not assigned a virtual IP")
    }
}

impl std::error::Error for NoAddress {}

/// Every node endpoint in [plan], as a host-order IPv4 address.
///
/// Both the WAN and LAN candidates count: the tunnel must not capture whichever
/// one the control plane picked, and it cannot know which that will be after a
/// handover.
#[must_use]
pub fn node_addresses(plan: &SessionPlan) -> Vec<u32> {
    let mut addresses = Vec::new();
    for candidates in plan.nodes.values() {
        for candidate in candidates {
            let Some((host, _)) = parse_endpoint(candidate) else {
                continue;
            };
            if let Some(address) = parse_ipv4(&host) {
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
        }
    }
    addresses.sort_unstable();
    addresses
}

/// A set of CIDR blocks as network address and prefix length.
pub type Blocks = Vec<(u32, u8)>;

/// Splits [blocks] into those that avoid every address in [hosts] and those
/// that were cut down to avoid one.
///
/// A block that does not contain a host is kept whole. One that does is split
/// into the minimal set of sub-blocks covering everything except that single
/// address, which is what lets `10.0.0.0/8` coexist with a node at
/// `10.1.2.3`: the route survives as eight narrower blocks with one hole in it.
pub fn partition_excluded(blocks: &Blocks, hosts: &[u32]) -> (Blocks, Blocks) {
    let mut kept: Blocks = Vec::new();
    let mut dropped: Blocks = Vec::new();
    for block in blocks {
        // Mask off any host bits, so `10.1.2.3/16` and `10.1.0.0/16` are the
        // same block. `parse_cidr` already does this; doing it again here keeps
        // the function correct for callers that built the tuple by hand.
        let block = (block.0 & prefix_mask(block.1), block.1);
        let mut current = vec![block];
        let mut cut = false;
        for host in hosts {
            let mut next = Vec::with_capacity(current.len() * 2);
            for (network, prefix) in current {
                if network & prefix_mask(prefix) != host & prefix_mask(prefix) {
                    // The host is outside this block; it is unaffected.
                    next.push((network, prefix));
                } else if prefix >= 32 {
                    // The block *is* the host. Nothing can be routed here.
                    cut = true;
                } else {
                    cut = true;
                    next.extend(split_excluding_host(network, prefix, *host));
                }
            }
            current = next;
        }
        if cut {
            dropped.push(block);
        }
        kept.extend(current);
    }
    kept.sort_unstable();
    kept.dedup();
    dropped.sort_unstable();
    dropped.dedup();
    (kept, dropped)
}

/// The minimal set of CIDR blocks covering `network/prefix` except the single
/// address [host]. The caller must have established that the block contains it.
///
/// Iterative rather than recursive: this runs in a long-lived daemon and there
/// is no reason to spend stack on a walk that is at most 32 steps deep.
fn split_excluding_host(network: u32, prefix: u8, host: u32) -> Vec<(u32, u8)> {
    if prefix >= 32 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut pending = vec![(network, prefix)];
    while let Some((base, length)) = pending.pop() {
        if length >= 32 {
            continue;
        }
        // Split in half; the half that does not contain the host is emitted
        // whole, and the half that does is split again.
        let half = 1_u32 << (31 - u32::from(length));
        let lower = base;
        let upper = base | half;
        if host < upper {
            out.push((upper, length + 1));
            pending.push((lower, length + 1));
        } else {
            out.push((lower, length + 1));
            pending.push((upper, length + 1));
        }
    }
    out
}

/// Applies [resolved] through the platform's own configurator.
///
/// A `None` configurator is not an error: Android and OHOS configured the
/// interface before handing over the descriptor, and a Linux daemon's packaging
/// decides between `iproute2`, `systemd-networkd`, and netlink. In both cases
/// this process has nothing to do and saying so is the right answer.
pub fn apply(opened: &crate::device::OpenedDevice, resolved: &InterfaceConfig) -> io::Result<()> {
    match &opened.configure {
        Some(configure) => configure(resolved),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> u32 {
        parse_ipv4(text).expect("a valid address")
    }

    fn cidrs(blocks: &[(&str, u8)]) -> Vec<(u32, u8)> {
        blocks
            .iter()
            .map(|(text, prefix)| (ip(text), *prefix))
            .collect()
    }

    fn texts(blocks: &[(u32, u8)]) -> Vec<String> {
        blocks
            .iter()
            .map(|(network, prefix)| format!("{}/{}", ipv4_text(*network), prefix))
            .collect()
    }

    #[test]
    fn a_block_that_avoids_every_node_is_kept_whole() {
        let (kept, dropped) = partition_excluded(&cidrs(&[("10.1.0.0", 16)]), &[ip("203.0.113.9")]);
        assert_eq!(texts(&kept), vec!["10.1.0.0/16"]);
        assert!(dropped.is_empty());
    }

    #[test]
    fn a_node_inside_a_block_punches_exactly_one_hole_in_it() {
        // 10.0.0.0/8 with a node at 10.1.2.3 becomes the blocks covering
        // everything except that one address: one sibling per level from /9 down
        // to /32, so 32 - 8 = 24 of them.
        let (kept, dropped) = partition_excluded(&cidrs(&[("10.0.0.0", 8)]), &[ip("10.1.2.3")]);
        assert_eq!(
            texts(&dropped),
            vec!["10.0.0.0/8"],
            "the original is reported"
        );
        assert_eq!(kept.len(), 24, "a /8 minus one host is 24 blocks");
        assert!(
            !kept.iter().any(|(network, prefix)| {
                network & prefix_mask(*prefix) == ip("10.1.2.3") & prefix_mask(*prefix)
            }),
            "no surviving block may contain the node: {:?}",
            texts(&kept)
        );
        // And nothing else was lost: every other address in the /8 is still
        // covered. Spot-check the neighbours of the hole.
        let covered = |address: u32| {
            kept.iter()
                .any(|(network, prefix)| address & prefix_mask(*prefix) == *network)
        };
        assert!(covered(ip("10.1.2.2")));
        assert!(covered(ip("10.1.2.4")));
        assert!(covered(ip("10.255.255.255")));
        assert!(covered(ip("10.0.0.0")));
        assert!(!covered(ip("10.1.2.3")));
    }

    #[test]
    fn a_host_route_that_is_the_node_disappears_entirely() {
        let (kept, dropped) =
            partition_excluded(&cidrs(&[("203.0.113.9", 32)]), &[ip("203.0.113.9")]);
        assert!(
            kept.is_empty(),
            "routing the node through the tunnel deadlocks"
        );
        assert_eq!(texts(&dropped), vec!["203.0.113.9/32"]);
    }

    #[test]
    fn several_nodes_each_get_their_own_hole() {
        let (kept, _) = partition_excluded(
            &cidrs(&[("10.0.0.0", 8)]),
            &[ip("10.1.2.3"), ip("10.9.9.9")],
        );
        let covered = |address: u32| {
            kept.iter()
                .any(|(network, prefix)| address & prefix_mask(*prefix) == *network)
        };
        assert!(!covered(ip("10.1.2.3")));
        assert!(!covered(ip("10.9.9.9")));
        assert!(covered(ip("10.1.2.4")));
        assert!(covered(ip("10.9.9.8")));
    }

    #[test]
    fn the_default_route_survives_as_everything_except_the_nodes() {
        // A full-tunnel deployment publishes 0.0.0.0/0. Losing the node out of
        // it must not lose the rest of the internet.
        let (kept, _) = partition_excluded(&cidrs(&[("0.0.0.0", 0)]), &[ip("203.0.113.9")]);
        assert_eq!(kept.len(), 32, "a /0 minus one host is 32 blocks");
        let covered = |address: u32| {
            kept.iter()
                .any(|(network, prefix)| address & prefix_mask(*prefix) == *network)
        };
        assert!(covered(ip("8.8.8.8")));
        assert!(covered(ip("1.1.1.1")));
        assert!(!covered(ip("203.0.113.9")));
    }

    #[test]
    fn duplicate_and_overlapping_input_is_deduplicated() {
        let (kept, _) = partition_excluded(
            &cidrs(&[("10.1.0.0", 16), ("10.1.0.0", 16), ("10.9.0.0", 16)]),
            &[],
        );
        assert_eq!(texts(&kept), vec!["10.1.0.0/16", "10.9.0.0/16"]);
    }

    #[test]
    fn host_bits_in_the_input_do_not_change_the_block() {
        let (kept, _) = partition_excluded(&cidrs(&[("10.1.2.3", 16)]), &[]);
        assert_eq!(texts(&kept), vec!["10.1.0.0/16"]);
    }

    #[test]
    fn node_addresses_come_from_every_candidate_in_every_group() {
        let plan = plan_with_nodes(&[
            ("major", &["203.0.113.9:441", "203.0.113.10:441"][..]),
            ("backup", &["198.51.100.4:443"][..]),
        ]);
        let mut nodes = node_addresses(&plan);
        nodes.sort_unstable();
        assert_eq!(
            nodes,
            vec![ip("198.51.100.4"), ip("203.0.113.9"), ip("203.0.113.10")]
        );
    }

    #[test]
    fn a_node_given_as_a_hostname_is_not_an_address_to_exclude() {
        // It cannot be: routing tables hold addresses. The control plane
        // resolves names before it writes the plan.
        let plan = plan_with_nodes(&[("major", &["vpn.example.test:441"][..])]);
        assert!(node_addresses(&plan).is_empty());
    }

    #[test]
    fn the_address_prefers_the_configuration_over_the_gateway() {
        let plan = plan_with_nodes(&[]);
        let config = HostConfig {
            address: Some("10.0.0.99".to_string()),
            ..HostConfig::default()
        };
        let resolved =
            InterfaceConfig::resolve(&config, &plan, Some("10.0.0.42")).expect("an address");
        assert_eq!(resolved.address, "10.0.0.99");
    }

    #[test]
    fn the_address_falls_back_to_the_gateway_assignment() {
        let plan = plan_with_nodes(&[]);
        let config = HostConfig::default();
        let resolved =
            InterfaceConfig::resolve(&config, &plan, Some("10.0.0.42")).expect("an address");
        assert_eq!(resolved.address, "10.0.0.42");
    }

    #[test]
    fn no_address_anywhere_is_an_error_rather_than_a_guess() {
        let plan = plan_with_nodes(&[]);
        let error =
            InterfaceConfig::resolve(&HostConfig::default(), &plan, None).expect_err("no address");
        assert!(
            error.to_string().contains("no address to assign"),
            "{error}"
        );
    }

    #[test]
    fn resolving_reports_what_it_excluded() {
        // The daemon logs this, because a control plane that published the node
        // inside a tunnel route is a bug worth seeing.
        let plan = plan_with_nodes(&[("major", &["10.1.2.3:441"][..])]);
        let config = HostConfig {
            routes: vec!["10.1.0.0/16".to_string()],
            ..HostConfig::default()
        };
        let resolved =
            InterfaceConfig::resolve(&config, &plan, Some("10.0.0.42")).expect("an address");
        assert_eq!(resolved.excluded, vec!["10.1.0.0/16"]);
        assert_eq!(
            resolved.routes.len(),
            16,
            "a /16 minus one host is 32 - 16 = 16 blocks"
        );
    }

    fn plan_with_nodes(groups: &[(&str, &[&str])]) -> SessionPlan {
        let mut plan = sangfor_core::plan::SessionPlan::decode(
            br#"{"schemaVersion":1,"sid":"s","deviceId":"d","connectionId":"c",
                 "username":"u","signKeyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                 "lang":"en","processName":"p","processPath":"/p","processPlatform":"windows",
                 "nodes":{},"majorNodeGroup":"major","routes":[],"dnsServers":[]}"#,
        )
        .expect("the plan decodes");
        plan.nodes = groups
            .iter()
            .map(|(name, endpoints)| {
                (
                    (*name).to_string(),
                    endpoints
                        .iter()
                        .map(|endpoint| (*endpoint).to_string())
                        .collect(),
                )
            })
            .collect();
        plan
    }
}
