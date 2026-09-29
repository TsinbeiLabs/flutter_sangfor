//! The resource route table and the two matching rules the gateway's own
//! client applies.
//!
//! The split matters: [`RouteTable::match_l3`] decides whether a packet can be
//! forwarded as raw IP, and it refuses TCP unless the resource is marked
//! `enableTcpPrefL3`. Everything else has to go through the TCP tunnel
//! ([`RouteTable::match_tcp`]), which is why a raw-IP data plane needs the
//! userspace terminator.

use crate::packet::parse_ipv4;

/// One routed resource as the gateway publishes it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    /// An address, CIDR, `min~max` range, or domain (possibly wildcard).
    pub host: String,
    /// `tcp`, `udp`, or `all`.
    pub protocol: String,
    /// Inclusive lower port bound.
    pub port_min: u16,
    /// Inclusive upper port bound.
    pub port_max: u16,
    /// The resource identity sent with every request.
    pub app_id: String,
    /// Which node group serves the resource.
    pub node_group_id: String,
    /// True when the gateway resolves the destination itself.
    pub addr_pretend: bool,
    /// True when the resource may also be carried as raw IP.
    pub enable_tcp_pref_l3: bool,
}

impl Route {
    /// Field names as the Dart side spells them, for callers that build routes
    /// by hand.
    #[must_use]
    pub fn field_names() -> [&'static str; 8] {
        [
            "host",
            "protocol",
            "portMin",
            "portMax",
            "appId",
            "nodeGroupId",
            "addrPretend",
            "enableTcpPrefL3",
        ]
    }
}

/// The published route list plus the two matching rules.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    routes: Vec<Route>,
}

impl RouteTable {
    /// Wraps [routes].
    #[must_use]
    pub fn new(routes: Vec<Route>) -> Self {
        Self { routes }
    }

    /// The routes, in the order the gateway published them.
    #[must_use]
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// The route that lets a packet to `destination:port` travel as raw IP.
    ///
    /// TCP only matches when the resource is marked L3-preferred, mirroring the
    /// reference client; that single rule is why most flows need the TCP
    /// tunnel instead.
    #[must_use]
    pub fn match_l3(&self, destination: u32, protocol: &str, port: u16) -> Option<&Route> {
        self.routes.iter().find(|route| {
            (route.protocol == "all" || route.protocol == protocol)
                && port >= route.port_min
                && port <= route.port_max
                && !(protocol == "tcp" && !route.enable_tcp_pref_l3)
                && host_covers(&route.host, destination)
        })
    }

    /// The route that lets a connection to `host:port` travel through the TCP
    /// tunnel. Prefers resources that are *not* L3-preferred;
    /// `include_l3_preferred` widens the second pass to everything published.
    ///
    /// [host] may be a dotted quad (matched against address-shaped resources)
    /// or a domain name (matched against domain-shaped ones).
    #[must_use]
    pub fn match_tcp(&self, host: &str, port: u16, include_l3_preferred: bool) -> Option<&Route> {
        let literal = parse_ipv4(host);
        let pass = |allow_l3_preferred: bool| {
            self.routes.iter().find(|route| {
                (route.protocol == "all" || route.protocol == "tcp")
                    && port >= route.port_min
                    && port <= route.port_max
                    && (allow_l3_preferred || !route.enable_tcp_pref_l3)
                    && match literal {
                        Some(address) => host_covers(&route.host, address),
                        None => domain_covers(&route.host, host),
                    }
            })
        };
        pass(false).or_else(|| {
            if include_l3_preferred {
                pass(true)
            } else {
                None
            }
        })
    }
}

/// True when a resource's `host` (address, CIDR, or `min~max` range) covers
/// [destination]. Domain-shaped entries never cover an address.
#[must_use]
pub fn host_covers(host: &str, destination: u32) -> bool {
    if let Some((base, prefix)) = host.split_once('/') {
        let (Some(base), Some(prefix)) = (parse_ipv4(base), prefix.parse::<u32>().ok()) else {
            return false;
        };
        if prefix > 32 {
            return false;
        }
        if prefix == 0 {
            return true;
        }
        let mask = if prefix == 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - prefix)
        };
        return base & mask == destination & mask;
    }
    if let Some((low, high)) = host.split_once('~') {
        let (Some(low), Some(high)) = (parse_ipv4(low.trim()), parse_ipv4(high.trim())) else {
            return false;
        };
        return destination >= low && destination <= high;
    }
    match parse_ipv4(host) {
        Some(address) => address == destination,
        None => false,
    }
}

/// True when a literal or wildcard domain pattern covers [host]. `*.example`
/// covers subdomains but not the apex, matching the reference client.
#[must_use]
pub fn domain_covers(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim();
    let pattern = pattern.strip_prefix('*').unwrap_or(pattern);
    if pattern.contains('*') || pattern.is_empty() {
        return false;
    }
    if let Some(suffix) = pattern.strip_prefix('.') {
        return host.ends_with(suffix) && host.len() > suffix.len();
    }
    host == pattern
}
