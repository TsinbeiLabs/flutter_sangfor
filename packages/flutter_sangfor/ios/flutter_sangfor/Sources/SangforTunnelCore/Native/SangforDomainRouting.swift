import Foundation

/// How the app wants destinations decided, handed to the extension inside the
/// session plan (`domainRouting`). The key is opt-in: a plan without it gets
/// no proxy. Within the key, a missing field takes the default below.
public struct SangforDomainRoutingConfiguration: Codable, Equatable {
  /// Mirrors the app's `VpnRoutePolicyMode`.
  public var policy: SangforRouteMatcher.Policy
  /// The user's custom entries, with the app's defaults already expanded. The
  /// extension never holds a default list of its own.
  public var customEntries: [String]
  /// Hosts that must keep the user's own source address (the app lists the VPN
  /// gateway itself). Matched exactly, like the app's `neverTunneledHosts`.
  public var neverTunnelHosts: [String]
  /// Whether the extension should publish its HTTP proxy to the system.
  public var proxyEnabled: Bool

  public init(
    policy: SangforRouteMatcher.Policy = .followServer,
    customEntries: [String] = [],
    neverTunnelHosts: [String] = [],
    proxyEnabled: Bool = true
  ) {
    self.policy = policy
    self.customEntries = customEntries
    self.neverTunnelHosts = neverTunnelHosts
    self.proxyEnabled = proxyEnabled
  }

  enum CodingKeys: String, CodingKey {
    case policy, customEntries, neverTunnelHosts, proxyEnabled
  }

  /// Every key is optional so a plan written by an older app still decodes.
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    policy =
      try container.decodeIfPresent(SangforRouteMatcher.Policy.self, forKey: .policy)
      ?? .followServer
    customEntries =
      try container.decodeIfPresent([String].self, forKey: .customEntries) ?? []
    neverTunnelHosts =
      try container.decodeIfPresent([String].self, forKey: .neverTunnelHosts) ?? []
    proxyEnabled =
      try container.decodeIfPresent(Bool.self, forKey: .proxyEnabled) ?? true
  }
}

/// Decides whether a destination travels through the aTrust tunnel.
///
/// This is a line-for-line port of the app's `VpnRouteMatcher`, which is what
/// the Android loopback proxy uses. Both are exercised by the same JSON case
/// table (`route_matcher_cases.json`), so a rule changed on one side cannot
/// drift from the other.
public struct SangforRouteMatcher {
  public enum Policy: String, Codable {
    /// Only the server-published resource list decides.
    case followServer
    /// The user's entries narrow the server list: a destination tunnels only
    /// when a custom entry *and* a server route both cover it.
    case custom
  }

  public let policy: Policy
  public let customEntries: [String]
  public let serverRoutes: [ATrustRoute]

  public init(policy: Policy, customEntries: [String], serverRoutes: [ATrustRoute]) {
    self.policy = policy
    self.customEntries = customEntries
    self.serverRoutes = serverRoutes
  }

  public func shouldTunnel(host: String, port: Int) -> Bool {
    let normalized = host.trimmingCharacters(in: .whitespaces).lowercased()
    if normalized.isEmpty { return false }
    // The tunnel carries IPv4 only.
    if normalized.contains(":") { return false }
    if Self.isLiteralIPv4(normalized) {
      return matchesAddress(normalized, port: port)
    }
    return matchesDomain(normalized, port: port)
  }

  private func matchesAddress(_ address: String, port: Int) -> Bool {
    if policy == .custom, !customEntryCoversAddress(address) { return false }
    for route in serverRoutes {
      guard Self.routeAllowsTcp(route), Self.portCovers(route, port) else { continue }
      if ATrustRouteTable.hostCovers(route.host, address: address) { return true }
    }
    return false
  }

  private func matchesDomain(_ host: String, port: Int) -> Bool {
    if policy == .custom, !customEntryCoversDomain(host) { return false }
    for route in serverRoutes {
      guard Self.routeAllowsTcp(route), Self.portCovers(route, port) else { continue }
      if ATrustRouteTable.domainCovers(route.host, host: host) { return true }
    }
    return false
  }

  private func customEntryCoversDomain(_ host: String) -> Bool {
    for entry in customEntries {
      // Address entries (IPv4, CIDR, range) never match a host name.
      if Self.isLiteralIPv4(entry) || entry.contains("/") || entry.contains("~") {
        continue
      }
      if ATrustRouteTable.domainCovers(entry, host: host) { return true }
    }
    return false
  }

  private func customEntryCoversAddress(_ address: String) -> Bool {
    for entry in customEntries {
      if !entry.contains("/"), !entry.contains("~"), Self.isLiteralIPv4(entry) {
        if entry == address { return true }
        continue
      }
      if ATrustRouteTable.hostCovers(entry, address: address) { return true }
    }
    return false
  }

  private static func routeAllowsTcp(_ route: ATrustRoute) -> Bool {
    route.protocolName == "all" || route.protocolName == "tcp"
  }

  private static func portCovers(_ route: ATrustRoute, _ port: Int) -> Bool {
    port >= route.portMin && port <= route.portMax
  }

  /// `a.b.c.d`, optionally followed by `/n` (the app's matcher accepts both).
  static func isLiteralIPv4(_ value: String) -> Bool {
    if value.isEmpty { return false }
    let host = value.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
      .first.map(String.init) ?? value
    let parts = host.split(separator: ".", omittingEmptySubsequences: false)
    if parts.count != 4 { return false }
    for part in parts {
      guard let octet = Int(part), (0...255).contains(octet) else { return false }
    }
    return true
  }
}

/// Turns resource host patterns into the domain suffixes the system should send
/// to the proxy (and, later, to a DNS resolver of our own).
public enum SangforDnsDomains {
  /// Domain-looking entries only: addresses, CIDRs and ranges are skipped,
  /// `*.x` and `.x` become `x`, anything else containing `*` or no dot is
  /// dropped, and a suffix already covered by a shorter one is removed.
  public static func derive(_ hosts: [String]) -> [String] {
    var seen = Set<String>()
    var domains: [String] = []
    for raw in hosts {
      var host = raw.trimmingCharacters(in: .whitespaces).lowercased()
      if host.isEmpty || host.contains("/") || host.contains("~") { continue }
      if SangforRouteMatcher.isLiteralIPv4(host) { continue }
      if host.hasPrefix("*.") {
        host.removeFirst(2)
      } else if host.hasPrefix(".") {
        host.removeFirst()
      }
      if host.contains("*") || !host.contains(".") || host.hasPrefix(".") { continue }
      if host.hasSuffix(".") { host.removeLast() }
      if seen.insert(host).inserted { domains.append(host) }
    }
    let set = Set(domains)
    let minimal = domains.filter { domain in
      !set.contains { other in other != domain && domain.hasSuffix("." + other) }
    }
    return minimal.sorted()
  }
}

/// What the loopback proxy does with one requested destination.
public enum SangforProxyDecision: Equatable {
  /// Carry the connection through the aTrust TCP tunnel.
  case tunnel
  /// Dial the destination from the extension, outside the tunnel.
  case direct
  /// Refuse it. The proxy is not a general open proxy.
  case reject
}

/// The proxy's one decision function; the relay and `explain` share it.
public struct SangforProxyPolicy {
  public let matcher: SangforRouteMatcher
  public let neverTunnelHosts: Set<String>
  /// The suffixes the system was told to send to the proxy.
  public let matchDomains: [String]

  public init(
    matcher: SangforRouteMatcher,
    neverTunnelHosts: [String],
    matchDomains: [String]
  ) {
    self.matcher = matcher
    self.neverTunnelHosts = Set(neverTunnelHosts.map { $0.lowercased() })
    self.matchDomains = matchDomains.map { $0.lowercased() }
  }

  public func decide(host: String, port: Int) -> SangforProxyDecision {
    var normalized = host.trimmingCharacters(in: .whitespaces).lowercased()
    if normalized.hasSuffix(".") { normalized.removeLast() }
    if normalized.isEmpty { return .reject }
    // No IPv6 in the tunnel, and an address literal is not a name the system
    // would have routed here.
    if normalized.contains(":") { return .reject }
    if neverTunnelHosts.contains(normalized) { return .direct }
    if matcher.shouldTunnel(host: normalized, port: port) { return .tunnel }
    if Self.isLiteralAddress(normalized) { return .reject }
    if coveredByMatchDomains(normalized) { return .direct }
    return .reject
  }

  public func coveredByMatchDomains(_ host: String) -> Bool {
    matchDomains.contains { host == $0 || host.hasSuffix("." + $0) }
  }

  private static func isLiteralAddress(_ host: String) -> Bool {
    SangforAddressBytes.ipv4(host) != nil
  }
}

/// The tunnel's network settings as the app computed them, carried in the
/// session plan (`tunnelSettings`).
///
/// An app-initiated start gets these through the start options. A start the
/// system initiates -- the VPN switched on from Settings or Control Center, or
/// iOS bringing the provider back after a network change or a reboot -- has no
/// options at all, and without this the extension would have nothing to apply.
/// The plan outlives a transient stop, so the extension can rebuild its
/// settings from it on its own.
public struct SangforPlanTunnelSettings: Codable, Equatable {
  /// The interface address; nil means the plan's own `virtualAddress`.
  public var address: String?
  public var prefixLength: Int
  public var routes: [String]
  /// Destinations that must never enter the tunnel (the VPN gateway). They win
  /// over `routes`.
  public var excludedRoutes: [String]
  public var dnsServers: [String]
  public var searchDomains: [String]
  public var mtu: Int?

  public init(
    address: String? = nil,
    prefixLength: Int = 32,
    routes: [String] = [],
    excludedRoutes: [String] = [],
    dnsServers: [String] = [],
    searchDomains: [String] = [],
    mtu: Int? = nil
  ) {
    self.address = address
    self.prefixLength = prefixLength
    self.routes = routes
    self.excludedRoutes = excludedRoutes
    self.dnsServers = dnsServers
    self.searchDomains = searchDomains
    self.mtu = mtu
  }

  enum CodingKeys: String, CodingKey {
    case address, prefixLength, routes, excludedRoutes, dnsServers, searchDomains, mtu
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    address = try container.decodeIfPresent(String.self, forKey: .address)
    prefixLength = try container.decodeIfPresent(Int.self, forKey: .prefixLength) ?? 32
    routes = try container.decodeIfPresent([String].self, forKey: .routes) ?? []
    excludedRoutes =
      try container.decodeIfPresent([String].self, forKey: .excludedRoutes) ?? []
    dnsServers = try container.decodeIfPresent([String].self, forKey: .dnsServers) ?? []
    searchDomains =
      try container.decodeIfPresent([String].self, forKey: .searchDomains) ?? []
    mtu = try container.decodeIfPresent(Int.self, forKey: .mtu)
  }
}
