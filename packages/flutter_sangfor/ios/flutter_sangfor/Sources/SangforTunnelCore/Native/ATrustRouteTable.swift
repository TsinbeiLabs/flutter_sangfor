import Foundation

/// One routed resource as the gateway publishes it.
public struct ATrustRoute: Codable, Equatable {
  public let host: String
  /// `tcp`, `udp`, or `all`; the JSON key is `protocol`.
  public let protocolName: String
  public let portMin: Int
  public let portMax: Int
  public let appId: String
  public let nodeGroupId: String
  public let addrPretend: Bool
  public let enableTcpPrefL3: Bool

  public init(
    host: String,
    protocolName: String,
    portMin: Int,
    portMax: Int,
    appId: String,
    nodeGroupId: String,
    addrPretend: Bool,
    enableTcpPrefL3: Bool
  ) {
    self.host = host
    self.protocolName = protocolName
    self.portMin = portMin
    self.portMax = portMax
    self.appId = appId
    self.nodeGroupId = nodeGroupId
    self.addrPretend = addrPretend
    self.enableTcpPrefL3 = enableTcpPrefL3
  }

  enum CodingKeys: String, CodingKey {
    case host
    case protocolName = "protocol"
    case portMin, portMax, appId, nodeGroupId, addrPretend, enableTcpPrefL3
  }
}

/// A node endpoint: `host:port`, or `[host]:port` for IPv6.
public struct ATrustNodeEndpoint: Equatable {
  public let host: String
  public let port: Int

  /// Parses `host:port`, defaulting to 441 like the reference client.
  public init?(_ text: String) {
    if text.hasPrefix("[") {
      guard let close = text.firstIndex(of: "]") else { return nil }
      host = String(text[text.index(after: text.startIndex)..<close])
      let rest = text[text.index(after: close)...]
      if rest.isEmpty {
        port = 441
      } else if rest.hasPrefix(":"), let parsed = Int(rest.dropFirst()) {
        port = parsed
      } else {
        return nil
      }
      return
    }
    guard let colon = text.lastIndex(of: ":") else {
      host = text
      port = 441
      return
    }
    guard let parsed = Int(text[text.index(after: colon)...]) else { return nil }
    host = String(text[..<colon])
    port = parsed
  }

  public init(host: String, port: Int) {
    self.host = host
    self.port = port
  }
}

/// Route matching for the tunnel data plane, mirroring the reference client.
public struct ATrustRouteTable {
  public let routes: [ATrustRoute]

  public init(routes: [ATrustRoute]) {
    self.routes = routes
  }

  /// The route that lets a packet travel as raw IP. TCP only matches when the
  /// resource is marked L3-preferred, which is why most flows need the TCP
  /// tunnel (or local termination) instead.
  public func matchL3(
    destinationAddress: String,
    protocolName: String,
    port: Int
  ) -> ATrustRoute? {
    for route in routes {
      if route.protocolName != "all", route.protocolName != protocolName {
        continue
      }
      if port < route.portMin || port > route.portMax { continue }
      if protocolName == "tcp", !route.enableTcpPrefL3 { continue }
      if Self.hostCovers(route.host, address: destinationAddress) { return route }
    }
    return nil
  }

  /// The route that lets a connection travel through the TCP tunnel. Prefers
  /// resources that are *not* L3-preferred; [includeL3Preferred] widens the
  /// second pass to everything the gateway published.
  public func matchTcp(
    destinationHost: String,
    port: Int,
    includeL3Preferred: Bool = true
  ) -> ATrustRoute? {
    func match(allowL3Preferred: Bool) -> ATrustRoute? {
      for route in routes {
        if route.protocolName != "all", route.protocolName != "tcp" { continue }
        if port < route.portMin || port > route.portMax { continue }
        if route.enableTcpPrefL3, !allowL3Preferred { continue }
        let covered = SangforAddressBytes.ipv4(destinationHost) != nil
          ? Self.hostCovers(route.host, address: destinationHost)
          : Self.domainCovers(route.host, host: destinationHost)
        if covered { return route }
      }
      return nil
    }
    return match(allowL3Preferred: false)
      ?? (includeL3Preferred ? match(allowL3Preferred: true) : nil)
  }

  /// True when [host] (an address, CIDR, or `min~max` range) covers [address].
  public static func hostCovers(_ host: String, address: String) -> Bool {
    if host.contains("/") {
      let parts = host.split(separator: "/")
      guard parts.count == 2,
        let base = ipv4Value(String(parts[0])),
        let prefix = Int(parts[1]),
        let destination = ipv4Value(address),
        (0...32).contains(prefix)
      else { return false }
      if prefix == 0 { return true }
      let mask: UInt32 = prefix == 32
        ? 0xffff_ffff
        : 0xffff_ffff << UInt32(32 - prefix)
      return base & mask == destination & mask
    }
    if host.contains("~") {
      let bounds = host.split(separator: "~")
      guard bounds.count == 2,
        let low = ipv4Value(String(bounds[0])),
        let high = ipv4Value(String(bounds[1])),
        let destination = ipv4Value(address)
      else { return false }
      return destination >= low && destination <= high
    }
    if ipv4Value(host) != nil { return host == address }
    return false
  }

  /// True when a literal or wildcard domain pattern covers [host].
  public static func domainCovers(_ pattern: String, host: String) -> Bool {
    var pattern = pattern.trimmingCharacters(in: .whitespaces)
    if pattern.hasPrefix("*.") { pattern = String(pattern.dropFirst(1)) }
    if pattern.contains("*") { return false }
    if pattern.isEmpty { return false }
    if pattern.hasPrefix(".") { return host.hasSuffix(pattern) }
    return host == pattern
  }

  static func ipv4Value(_ text: String) -> UInt32? {
    guard let bytes = SangforAddressBytes.ipv4(text) else { return nil }
    return UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16
      | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
  }
}
