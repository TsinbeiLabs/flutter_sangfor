import Foundation

/// Stable identifiers stored in `NETunnelProviderProtocol.providerConfiguration`
/// so a saved manager can be recognized as one created by this package.
public enum SangforTunnelConfigurationKeys {
  /// Marker identifying a configuration as owned by `flutter_sangfor`.
  public static let implementation = "implementation"

  /// The value stored under [implementation].
  public static let implementationValue = "flutter_sangfor"

  /// Schema version of the provider configuration blob.
  public static let schemaVersion = "schemaVersion"

  /// Current schema version.
  public static let currentSchemaVersion = 1

  /// Key for the app group shared between Runner and the extension.
  public static let appGroupIdentifier = "appGroupIdentifier"

  /// Key for the runtime mode of the extension data plane.
  public static let runtimeMode = "runtimeMode"
}

/// Runtime mode of the packet tunnel extension.
public enum SangforRuntimeMode: String, Codable {
  /// The extension forwards packets to the containing app over a loopback
  /// TCP bridge. Requires the Runner to stay alive; experimental.
  case loopbackBridge

  /// Reserved for the future extension-hosted native data plane.
  case extensionNative
}

/// Codable tunnel configuration shared between the Runner and the packet
/// tunnel extension (large payloads travel through the App Group container,
/// never through `providerConfiguration`).
public struct SangforTunnelConfiguration: Codable, Equatable {
  public var schemaVersion: Int
  public var address: String
  public var prefixLength: Int
  public var routes: [String]
  public var dnsServers: [String]
  public var searchDomains: [String]
  /// Host of a loopback HTTP proxy advertised system-wide through
  /// `NEProxySettings` while the tunnel is up. Resources published as
  /// TCP-tunnel-only cannot be forwarded as raw IP, so proxy-honoring
  /// clients must be pointed at the caller's proxy instead of the packet
  /// flow. Empty/nil keeps the tunnel proxy-free.
  public var proxyHost: String?
  /// Port of [proxyHost]; ignored unless the port is in 1...65535.
  public var proxyPort: Int?
  public var mtu: Int?
  public var runtimeMode: SangforRuntimeMode

  public init(
    schemaVersion: Int = SangforTunnelConfigurationKeys.currentSchemaVersion,
    address: String,
    prefixLength: Int = 32,
    routes: [String] = [],
    dnsServers: [String] = [],
    searchDomains: [String] = [],
    proxyHost: String? = nil,
    proxyPort: Int? = nil,
    mtu: Int? = nil,
    runtimeMode: SangforRuntimeMode = .loopbackBridge
  ) {
    self.schemaVersion = schemaVersion
    self.address = address
    self.prefixLength = prefixLength
    self.routes = routes
    self.dnsServers = dnsServers
    self.searchDomains = searchDomains
    self.proxyHost = proxyHost
    self.proxyPort = proxyPort
    self.mtu = mtu
    self.runtimeMode = runtimeMode
  }

  /// The proxy endpoint when both halves are present and the port is usable.
  /// Callers must treat `nil` as "no system proxy" and never fall back to a
  /// default port.
  public var proxyEndpoint: (host: String, port: Int)? {
    guard
      let host = proxyHost?.trimmingCharacters(in: .whitespaces),
      !host.isEmpty,
      let port = proxyPort,
      (1...65_535).contains(port)
    else { return nil }
    return (host, port)
  }

  /// Encodes the configuration as JSON data.
  public func encoded() throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return try encoder.encode(self)
  }

  /// Decodes a configuration from JSON data.
  public static func decode(_ data: Data) throws -> SangforTunnelConfiguration {
    try JSONDecoder().decode(SangforTunnelConfiguration.self, from: data)
  }

  /// The minimal `providerConfiguration` dictionary identifying this
  /// package's saved managers. Never store secrets here.
  public func providerConfiguration(appGroupIdentifier: String?) -> [String: Any] {
    var configuration: [String: Any] = [
      SangforTunnelConfigurationKeys.implementation:
        SangforTunnelConfigurationKeys.implementationValue,
      SangforTunnelConfigurationKeys.schemaVersion:
        SangforTunnelConfigurationKeys.currentSchemaVersion,
      SangforTunnelConfigurationKeys.runtimeMode: runtimeMode.rawValue,
    ]
    if let appGroupIdentifier, !appGroupIdentifier.isEmpty {
      configuration[SangforTunnelConfigurationKeys.appGroupIdentifier] = appGroupIdentifier
    }
    return configuration
  }
}
