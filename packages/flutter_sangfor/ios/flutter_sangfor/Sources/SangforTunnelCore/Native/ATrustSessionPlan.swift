import Foundation

/// Everything the packet tunnel extension needs to run the tunnel itself,
/// handed over by the Runner after login.
///
/// The extension cannot log in: it has no UI for challenges and no access to
/// the credential store. The Runner therefore resolves the session (login,
/// node probing, virtual IP) and writes this plan into the App Group container
/// before starting the tunnel. The JSON keys are part of the contract with the
/// Dart side, which encodes the same shape.
public struct ATrustSessionPlan: Codable, Equatable {
  /// Bumped when a field is added that older extensions cannot ignore.
  public static let currentSchemaVersion = 1

  public let schemaVersion: Int
  public let sid: String
  public let deviceId: String
  public let connectionId: String
  public let username: String
  /// Base64 of the 32-byte request signing key.
  public let signKeyBase64: String
  public let lang: String
  public let processName: String
  public let processPath: String
  public let processPlatform: String
  /// Node endpoints per group, best candidate first (`host:port`).
  public let nodes: [String: [String]]
  public let majorNodeGroup: String
  public let routes: [ATrustRoute]
  public let dnsServers: [String]
  /// The virtual IP the gateway assigned; nil when the extension should take
  /// whatever the handshake returns.
  public let virtualAddress: String?
  /// Hex SHA-256 digests of accepted gateway certificates (anti-MITM). Empty
  /// means "no pins available".
  public let certificateDigests: [String]
  /// True when the deployment presents certificates the platform trust store
  /// rejects and no pins are available.
  public let acceptAnyCertificate: Bool
  /// Resolved IPv4 address to the host name the gateway published, so a
  /// domain-published resource can still be dialed by name.
  public let dialHosts: [String: String]
  public let heartbeatSeconds: Double
  public let mtu: Int
  /// How destinations are decided for the extension's proxy. The app adds this
  /// key to the document it writes; plans without it decode as nil.
  public let domainRouting: SangforDomainRoutingConfiguration?
  /// The network settings the app computed, for starts that arrive without
  /// start options.
  public let tunnelSettings: SangforPlanTunnelSettings?
  /// Every host name that resolved to an address, where [dialHosts] keeps one.
  /// Several names often sit behind one address (a shared front end), each
  /// published on its own ports; this lets a flow be matched by port. Optional:
  /// without it [dialHosts] is all there is.
  public let dialHostAliases: [String: [String]]?

  public init(
    schemaVersion: Int = ATrustSessionPlan.currentSchemaVersion,
    sid: String,
    deviceId: String,
    connectionId: String,
    username: String,
    signKeyBase64: String,
    lang: String,
    processName: String,
    processPath: String,
    processPlatform: String,
    nodes: [String: [String]],
    majorNodeGroup: String,
    routes: [ATrustRoute],
    dnsServers: [String],
    virtualAddress: String? = nil,
    certificateDigests: [String] = [],
    acceptAnyCertificate: Bool = true,
    dialHosts: [String: String] = [:],
    heartbeatSeconds: Double = 5,
    mtu: Int = 1400,
    domainRouting: SangforDomainRoutingConfiguration? = nil,
    tunnelSettings: SangforPlanTunnelSettings? = nil,
    dialHostAliases: [String: [String]]? = nil
  ) {
    self.schemaVersion = schemaVersion
    self.sid = sid
    self.deviceId = deviceId
    self.connectionId = connectionId
    self.username = username
    self.signKeyBase64 = signKeyBase64
    self.lang = lang
    self.processName = processName
    self.processPath = processPath
    self.processPlatform = processPlatform
    self.nodes = nodes
    self.majorNodeGroup = majorNodeGroup
    self.routes = routes
    self.dnsServers = dnsServers
    self.virtualAddress = virtualAddress
    self.certificateDigests = certificateDigests
    self.acceptAnyCertificate = acceptAnyCertificate
    self.dialHosts = dialHosts
    self.heartbeatSeconds = heartbeatSeconds
    self.mtu = mtu
    self.domainRouting = domainRouting
    self.tunnelSettings = tunnelSettings
    self.dialHostAliases = dialHostAliases
  }

  /// The host name to dial for a flow to [address]:[port]: the first name behind
  /// the address that a resource covers on that port, else the name [dialHosts]
  /// has, else nil.
  public func dialHost(for address: String, port: Int) -> String? {
    let candidates = dialHostAliases?[address] ?? dialHosts[address].map { [$0] } ?? []
    let table = routeTable
    return candidates.first { table.matchTcp(destinationHost: $0, port: port) != nil }
      ?? candidates.first
  }

  /// The request signing key, or nil when it is not valid base64.
  public var signKey: [UInt8]? {
    guard let data = Data(base64Encoded: signKeyBase64) else { return nil }
    return [UInt8](data)
  }

  /// The process identity reported with every signed request.
  public var process: ATrustProcessInfo {
    ATrustProcessInfo(
      name: processName,
      path: processPath,
      platform: processPlatform
    )
  }

  public var routeTable: ATrustRouteTable {
    ATrustRouteTable(routes: routes)
  }

  /// The endpoint to dial for [nodeGroupId], falling back to the major group.
  public func nodeEndpoint(for nodeGroupId: String) -> ATrustNodeEndpoint? {
    let candidates = nodes[nodeGroupId] ?? nodes[majorNodeGroup] ?? []
    for candidate in candidates {
      if let endpoint = ATrustNodeEndpoint(candidate) { return endpoint }
    }
    return nil
  }

  public static func decode(_ data: Data) throws -> ATrustSessionPlan {
    try JSONDecoder().decode(ATrustSessionPlan.self, from: data)
  }

  public func encoded() throws -> Data {
    try JSONEncoder().encode(self)
  }
}

/// A bidirectional byte stream to a tunnel node, or to a dialed TCP tunnel
/// connection. Implemented over `NWConnection` in production and over an
/// in-memory double in tests.
public protocol SangforByteChannel: AnyObject {
  /// True once the channel can no longer carry bytes.
  var isClosed: Bool { get }

  /// Called with every chunk that arrives.
  var onData: ((Data) -> Void)? { get set }

  /// Called once when the peer hangs up or the channel fails.
  var onClosed: ((Error?) -> Void)? { get set }

  /// Queues [data] for sending.
  func send(_ data: Data)

  /// Stops or resumes delivering [onData], for backpressure. Channels that
  /// cannot pause keep the default no-op.
  func setReadsPaused(_ paused: Bool)

  /// Closes the channel. Idempotent.
  func close()
}

public extension SangforByteChannel {
  func setReadsPaused(_ paused: Bool) {}
}

/// Opens a [SangforByteChannel] to `host:port` over TLS.
public typealias SangforChannelDialer =
  (_ host: String, _ port: Int, _ completion: @escaping (Result<SangforByteChannel, Error>) -> Void) -> Void
