import Foundation

/// The extension-side data plane: node connections, route decisions, local TCP
/// termination, and the inbound packet stream.
///
/// Everything platform-specific (TLS, timers, the packet flow) is injected, so
/// this type is testable off-device: [SangforChannelDialer] supplies channels
/// and [SangforScheduler] supplies time.
public final class SangforNativeDataPlane {
  /// Counters for the log line the provider emits periodically.
  public struct Statistics {
    public var egress = 0
    public var routed = 0
    public var terminated = 0
    public var unrouted = 0
    public var ingress = 0
    public var egressBytes = 0
    public var ingressBytes = 0
    public var reconnects = 0

    public var description: String {
      "egress=\(egress) routed=\(routed) terminated=\(terminated) "
        + "unrouted=\(unrouted) ingress=\(ingress) reconnects=\(reconnects)"
    }
  }

  public struct Configuration {
    /// Delay before a dropped node connection is retried.
    public var reconnectDelay: Double = 5
    /// Flow-auth and heartbeat tuning handed to each L3 connection.
    public var connection = ATrustL3Connection.Configuration()
    /// Terminator tuning.
    public var terminator = ATrustTcpTerminator.Configuration()

    public init() {}
  }

  private let plan: ATrustSessionPlan
  private let scheduler: SangforScheduler
  private let dialer: SangforChannelDialer
  private let configuration: Configuration
  private let routeTable: ATrustRouteTable
  private let log: (String) -> Void

  private var connections: [String: ATrustL3Connection] = [:]
  private var connecting: [String: Bool] = [:]
  private var reconnectTasks: [String: SangforScheduledTask] = [:]
  private var terminator: ATrustTcpTerminator?
  private var closed = false

  public private(set) var statistics = Statistics()
  public private(set) var virtualAddresses: [String] = []

  /// Packets to inject into the system (packetFlow.writePackets).
  public var onIngressPacket: ((Data) -> Void)?
  /// A failure the provider should surface by cancelling the tunnel.
  public var onFatalError: ((Error) -> Void)?
  public var onVirtualIP: (([String]) -> Void)?

  public init(
    plan: ATrustSessionPlan,
    scheduler: SangforScheduler,
    dialer: @escaping SangforChannelDialer,
    configuration: Configuration = Configuration(),
    log: @escaping (String) -> Void = { _ in }
  ) {
    self.plan = plan
    self.scheduler = scheduler
    self.dialer = dialer
    self.configuration = configuration
    routeTable = plan.routeTable
    self.log = log
  }

  /// Brings up the connection for the major node group. The completion reports
  /// the virtual IP the gateway assigned (the plan's value when the gateway
  /// does not send one).
  public func start(completion: @escaping (Result<[String], Error>) -> Void) {
    let terminatorConfiguration = configuration.terminator
    let terminator = ATrustTcpTerminator(
      dialer: { [weak self] host, port, dialCompletion in
        self?.dialTcpTunnel(host: host, port: port, completion: dialCompletion)
      },
      shouldTerminate: { [weak self] address, port in
        self?.shouldTerminate(address: address, port: port) ?? false
      },
      dialHostResolver: { [weak self] address, _ in
        self?.plan.dialHosts[address]
      },
      scheduler: scheduler,
      configuration: terminatorConfiguration,
      onError: { [weak self] error in
        self?.log("tcp terminator: \(error)")
      }
    )
    terminator.onPacket = { [weak self] packet in
      self?.deliverIngress(packet)
    }
    self.terminator = terminator

    openConnection(for: plan.majorNodeGroup) { [weak self] result in
      guard let self else { return }
      switch result {
      case .failure(let error):
        completion(.failure(error))
      case .success(let connection):
        let addresses = connection.virtualAddresses.isEmpty
          ? (self.plan.virtualAddress.map { [$0] } ?? [])
          : connection.virtualAddresses
        self.virtualAddresses = addresses
        completion(.success(addresses))
      }
    }
  }

  /// Routes one packet that the system handed to the tunnel.
  public func handleEgressPacket(_ packet: Data) {
    guard !closed else { return }
    statistics.egress += 1
    statistics.egressBytes += packet.count
    guard let meta = buildPacketMeta(packet) else {
      statistics.unrouted += 1
      return
    }
    if meta.protocolNumber == ATrustIpProtocol.tcp,
      routeTable.matchL3(
        destinationAddress: meta.destinationAddress,
        protocolName: "tcp",
        port: meta.destinationPort
      ) == nil,
      shouldTerminate(address: meta.destinationAddress, port: meta.destinationPort)
    {
      if terminator?.accept(packet) ?? false {
        statistics.terminated += 1
        return
      }
    }
    guard
      let route = routeTable.matchL3(
        destinationAddress: meta.destinationAddress,
        protocolName: meta.protocolName,
        port: meta.destinationPort
      )
    else {
      statistics.unrouted += 1
      if statistics.unrouted <= 10 {
        log(
          "packet not routed: \(meta.destinationAddress):\(meta.destinationPort) "
            + "(\(meta.protocolName))"
        )
      }
      return
    }
    statistics.routed += 1
    guard let connection = connections[route.nodeGroupId] ?? connections[plan.majorNodeGroup]
    else {
      // The connection is still coming up; TCP retransmits cover the gap.
      openConnection(for: route.nodeGroupId, completion: nil)
      return
    }
    connection.sendPacket(packet, route: route)
  }

  public func close() {
    guard !closed else { return }
    closed = true
    for task in reconnectTasks.values { task.cancel() }
    reconnectTasks.removeAll()
    terminator?.close()
    terminator = nil
    let live = Array(connections.values)
    connections.removeAll()
    connecting.removeAll()
    for connection in live {
      connection.close()
    }
  }

  /// True when a TCP flow cannot be forwarded as raw IP but the TCP tunnel can
  /// carry it — the case the terminator exists for.
  public func shouldTerminate(address: String, port: Int) -> Bool {
    if routeTable.matchL3(destinationAddress: address, protocolName: "tcp", port: port) != nil {
      return false
    }
    let host = plan.dialHosts[address] ?? address
    return routeTable.matchTcp(destinationHost: host, port: port) != nil
  }

  // MARK: - Connections

  private func deliverIngress(_ packet: Data) {
    guard !closed else { return }
    statistics.ingress += 1
    statistics.ingressBytes += packet.count
    onIngressPacket?(packet)
  }

  private func openConnection(
    for nodeGroupId: String,
    completion: ((Result<ATrustL3Connection, Error>) -> Void)?
  ) {
    if let existing = connections[nodeGroupId], !existing.isClosed {
      completion?(.success(existing))
      return
    }
    if connecting[nodeGroupId] == true {
      completion?(
        .failure(SangforTunnelError.channelClosed("connection already in flight"))
      )
      return
    }
    guard let endpoint = plan.nodeEndpoint(for: nodeGroupId) else {
      let error = SangforTunnelError.invalidPlan(
        "no node endpoint for group \(nodeGroupId)"
      )
      completion?(.failure(error))
      return
    }
    guard let signKey = plan.signKey, !signKey.isEmpty else {
      let error = SangforTunnelError.invalidPlan("no signing key")
      completion?(.failure(error))
      return
    }
    connecting[nodeGroupId] = true
    log("dialing node \(endpoint.host):\(endpoint.port) for group \(nodeGroupId)")
    dialer(endpoint.host, endpoint.port) { [weak self] result in
      guard let self, !self.closed else { return }
      self.connecting[nodeGroupId] = false
      switch result {
      case .failure(let error):
        self.log("node dial failed: \(error)")
        self.scheduleReconnect(nodeGroupId)
        completion?(.failure(error))
      case .success(let channel):
        let connection = ATrustL3Connection(
          channel: channel,
          plan: self.plan,
          scheduler: self.scheduler,
          configuration: self.configuration.connection
        )
        connection.onPacket = { [weak self] packet in
          self?.deliverIngress(packet)
        }
        connection.onVirtualIP = { [weak self] addresses in
          guard let self else { return }
          self.virtualAddresses = addresses
          self.onVirtualIP?(addresses)
        }
        connection.onError = { [weak self] error in
          guard let self else { return }
          self.log("tunnel error: \(error)")
          if self.connections[nodeGroupId] === connection {
            self.connections.removeValue(forKey: nodeGroupId)
          }
          connection.close()
          if (error as? SangforTunnelError)?.isFatalForSession ?? false {
            self.onFatalError?(error)
            return
          }
          self.scheduleReconnect(nodeGroupId)
        }
        connection.start { [weak self] result in
          guard let self else { return }
          switch result {
          case .failure(let error):
            connection.close()
            self.scheduleReconnect(nodeGroupId)
            completion?(.failure(error))
          case .success(let addresses):
            self.connections[nodeGroupId] = connection
            if !addresses.isEmpty {
              self.virtualAddresses = addresses
            }
            completion?(.success(connection))
          }
        }
      }
    }
  }

  private func scheduleReconnect(_ nodeGroupId: String) {
    guard !closed else { return }
    reconnectTasks[nodeGroupId]?.cancel()
    statistics.reconnects += 1
    reconnectTasks[nodeGroupId] = scheduler.schedule(
      after: configuration.reconnectDelay
    ) { [weak self] in
      guard let self, !self.closed else { return }
      self.reconnectTasks.removeValue(forKey: nodeGroupId)
      self.openConnection(for: nodeGroupId, completion: nil)
    }
  }

  /// Dials one TCP tunnel connection for the terminator.
  private func dialTcpTunnel(
    host: String,
    port: Int,
    completion: @escaping (Result<SangforRelayStream, Error>) -> Void
  ) {
    guard let signKey = plan.signKey else {
      completion(.failure(SangforTunnelError.invalidPlan("no signing key")))
      return
    }
    let route = routeTable.matchTcp(
      destinationHost: plan.dialHosts[host] ?? host,
      port: port
    )
    guard let route else {
      completion(
        .failure(
          SangforTunnelError.flowAuthFailed("no TCP tunnel resource for \(host):\(port)")
        )
      )
      return
    }
    guard let endpoint = plan.nodeEndpoint(for: route.nodeGroupId) else {
      completion(
        .failure(
          SangforTunnelError.invalidPlan("no node for group \(route.nodeGroupId)")
        )
      )
      return
    }
    let dialHost = plan.dialHosts[host] ?? host
    let destination = "\(dialHost):\(port)"
    let request = ATrustTcpTunnelAuthRequest(
      sid: plan.sid,
      appId: route.appId,
      url: "tcp://\(destination)",
      deviceId: plan.deviceId,
      connectionId: plan.connectionId,
      procHash: plan.process.fingerprint,
      userName: plan.username,
      lang: plan.lang,
      destAddr: destination,
      // Pretending the address means the gateway resolves the name itself.
      destIp: route.addrPretend ? nil : host,
      process: plan.process
    )
    dialer(endpoint.host, endpoint.port) { [weak self] result in
      guard let self else { return }
      switch result {
      case .failure(let error):
        completion(.failure(error))
      case .success(let channel):
        ATrustTcpTunnelStream.connect(
          channel: channel,
          request: request,
          signKey: signKey,
          host: dialHost,
          port: port,
          scheduler: self.scheduler,
          completion: { streamResult in
            switch streamResult {
            case .failure(let error):
              completion(.failure(error))
            case .success(let stream):
              completion(.success(stream))
            }
          }
        )
      }
    }
  }
}
