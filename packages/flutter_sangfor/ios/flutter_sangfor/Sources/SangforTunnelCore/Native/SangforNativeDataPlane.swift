import Foundation

/// Opens a connection to `host:port` from outside the tunnel, for a flow the
/// tunnel was never meant to carry. The completion must be called on the data
/// plane's queue.
public typealias SangforDirectDialer =
  (
    _ host: String, _ port: Int,
    _ completion: @escaping (Result<SangforRelayStream, Error>) -> Void
  ) -> Void

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
    public var direct = 0
    public var egressBytes = 0
    public var ingressBytes = 0
    public var reconnects = 0

    public var description: String {
      "egress=\(egress) routed=\(routed) terminated=\(terminated) "
        + "direct=\(direct) unrouted=\(unrouted) ingress=\(ingress) "
        + "reconnects=\(reconnects)"
    }
  }

  public struct Configuration {
    /// Delay before a dropped node connection is retried.
    public var reconnectDelay: Double = 5
    /// Flow-auth and heartbeat tuning handed to each L3 connection.
    public var connection = ATrustL3Connection.Configuration()
    /// Terminator tuning.
    public var terminator = ATrustTcpTerminator.Configuration()
    /// Carries a flow outside the tunnel. Without one, a flow the plan routes
    /// only because a host name resolved to its address, and that no resource
    /// covers, is dropped.
    public var directDialer: SangforDirectDialer?

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
  /// Consecutive handshakes the gateway refused, per node group. One refusal can
  /// be a busy node; the second in a row means the session is gone.
  private var refusedHandshakes: [String: Int] = [:]
  private var terminator: ATrustTcpTerminator?
  private var closed = false
  /// How many successful dials are still logged; failures always are.
  private var dialLogBudget = 40
  private var flowLogBudget = 80

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
      dialHostResolver: { [weak self] address, port in
        self?.plan.dialHost(for: address, port: port)
      },
      scheduler: scheduler,
      configuration: terminatorConfiguration,
      flowSniffer: makeFlowSniffer(),
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
    // With a way out of the tunnel, every flow to a pre-resolved address is
    // terminated and decided by the name it turns out to want (see
    // [makeFlowSniffer]).
    if configuration.directDialer != nil, isPreResolved(address) { return true }
    let host = plan.dialHost(for: address, port: port) ?? address
    return routeTable.matchTcp(destinationHost: host, port: port) != nil
  }

  /// True for an address the plan routes only because a published host name
  /// resolved to it. A route cannot tell one name or port from another, so
  /// everything else behind that address (other names on a shared front end,
  /// other ports) is pulled into the tunnel with the published name.
  private func isPreResolved(_ address: String) -> Bool {
    plan.dialHosts[address] != nil || plan.dialHostAliases?[address] != nil
  }

  /// Routes a flow to a pre-resolved address by the host name its first bytes
  /// name -- the SNI of a TLS handshake, the `Host` of an HTTP request -- since
  /// the address cannot say which of several names the client wants. A name a
  /// resource covers on that port goes through the tunnel, dialed by that name;
  /// any other goes out directly, as it would have without the tunnel. When
  /// nothing names a host, the address's own name decides.
  private func makeFlowSniffer() -> ATrustTcpTerminator.FlowSniffer? {
    guard configuration.directDialer != nil else { return nil }
    return ATrustTcpTerminator.FlowSniffer(
      wants: { [weak self] address, port in
        guard let self else { return false }
        return self.isPreResolved(address)
          && self.routeTable.matchL3(destinationAddress: address, protocolName: "tcp", port: port) == nil
      },
      resolve: { [weak self] address, port, name in
        guard let self else { return nil }
        let chosen: String?
        if let name {
          chosen = self.routeTable.matchTcp(destinationHost: name, port: port) != nil ? name : nil
        } else if let host = self.plan.dialHost(for: address, port: port),
          self.routeTable.matchTcp(destinationHost: host, port: port) != nil
        {
          chosen = host
        } else {
          chosen = nil
        }
        self.logFlowDecision(
          "flow \(address):\(port) names \(name ?? "nobody") -> "
            + (chosen.map { "tunnel as \($0)" } ?? "direct")
        )
        return chosen
      },
      directDialer: { [weak self] address, port, completion in
        guard let self, let direct = self.configuration.directDialer else {
          completion(.failure(SangforTunnelError.channelClosed("the tunnel is closed")))
          return
        }
        self.statistics.direct += 1
        direct(address, port) { [weak self] result in
          switch result {
          case .success:
            self?.logFlowDecision("direct connection to \(address):\(port) is up")
          case .failure(let error):
            self?.log("direct connection to \(address):\(port) failed: \(error)")
          }
          completion(result)
        }
      }
    )
  }

  /// Logs where a sniffed flow went, for the first few dozen: a busy page opens
  /// many connections and the decision is the same each time.
  private func logFlowDecision(_ message: String) {
    guard flowLogBudget > 0 else { return }
    flowLogBudget -= 1
    log(message)
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
          connection.close()
          // A connection that never finished its handshake is not in
          // `connections`: its failure is reported once, through `start`'s
          // completion below, which also decides whether to retry.
          guard self.connections[nodeGroupId] === connection else { return }
          self.connections.removeValue(forKey: nodeGroupId)
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
            if (error as? SangforTunnelError)?.isFatalForSession ?? false {
              let refused = (self.refusedHandshakes[nodeGroupId] ?? 0) + 1
              self.refusedHandshakes[nodeGroupId] = refused
              // The first attempt, the one starting the tunnel, reports it to its
              // caller; a reconnect has no caller, so the second refusal in a row
              // is reported as fatal and the reconnecting stops.
              if completion == nil && refused >= 2 {
                self.log("the gateway refused the session twice: \(error)")
                self.onFatalError?(error)
                return
              }
              if completion != nil {
                completion?(.failure(error))
                return
              }
            }
            self.scheduleReconnect(nodeGroupId)
            completion?(.failure(error))
          case .success(let addresses):
            self.refusedHandshakes[nodeGroupId] = nil
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

  /// Dials one TCP tunnel connection for the extension's HTTP proxy.
  ///
  /// The proxy hands over the host name the client asked for, which is what the
  /// gateway authorizes: a request naming the host and carrying no `destIP` is
  /// accepted for resources published with and without `addrPretend`.
  public func dialTcpTunnelForProxy(
    host: String,
    port: Int,
    completion: @escaping (Result<SangforRelayStream, Error>) -> Void
  ) {
    dialTcpTunnel(host: host.lowercased(), port: port, completion: completion)
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
    // An address is sent only when the destination *is* an address, and the
    // resource is one the gateway does not resolve itself. A flow to a host
    // name carries none: the gateway authorizes the name, and refuses a request
    // that also carries an address (closing the connection during the handshake
    // when the "address" is a name, as the terminator used to send, or with
    // `tcp tunnel connection not allowed` when it is the address the name
    // resolves to here). Measured against the WHU gateway, 2026-10-06.
    let destinationIp: String? =
      !route.addrPretend && SangforAddressBytes.ipv4(dialHost) != nil ? dialHost : nil
    // What a failed (or one of the first successful) dials was about, so a
    // refusal can be told apart by host, address and resource flag.
    let description =
      "\(destination) destIP=\(destinationIp ?? "none") "
      + "pretend=\(route.addrPretend) app=\(route.appId.prefix(8))"
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
      // Only a resource the gateway does not resolve itself takes an address,
      // and it has to be an address: a host name here is refused.
      destIp: destinationIp,
      process: plan.process
    )
    dialer(endpoint.host, endpoint.port) { [weak self] result in
      guard let self else { return }
      switch result {
      case .failure(let error):
        self.log("tcp tunnel node dial failed: \(description): \(error)")
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
              self.log("tcp tunnel refused: \(description): \(error)")
              completion(.failure(error))
            case .success(let stream):
              if self.dialLogBudget > 0 {
                self.dialLogBudget -= 1
                self.log("tcp tunnel dial ok: \(description)")
              }
              completion(.success(stream))
            }
          }
        )
      }
    }
  }
}
