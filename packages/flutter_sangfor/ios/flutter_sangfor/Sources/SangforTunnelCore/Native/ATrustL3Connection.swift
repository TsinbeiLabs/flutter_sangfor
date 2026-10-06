import Foundation

/// Errors the tunnel driver reports.
public enum SangforTunnelError: Error, CustomStringConvertible, Equatable {
  /// The gateway rejected the tunnel handshake; the session is gone and the
  /// Runner has to log in again.
  case tunnelAuthFailed(String)
  /// A per-flow authentication failed.
  case flowAuthFailed(String)
  /// A flow never authenticated in time.
  case flowAuthTimeout(String)
  /// The gateway stopped answering heartbeats.
  case heartbeatTimeout(Int)
  /// The transport closed or failed.
  case channelClosed(String)
  /// The session plan could not be used (bad key, no node, ...).
  case invalidPlan(String)

  public var description: String {
    switch self {
    case .tunnelAuthFailed(let detail): "L3 tunnel auth failed: \(detail)"
    case .flowAuthFailed(let detail): "flow auth failed: \(detail)"
    case .flowAuthTimeout(let detail): "flow auth timed out: \(detail)"
    case .heartbeatTimeout(let misses): "heartbeat timed out after \(misses) misses"
    case .channelClosed(let detail): "tunnel channel closed: \(detail)"
    case .invalidPlan(let detail): "invalid session plan: \(detail)"
    }
  }

  /// True when the session itself is unusable and the Runner must re-login.
  public var isFatalForSession: Bool {
    if case .tunnelAuthFailed = self { return true }
    return false
  }
}

/// The five-tuple identity of a flow.
public struct ATrustL3FlowKey: Hashable {
  public let protocolNumber: Int
  public let sourceAddress: String
  public let sourcePort: Int
  public let destinationAddress: String
  public let destinationPort: Int

  public init(
    protocolNumber: Int,
    sourceAddress: String,
    sourcePort: Int,
    destinationAddress: String,
    destinationPort: Int
  ) {
    self.protocolNumber = protocolNumber
    self.sourceAddress = sourceAddress
    self.sourcePort = sourcePort
    self.destinationAddress = destinationAddress
    self.destinationPort = destinationPort
  }

  public var reversed: ATrustL3FlowKey {
    ATrustL3FlowKey(
      protocolNumber: protocolNumber,
      sourceAddress: destinationAddress,
      sourcePort: destinationPort,
      destinationAddress: sourceAddress,
      destinationPort: sourcePort
    )
  }
}

public enum ATrustL3FlowState {
  case pending, authenticated, failed, expired
}

/// One tracked flow: its token, the packets waiting for that token, and the
/// authentication attempt bookkeeping.
public final class ATrustL3Flow {
  public let id: Int
  public let key: ATrustL3FlowKey
  public let appId: String
  public let nodeGroupId: String
  public fileprivate(set) var pendingPackets: [Data] = []
  public var state: ATrustL3FlowState = .pending
  public var token: String?
  public var error: Error?
  public var authRequested = false
  public var authDeadline: Double?
  public var authRetryAt: Double?
  public var authTimeouts = 0
  public var lastSeen: Double
  public var expiresAt: Double

  init(
    id: Int,
    key: ATrustL3FlowKey,
    appId: String,
    nodeGroupId: String,
    now: Double,
    ttl: Double
  ) {
    self.id = id
    self.key = key
    self.appId = appId
    self.nodeGroupId = nodeGroupId
    lastSeen = now
    expiresAt = now + ttl
  }
}

/// Flow table with expiry, mirroring the reference client's conntrack.
public final class ATrustL3FlowTracker {
  public static let tcpEstablishedTTL: Double = 6 * 60 * 60
  public static let udpTTL: Double = 120
  public static let icmpTTL: Double = 30
  public static let defaultTTL: Double = 60

  private var flowsByKey: [ATrustL3FlowKey: ATrustL3Flow] = [:]
  private var nextId = 0

  public let maxFlows: Int
  public let maxPendingPackets: Int
  private let scheduler: SangforScheduler

  public init(
    scheduler: SangforScheduler,
    maxFlows: Int = 4096,
    maxPendingPackets: Int = 512
  ) {
    self.scheduler = scheduler
    self.maxFlows = maxFlows
    self.maxPendingPackets = maxPendingPackets
  }

  public var count: Int { flowsByKey.count }

  public var flows: [ATrustL3Flow] { Array(flowsByKey.values) }

  public func flow(byId id: Int) -> ATrustL3Flow? {
    flowsByKey.values.first { $0.id == id }
  }

  public func getOrCreate(
    _ key: ATrustL3FlowKey,
    appId: String,
    nodeGroupId: String
  ) -> ATrustL3Flow {
    let now = scheduler.now
    removeExpired(now)
    if let existing = flowsByKey[key] {
      existing.lastSeen = now
      return existing
    }
    if flowsByKey.count >= maxFlows,
      let oldest = flowsByKey.values.min(by: { $0.lastSeen < $1.lastSeen })
    {
      oldest.state = .expired
      flowsByKey.removeValue(forKey: oldest.key)
    }
    nextId += 1
    let flow = ATrustL3Flow(
      id: nextId,
      key: key,
      appId: appId,
      nodeGroupId: nodeGroupId,
      now: now,
      ttl: Self.defaultTTL
    )
    flowsByKey[key] = flow
    return flow
  }

  /// Refreshes a flow's expiry from a packet that just travelled.
  public func observe(_ key: ATrustL3FlowKey, packet: Data) {
    guard let flow = flowsByKey[key] else { return }
    let now = scheduler.now
    flow.lastSeen = now
    flow.expiresAt = now + ttl(for: packet)
  }

  private func ttl(for packet: Data) -> Double {
    guard let meta = buildPacketMeta(packet) else { return Self.defaultTTL }
    switch meta.protocolNumber {
    case ATrustIpProtocol.tcp: return Self.tcpEstablishedTTL
    case ATrustIpProtocol.udp: return Self.udpTTL
    case ATrustIpProtocol.icmp: return Self.icmpTTL
    default: return Self.defaultTTL
    }
  }

  /// Queues a packet while its flow is still unauthenticated.
  public func cachePacket(_ flow: ATrustL3Flow, _ packet: Data) -> Bool {
    guard flow.state == .pending,
      flow.pendingPackets.count < maxPendingPackets
    else { return false }
    flow.pendingPackets.append(packet)
    flow.lastSeen = scheduler.now
    return true
  }

  /// Completes a flow, returning the packets that were waiting.
  public func complete(
    _ flowId: Int,
    token: String? = nil,
    error: Error? = nil
  ) -> [Data] {
    guard let flow = flow(byId: flowId), flow.state == .pending else { return [] }
    flow.token = token
    flow.error = error
    flow.state = error == nil ? .authenticated : .failed
    flow.authDeadline = nil
    let packets = flow.pendingPackets
    flow.pendingPackets.removeAll()
    if error != nil {
      flowsByKey.removeValue(forKey: flow.key)
    }
    return packets
  }

  @discardableResult
  public func removeExpired(_ now: Double) -> Int {
    let expired = flowsByKey.values.filter { now > $0.expiresAt }
    for flow in expired {
      flow.state = .expired
      flowsByKey.removeValue(forKey: flow.key)
    }
    return expired.count
  }

  public func removeAll() {
    for flow in flowsByKey.values { flow.state = .expired }
    flowsByKey.removeAll()
  }
}

/// Drives one aTrust L3 tunnel connection: the authTunnel handshake, per-flow
/// authentication, heartbeats, and the inbound packet stream.
///
/// Every method must be called on the same serial queue the channel delivers
/// on; the driver keeps no locks of its own.
public final class ATrustL3Connection {
  /// Tuning knobs, defaulted to the reference client's values.
  public struct Configuration {
    public var heartbeatInterval: Double = 5
    public var heartbeatMissLimit: Int = 3
    public var authTimeout: Double = 5
    public var authScanInterval: Double = 0.25
    public var authRetryWait: Double = 10
    public var authMaxAttempts: Int = 3
    public var authBatchSize: Int = 64
    public var connectTimeout: Double = 10

    public init() {}
  }

  private let channel: SangforByteChannel
  private let plan: ATrustSessionPlan
  private let scheduler: SangforScheduler
  private let configuration: Configuration
  private let tracker: ATrustL3FlowTracker

  private let decoder = ATrustL3FrameStreamDecoder()
  private let handshakeParser = ATrustL3HandshakeParser()
  private var dataStream: [UInt8] = []

  private var handshakeTask: SangforScheduledTask?
  private var authTask: SangforScheduledTask?
  private var heartbeatTask: SangforScheduledTask?
  private var heartbeatMisses = 0
  private var wroteSinceHeartbeat = false
  private var handshook = false
  private var closed = false

  /// Inbound raw IP packets, in arrival order.
  public var onPacket: ((Data) -> Void)?
  /// Virtual-IP updates (initial and 0x96 responses).
  public var onVirtualIP: (([String]) -> Void)?
  /// Fatal errors; the connection closes itself after reporting one.
  public var onError: ((Error) -> Void)?

  public init(
    channel: SangforByteChannel,
    plan: ATrustSessionPlan,
    scheduler: SangforScheduler,
    configuration: Configuration = Configuration()
  ) {
    self.channel = channel
    self.plan = plan
    self.scheduler = scheduler
    self.configuration = configuration
    tracker = ATrustL3FlowTracker(scheduler: scheduler)
  }

  public private(set) var virtualAddresses: [String] = []
  public var isClosed: Bool { closed }
  public var isHandshook: Bool { handshook }

  /// Performs the authTunnel handshake. The completion receives the virtual IP
  /// the gateway assigned, or the failure.
  public func start(completion: @escaping (Result<[String], Error>) -> Void) {
    guard let signKey = plan.signKey, !signKey.isEmpty else {
      completion(.failure(SangforTunnelError.invalidPlan("no signing key")))
      return
    }
    var finished = false
    channel.onData = { [weak self] chunk in
      guard let self, !self.closed else { return }
      guard !self.handshook else {
        self.handleChannelData(chunk)
        return
      }
      do {
        guard let parsed = try self.handshakeParser.add(chunk) else { return }
        self.handshook = true
        self.handshakeTask?.cancel()
        self.handshakeTask = nil
        let addresses = parsed.0.virtualIP
        self.virtualAddresses = addresses
        if !addresses.isEmpty { self.onVirtualIP?(addresses) }
        if !parsed.1.isEmpty { self.handleChannelData(parsed.1) }
        self.startBackgroundLoops()
        if !finished {
          finished = true
          completion(.success(addresses))
        }
      } catch {
        // A gateway that answers the handshake with a refusal has dropped the
        // session; any other failure here is the transport misbehaving.
        let failure: Error = (error as? SangforProtocolError).flatMap { protocolError in
          if case .invalidStatus = protocolError {
            return SangforTunnelError.tunnelAuthFailed("\(protocolError)")
          }
          return nil
        } ?? error
        self.fail(failure)
        if !finished {
          finished = true
          completion(.failure(failure))
        }
      }
    }
    channel.onClosed = { [weak self] error in
      guard let self, !self.closed else { return }
      let failure = SangforTunnelError.channelClosed(error?.localizedDescription ?? "peer hung up")
      if !finished {
        finished = true
        completion(.failure(failure))
      }
      self.fail(failure)
    }

    do {
      try write(ATrustL3Protocol.authTunnelRequest(sid: plan.sid))
    } catch {
      finished = true
      completion(.failure(error))
      fail(error)
      return
    }
    handshakeTask = scheduler.schedule(after: configuration.connectTimeout) {
      [weak self] in
      guard let self, !self.handshook, !self.closed else { return }
      let failure = SangforTunnelError.channelClosed("handshake timed out")
      if !finished {
        finished = true
        completion(.failure(failure))
      }
      self.fail(failure)
    }
  }

  private func startBackgroundLoops() {
    authTask = scheduler.scheduleRepeating(
      every: configuration.authScanInterval
    ) { [weak self] in
      guard let self, !self.closed else { return }
      self.tracker.removeExpired(self.scheduler.now)
      self.expireAuthentications()
      self.dispatchPendingAuthentications()
    }
    heartbeatTask = scheduler.scheduleRepeating(
      every: configuration.heartbeatInterval
    ) { [weak self] in
      guard let self, !self.closed else { return }
      self.onHeartbeatTick()
    }
  }

  /// Routes one raw IP packet, authenticating its flow first if needed.
  /// Returns false when no resource covers the packet.
  public func sendPacket(
    _ packet: Data,
    route: ATrustRoute
  ) {
    guard !closed, handshook else { return }
    guard let meta = buildPacketMeta(packet) else { return }
    let key = ATrustL3FlowKey(
      protocolNumber: meta.protocolNumber,
      sourceAddress: meta.sourceAddress,
      sourcePort: meta.sourcePort,
      destinationAddress: meta.destinationAddress,
      destinationPort: meta.destinationPort
    )
    let flow = tracker.getOrCreate(
      key,
      appId: route.appId,
      nodeGroupId: route.nodeGroupId
    )
    tracker.observe(key, packet: packet)
    if flow.state == .authenticated, let token = flow.token {
      writeData(token: token, packet: packet)
      return
    }
    guard flow.state == .pending else { return }
    guard tracker.cachePacket(flow, packet) else { return }
    dispatchPendingAuthentications()
  }

  public func close() {
    guard !closed else { return }
    closed = true
    handshakeTask?.cancel()
    authTask?.cancel()
    heartbeatTask?.cancel()
    handshakeTask = nil
    authTask = nil
    heartbeatTask = nil
    channel.onData = nil
    channel.onClosed = nil
    channel.close()
    tracker.removeAll()
    dataStream.removeAll()
  }

  // MARK: - Inbound

  private func handleChannelData(_ chunk: Data) {
    let frames: [ATrustL3Frame]
    do {
      frames = try decoder.add(chunk)
    } catch {
      fail(error)
      return
    }
    for frame in frames {
      handle(frame)
    }
  }

  private func handle(_ frame: ATrustL3Frame) {
    switch frame.command {
    case .dataResponse:
      dataStream.append(contentsOf: frame.payload)
      do {
        let split = try ATrustPacketCodec.splitIncomingIPPackets(dataStream)
        dataStream = split.remaining
        for packet in split.packets {
          if let meta = buildPacketMeta(packet) {
            tracker.observe(meta.reversedFlowKeyTuple, packet: packet)
          }
          onPacket?(packet)
        }
      } catch {
        // A malformed stream would desynchronize forever; drop it and keep the
        // connection alive so the next data frame can resynchronize.
        dataStream.removeAll()
        onError?(error)
      }
    case .authResponse:
      handleAuthResponse(frame)
    case .secondVipResponse:
      if frame.status == 0 {
        let addresses = ATrustL3Protocol.extractVIPs(frame.payload)
        if !addresses.isEmpty {
          virtualAddresses = addresses
          onVirtualIP?(addresses)
        }
      }
    case .heartbeatResponse:
      heartbeatMisses = 0
    default:
      break
    }
  }

  private func handleAuthResponse(_ frame: ATrustL3Frame) {
    guard let object = SangforJsonObject.parse(frame.payload) else { return }
    let data = object.object("data")
    let conntrackHash = data?.int("conntrackHash")
    var flow = conntrackHash.flatMap { tracker.flow(byId: $0) }
    if flow == nil, let ip = data?.object("ip") {
      flow = findFlow(byIpInfo: ip)
    }
    guard let flow else { return }
    if frame.status == 0x84 {
      retryAuthentication(flow, after: 0)
      return
    }
    if (0x85...0x87).contains(frame.status) {
      retryAuthentication(flow, after: configuration.authRetryWait)
      return
    }
    if frame.status != 0 {
      let packets = tracker.complete(
        flow.id,
        error: SangforTunnelError.flowAuthFailed("status \(frame.status)")
      )
      _ = packets
      return
    }
    let code = data?.int("code") ?? object.int("code") ?? 0
    if code != 0 {
      let message = data?.string("message") ?? object.string("message") ?? ""
      _ = tracker.complete(
        flow.id,
        error: SangforTunnelError.flowAuthFailed("code \(code): \(message)")
      )
      return
    }
    let token = data?.string("connectToken") ?? ""
    let packets = tracker.complete(flow.id, token: token)
    for packet in packets {
      writeData(token: token, packet: packet)
    }
  }

  private func findFlow(byIpInfo ip: SangforJsonObject) -> ATrustL3Flow? {
    guard
      let sourceAddress = ip.string("srcAddr"),
      let destinationAddress = ip.string("destAddr")
    else { return nil }
    let sourcePort = ip.int("srcPort")
    let destinationPort = ip.int("destPort")
    let protocolNumber = ip.int("protocol")
    if let atype = ip.int("atype"), atype != 0x0800 { return nil }
    return tracker.flows.first { flow in
      guard flow.key.sourceAddress == sourceAddress,
        flow.key.destinationAddress == destinationAddress
      else { return false }
      if let sourcePort, flow.key.sourcePort != sourcePort { return false }
      if let destinationPort, flow.key.destinationPort != destinationPort {
        return false
      }
      if let protocolNumber, flow.key.protocolNumber != protocolNumber {
        return false
      }
      return true
    }
  }

  private func retryAuthentication(_ flow: ATrustL3Flow, after delay: Double) {
    guard flow.state == .pending else { return }
    flow.authRequested = false
    flow.authDeadline = nil
    flow.authRetryAt = scheduler.now + delay
  }

  private func expireAuthentications() {
    let now = scheduler.now
    for flow in tracker.flows {
      guard let deadline = flow.authDeadline, now >= deadline else { continue }
      flow.authTimeouts += 1
      if flow.authTimeouts < configuration.authMaxAttempts {
        flow.authRequested = false
        flow.authDeadline = nil
        flow.authRetryAt = now
      } else {
        _ = tracker.complete(
          flow.id,
          error: SangforTunnelError.flowAuthTimeout(flow.key.flowKeyText)
        )
      }
    }
  }

  private func dispatchPendingAuthentications() {
    var dispatched = 0
    let now = scheduler.now
    for flow in tracker.flows {
      if dispatched >= configuration.authBatchSize { break }
      if flow.pendingPackets.isEmpty || flow.authRequested { continue }
      if let retryAt = flow.authRetryAt, now < retryAt { continue }
      flow.authRequested = true
      flow.authDeadline = now + configuration.authTimeout
      let request = ATrustL3AuthRequest(
        sid: plan.sid,
        appId: flow.appId,
        url: "\(flow.key.protocolNameForUrl):\(flow.key.destinationAddress):\(flow.key.destinationPort)",
        deviceId: plan.deviceId,
        connectionId: plan.connectionId,
        lang: plan.lang,
        conntrackHash: flow.id,
        ip: ATrustL3IpInfo(
          atype: 0x0800,
          protocolNumber: flow.key.protocolNumber,
          destinationAddress: flow.key.destinationAddress,
          destinationPort: flow.key.destinationPort,
          sourceAddress: flow.key.sourceAddress,
          sourcePort: flow.key.sourcePort
        ),
        env: plan.process
      )
      do {
        guard let signKey = plan.signKey else {
          throw SangforTunnelError.invalidPlan("no signing key")
        }
        try write(ATrustL3Protocol.authRequestFrame(request, signKey: signKey))
        dispatched += 1
      } catch {
        fail(error)
        return
      }
    }
  }

  // MARK: - Outbound

  private func writeData(token: String, packet: Data) {
    do {
      try write(ATrustL3Protocol.dataRequest(token: token, packet: packet))
    } catch {
      fail(error)
    }
  }

  private func write(_ frame: Data) throws {
    guard !closed else { throw SangforTunnelError.channelClosed("closed") }
    channel.send(frame)
    wroteSinceHeartbeat = true
  }

  private func onHeartbeatTick() {
    tracker.removeExpired(scheduler.now)
    if wroteSinceHeartbeat {
      wroteSinceHeartbeat = false
      heartbeatMisses = 0
      return
    }
    if heartbeatMisses >= configuration.heartbeatMissLimit {
      fail(SangforTunnelError.heartbeatTimeout(heartbeatMisses))
      return
    }
    heartbeatMisses += 1
    guard !closed else { return }
    channel.send(ATrustL3Protocol.heartbeatRequest())
  }

  private func fail(_ error: Error) {
    guard !closed else { return }
    close()
    onError?(error)
  }
}

extension ATrustL3FlowKey {
  /// The protocol name used in the `url` field of an auth request.
  var protocolNameForUrl: String {
    switch protocolNumber {
    case ATrustIpProtocol.tcp: "tcp"
    case ATrustIpProtocol.udp: "udp"
    case ATrustIpProtocol.icmp: "icmp"
    case ATrustIpProtocol.icmp6: "icmp6"
    default: "ip"
    }
  }

  var flowKeyText: String {
    "\(protocolNameForUrl):\(sourceAddress):\(sourcePort)"
      + "-\(destinationAddress):\(destinationPort)"
  }
}

extension ATrustPacketMeta {
  /// The flow key of the *reverse* direction, as a tracker lookup key.
  var reversedFlowKeyTuple: ATrustL3FlowKey {
    ATrustL3FlowKey(
      protocolNumber: protocolNumber,
      sourceAddress: destinationAddress,
      sourcePort: destinationPort,
      destinationAddress: sourceAddress,
      destinationPort: sourcePort
    )
  }
}
