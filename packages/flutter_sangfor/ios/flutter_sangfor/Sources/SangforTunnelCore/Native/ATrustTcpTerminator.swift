import Foundation

/// A byte stream that can be half-closed, as the TCP tunnel connections can.
public protocol SangforRelayStream: AnyObject {
  var isClosed: Bool { get }
  var onData: ((Data) -> Void)? { get set }
  var onClosed: ((Error?) -> Void)? { get set }
  func send(_ data: Data)
  /// Signals end-of-stream upstream without tearing the connection down.
  func closeWrite()
  /// Stops or resumes delivering [onData]; used for backpressure.
  func setReadsPaused(_ paused: Bool)
  func close()
}

/// Terminates TCP connections that arrive as raw IP packets and relays their
/// payload through a byte-stream dialer (RFC 793, server role).
///
/// Gateways publish most resources for the TCP tunnel only, so the L3 plane
/// refuses those flows and a packet device would drop their SYNs silently. The
/// terminator completes the handshake locally, dials the real destination
/// through the tunnel, and copies bytes in both directions.
///
/// Deliberately minimal, like the Dart reference: no window scaling, no SACK,
/// no timestamps, and out-of-order segments get a duplicate ACK so the peer
/// retransmits.
public final class ATrustTcpTerminator {
  public struct Configuration {
    public var maximumSegmentSize = 1400
    public var advertisedWindow = 65535
    public var dialTimeout: Double = 20
    public var idleTimeout: Double = 300
    public var initialRetransmitTimeout: Double = 0.3
    public var maximumRetransmitTimeout: Double = 8
    public var maximumRetransmits = 8
    public var pauseUpstreamAt = 512 * 1024
    public var resumeUpstreamAt = 128 * 1024

    public init() {}
  }

  /// Opens the upstream for one terminated flow. [host] is the name to dial
  /// (the host name the resource was published under when there is one);
  /// [resolvedAddress] is the IPv4 address the client actually connected to,
  /// which a gateway that does not resolve names itself (`addrPretend == false`)
  /// has to be given.
  public typealias Dialer =
    (
      _ host: String, _ port: Int, _ resolvedAddress: String,
      _ completion: @escaping (Result<SangforRelayStream, Error>) -> Void
    ) -> Void
  public typealias TerminationFilter = (_ destinationAddress: String, _ destinationPort: Int) -> Bool
  public typealias DialHostResolver = (_ destinationAddress: String, _ destinationPort: Int) -> String?

  fileprivate let dial: Dialer
  private let shouldTerminate: TerminationFilter
  fileprivate let resolveDialHost: DialHostResolver?
  fileprivate let scheduler: SangforScheduler
  fileprivate let configuration: Configuration
  private let onError: ((Error) -> Void)?

  private var connections: [String: TerminatedConnection] = [:]
  private var identification: Int
  private var closed = false

  /// Synthesized packets, to be written into the packet flow.
  public var onPacket: ((Data) -> Void)?

  public init(
    dialer: @escaping Dialer,
    shouldTerminate: @escaping TerminationFilter,
    dialHostResolver: DialHostResolver? = nil,
    scheduler: SangforScheduler,
    configuration: Configuration = Configuration(),
    randomSeed: Int = 0x5eed,
    onError: ((Error) -> Void)? = nil
  ) {
    dial = dialer
    self.shouldTerminate = shouldTerminate
    resolveDialHost = dialHostResolver
    self.scheduler = scheduler
    self.configuration = configuration
    self.onError = onError
    var generator = SplitMix64(seed: UInt64(bitPattern: Int64(randomSeed)))
    identification = Int(generator.next() % 0xffff)
    self.generator = generator
  }

  private var generator: SplitMix64

  public var connectionCount: Int { connections.count }
  public var isClosed: Bool { closed }

  /// Consumes one raw IP packet. Returns true when the terminator claimed it.
  public func accept(_ packet: Data) -> Bool {
    guard !closed else { return false }
    guard let ip = ATrustIPv4Packet(packet),
      ip.protocolNumber == ATrustIpProtocol.tcp,
      let tcp = ATrustTcpSegmentHeader(ip.payload)
    else { return false }
    let key = TerminatedConnection.key(
      clientAddress: ip.sourceAddress,
      clientPort: tcp.sourcePort,
      serverAddress: ip.destinationAddress,
      serverPort: tcp.destinationPort
    )
    if let existing = connections[key] {
      existing.handle(ip: ip, tcp: tcp)
      return true
    }
    let reversedKey = TerminatedConnection.key(
      clientAddress: ip.destinationAddress,
      clientPort: tcp.destinationPort,
      serverAddress: ip.sourceAddress,
      serverPort: tcp.sourcePort
    )
    if connections[reversedKey] != nil {
      // An echo of a packet we synthesized; never hand it to the tunnel.
      return true
    }
    let isSyn = tcp.flags & ATrustTcpFlag.syn != 0
    let isAck = tcp.flags & ATrustTcpFlag.ack != 0
    guard isSyn, !isAck else { return false }
    guard shouldTerminate(ip.destinationAddress, tcp.destinationPort) else {
      return false
    }
    let connection = TerminatedConnection(
      terminator: self,
      key: key,
      clientAddress: ip.sourceAddress,
      clientPort: tcp.sourcePort,
      serverAddress: ip.destinationAddress,
      serverPort: tcp.destinationPort
    )
    connections[key] = connection
    connection.start(tcp: tcp)
    return true
  }

  public func close() {
    guard !closed else { return }
    closed = true
    let live = Array(connections.values)
    connections.removeAll()
    for connection in live {
      connection.abort()
    }
  }

  // MARK: - Internals used by TerminatedConnection

  func emit(_ packet: Data) {
    guard !closed else { return }
    onPacket?(packet)
  }

  func report(_ error: Error) {
    guard !closed else { return }
    onError?(error)
  }

  func remove(_ connection: TerminatedConnection) {
    if connections[connection.key] === connection {
      connections.removeValue(forKey: connection.key)
    }
  }

  func nextIdentification() -> Int {
    identification = (identification + 1) & 0xffff
    return identification
  }

  func nextInitialSequence() -> Int {
    Int(generator.next() % 0x7fff_ffff)
  }
}

/// A deterministic PRNG so tests can pin the initial sequence numbers.
struct SplitMix64 {
  private var state: UInt64

  init(seed: UInt64) { state = seed }

  mutating func next() -> UInt64 {
    state = state &+ 0x9e37_79b9_7f4a_7c15
    var z = state
    z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
    z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
    return z ^ (z >> 31)
  }
}

/// One terminated TCP connection.
final class TerminatedConnection {
  enum State { case synReceived, established, inboundClosed, outboundClosed, closed }

  struct Unacknowledged {
    let packet: Data
    let sequenceNumber: Int
    /// Sequence space consumed: one for a bare SYN/FIN, the payload length
    /// otherwise.
    let length: Int
  }

  let key: String
  let clientAddress: String
  let clientPort: Int
  let serverAddress: String
  let serverPort: Int

  private weak var terminator: ATrustTcpTerminator?
  private var unacknowledged: [Unacknowledged] = []
  private var sendQueue: [UInt8] = []
  private var pendingForUpstream: [UInt8] = []

  private var upstream: SangforRelayStream?
  private var retransmitTask: SangforScheduledTask?
  private var idleTask: SangforScheduledTask?
  private var retransmitTimeout: Double
  private var retransmits = 0

  private var clientInitialSequence = 0
  private var ourInitialSequence = 0
  private var receiveNext = 0
  private var sendNext = 0
  private var sendUnacknowledged = 0
  private var peerWindow = 0
  private var maximumSegmentSize = 1400
  private var handshakeComplete = false
  private var upstreamDone = false
  private var inboundClosed = false
  private var upstreamPaused = false
  private var finSent = false
  private var disposed = false
  private var state: State = .synReceived

  init(
    terminator: ATrustTcpTerminator,
    key: String,
    clientAddress: String,
    clientPort: Int,
    serverAddress: String,
    serverPort: Int
  ) {
    self.terminator = terminator
    self.key = key
    self.clientAddress = clientAddress
    self.clientPort = clientPort
    self.serverAddress = serverAddress
    self.serverPort = serverPort
    retransmitTimeout = terminator.configuration.initialRetransmitTimeout
  }

  static func key(
    clientAddress: String,
    clientPort: Int,
    serverAddress: String,
    serverPort: Int
  ) -> String {
    "\(clientAddress):\(clientPort)-\(serverAddress):\(serverPort)"
  }

  private var configuration: ATrustTcpTerminator.Configuration {
    terminator?.configuration ?? ATrustTcpTerminator.Configuration()
  }

  // MARK: - Lifecycle

  func start(tcp: ATrustTcpSegmentHeader) {
    guard let terminator else { return }
    clientInitialSequence = tcp.sequenceNumber
    receiveNext = tcpSequenceAdd(clientInitialSequence, 1)
    ourInitialSequence = terminator.nextInitialSequence()
    sendNext = tcpSequenceAdd(ourInitialSequence, 1)
    sendUnacknowledged = ourInitialSequence
    peerWindow = tcp.window
    let offered = tcp.maximumSegmentSize
    maximumSegmentSize = offered == 0
      ? terminator.configuration.maximumSegmentSize
      : min(offered, terminator.configuration.maximumSegmentSize)
    retransmitTimeout = terminator.configuration.initialRetransmitTimeout
    transmit(
      flags: ATrustTcpFlag.syn | ATrustTcpFlag.ack,
      sequenceLength: 1,
      mss: maximumSegmentSize,
      sequenceOverride: ourInitialSequence
    )
    armIdleTimer()
    openUpstream()
  }

  func abort() {
    dispose(reset: false)
  }

  func handle(ip: ATrustIPv4Packet, tcp: ATrustTcpSegmentHeader) {
    guard !disposed else { return }
    armIdleTimer()
    if tcp.flags & ATrustTcpFlag.rst != 0 {
      dispose(reset: false)
      return
    }
    peerWindow = tcp.window
    if tcp.flags & ATrustTcpFlag.ack != 0 {
      acknowledge(tcp.acknowledgmentNumber)
    }
    if state == .synReceived {
      guard handshakeComplete else { return }
      state = .established
    }
    if tcp.flags & ATrustTcpFlag.syn != 0 {
      // A retransmitted SYN: answer with the current state, keep the flow.
      sendAck()
      return
    }
    let payload = tcp.payload
    if !payload.isEmpty {
      acceptPayload(sequence: tcp.sequenceNumber, payload: payload)
    }
    if tcp.flags & ATrustTcpFlag.fin != 0 {
      receiveNext = tcpSequenceAdd(receiveNext, 1)
      sendAck()
      // The inbound half closes whatever the outbound half is doing: our own
      // FIN may already be out, and the dial may still be in flight.
      if !inboundClosed {
        inboundClosed = true
        if let upstream {
          upstream.closeWrite()
        }
      }
      if state == .established {
        state = .inboundClosed
      }
    }
    flush()
    maybeFinish()
  }

  private func acceptPayload(sequence: Int, payload: [UInt8]) {
    let gap = tcpSequenceDifference(sequence, receiveNext)
    if gap > 0 {
      // A hole: drop it and repeat the ACK so the peer retransmits.
      sendAck()
      return
    }
    let overlap = -gap
    if overlap >= payload.count {
      sendAck()
      return
    }
    let fresh = overlap == 0 ? payload : Array(payload[overlap...])
    receiveNext = tcpSequenceAdd(receiveNext, fresh.count)
    sendAck()
    guard let upstream, !upstream.isClosed else {
      // The dial is still in flight; only the first flight can land here.
      pendingForUpstream.append(contentsOf: fresh)
      return
    }
    upstream.send(Data(fresh))
  }

  private func openUpstream() {
    guard let terminator else { return }
    let host = terminator.resolveDialHost?(serverAddress, serverPort) ?? serverAddress
    terminator.dial(host, serverPort, serverAddress) { [weak self] result in
      guard let self, !self.disposed else { return }
      switch result {
      case .failure(let error):
        terminator.report(error)
        // Nothing can be relayed, so the local stack must be told.
        self.dispose(reset: true)
      case .success(let stream):
        self.attachUpstream(stream)
      }
    }
  }

  private func attachUpstream(_ stream: SangforRelayStream) {
    upstream = stream
    stream.onData = { [weak self] chunk in
      guard let self, !self.disposed else { return }
      self.sendQueue.append(contentsOf: chunk)
      self.flush()
      if self.sendQueue.count >= self.configuration.pauseUpstreamAt,
        !self.upstreamPaused
      {
        self.upstreamPaused = true
        stream.setReadsPaused(true)
      }
    }
    stream.onClosed = { [weak self] error in
      guard let self, !self.disposed else { return }
      if let error { self.terminator?.report(error) }
      self.upstreamDone = true
      self.flush()
      self.maybeFinish()
      if error != nil { self.dispose(reset: true) }
    }
    if !pendingForUpstream.isEmpty {
      stream.send(Data(pendingForUpstream))
      pendingForUpstream.removeAll()
    }
    if state == .inboundClosed {
      stream.closeWrite()
    }
    flush()
  }

  private func maybeFinish() {
    guard !disposed, !finSent, upstreamDone else { return }
    guard sendQueue.isEmpty, unacknowledged.isEmpty else { return }
    guard state != .closed else { return }
    transmit(flags: ATrustTcpFlag.fin | ATrustTcpFlag.ack, sequenceLength: 1)
    finSent = true
    state = .outboundClosed
  }

  private func maybeDisposeAfterFin() {
    guard !disposed, finSent, unacknowledged.isEmpty else { return }
    dispose(reset: false)
  }

  // MARK: - Sending

  private func flush() {
    guard !disposed, handshakeComplete else { return }
    while !sendQueue.isEmpty {
      let inFlight = tcpSequenceDifference(sendUnacknowledged, sendNext)
      let available = peerWindow - inFlight
      if available <= 0 { break }
      let limit = min(available, maximumSegmentSize)
      let payload = Array(sendQueue.prefix(limit))
      sendQueue.removeFirst(payload.count)
      transmit(
        flags: ATrustTcpFlag.ack | ATrustTcpFlag.psh,
        payload: payload,
        sequenceLength: payload.count
      )
    }
    if sendQueue.count < configuration.resumeUpstreamAt, upstreamPaused {
      upstreamPaused = false
      upstream?.setReadsPaused(false)
    }
    armRetransmitTimer()
    if upstreamDone { maybeFinish() }
  }

  private func sendAck() {
    guard !disposed, handshakeComplete, let terminator else { return }
    terminator.emit(
      buildPacket(flags: ATrustTcpFlag.ack, payload: [], mss: nil)
    )
  }

  private func transmit(
    flags: UInt8,
    payload: [UInt8] = [],
    sequenceLength: Int,
    mss: Int? = nil,
    sequenceOverride: Int? = nil
  ) {
    guard let terminator else { return }
    let sequence = sequenceOverride ?? sendNext
    let packet = buildPacket(
      flags: flags,
      payload: payload,
      mss: mss,
      sequenceOverride: sequence
    )
    if sequenceOverride == nil {
      sendNext = tcpSequenceAdd(sendNext, sequenceLength)
    }
    unacknowledged.append(
      Unacknowledged(
        packet: packet,
        sequenceNumber: sequence,
        length: sequenceLength
      )
    )
    terminator.emit(packet)
    armRetransmitTimer()
  }

  private func buildPacket(
    flags: UInt8,
    payload: [UInt8],
    mss: Int?,
    sequenceOverride: Int? = nil
  ) -> Data {
    let packet = (try? ATrustPacketCodec.buildTcp(
      sourceAddress: serverAddress,
      destinationAddress: clientAddress,
      sourcePort: serverPort,
      destinationPort: clientPort,
      sequenceNumber: sequenceOverride ?? sendNext,
      acknowledgmentNumber: receiveNext,
      flags: flags,
      window: configuration.advertisedWindow,
      payload: payload,
      mss: mss,
      identification: terminator?.nextIdentification() ?? 0
    )) ?? Data()
    return packet
  }

  private func acknowledge(_ acknowledgment: Int) {
    if tcpSequenceDifference(sendUnacknowledged, acknowledgment) < 0 {
      // Already acknowledged, or a duplicate ACK.
      maybeFinish()
      return
    }
    if tcpSequenceDifference(sendNext, acknowledgment) > 0 {
      // Beyond anything we sent: ignore instead of trusting a bogus ACK.
      return
    }
    var advanced = false
    while let oldest = unacknowledged.first {
      let end = tcpSequenceAdd(oldest.sequenceNumber, oldest.length)
      // Stop at the first segment this ACK does not fully cover.
      if tcpSequenceDifference(acknowledgment, end) > 0 { break }
      unacknowledged.removeFirst()
      sendUnacknowledged = end
      advanced = true
    }
    if advanced {
      retransmits = 0
      retransmitTimeout = configuration.initialRetransmitTimeout
    }
    if !handshakeComplete,
      tcpSequenceDifference(sendUnacknowledged, tcpSequenceAdd(ourInitialSequence, 1)) >= 0
    {
      handshakeComplete = true
    }
    maybeDisposeAfterFin()
    flush()
  }

  // MARK: - Timers

  private func armRetransmitTimer() {
    guard !disposed, let scheduler = terminator?.scheduler else { return }
    if unacknowledged.isEmpty {
      retransmitTask?.cancel()
      retransmitTask = nil
      return
    }
    guard retransmitTask == nil else { return }
    retransmitTask = scheduler.schedule(after: retransmitTimeout) {
      [weak self] in
      self?.onRetransmitTimeout()
    }
  }

  private func onRetransmitTimeout() {
    retransmitTask = nil
    guard !disposed, let oldest = unacknowledged.first else { return }
    if retransmits >= configuration.maximumRetransmits {
      terminator?.report(
        SangforTunnelError.channelClosed(
          "terminated TCP flow to \(serverAddress):\(serverPort) gave up after "
            + "\(configuration.maximumRetransmits) retransmits"
        )
      )
      dispose(reset: true)
      return
    }
    retransmits += 1
    terminator?.emit(oldest.packet)
    retransmitTimeout = min(
      retransmitTimeout * 2,
      configuration.maximumRetransmitTimeout
    )
    armRetransmitTimer()
  }

  private func armIdleTimer() {
    guard let terminator, !disposed else { return }
    idleTask?.cancel()
    idleTask = terminator.scheduler.schedule(
      after: terminator.configuration.idleTimeout
    ) { [weak self] in
      self?.dispose(reset: true)
    }
  }

  private func dispose(reset: Bool) {
    guard !disposed else { return }
    disposed = true
    state = .closed
    if reset {
      terminator?.emit(
        buildPacket(flags: ATrustTcpFlag.rst, payload: [], mss: nil)
      )
    }
    retransmitTask?.cancel()
    retransmitTask = nil
    idleTask?.cancel()
    idleTask = nil
    unacknowledged.removeAll()
    sendQueue.removeAll()
    pendingForUpstream.removeAll()
    let stream = upstream
    upstream = nil
    stream?.onData = nil
    stream?.onClosed = nil
    stream?.close()
    terminator?.remove(self)
  }
}
