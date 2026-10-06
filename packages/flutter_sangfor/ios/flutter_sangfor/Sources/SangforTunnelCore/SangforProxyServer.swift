import Foundation
import Network

/// A loopback HTTP proxy that runs inside the packet tunnel extension.
///
/// The extension publishes it to the system with `NEProxySettings`, so the
/// apps that honor the system proxy (WebKit, CFNetwork) send their campus
/// traffic here by host name. That is what lets iOS decide per domain, the way
/// the Android loopback proxy does, while the tunnel itself keeps running when
/// iOS suspends the app: the proxy lives in the same process as the data plane.
///
/// Everything runs on one serial queue, the data plane's own, so the dial
/// closure can reach the plane without further locking.
public final class SangforProxyServer {
  public struct Statistics: Equatable {
    public var sessions = 0
    public var tunneled = 0
    public var direct = 0
    public var rejected = 0
    public var failures = 0
    public var upBytes = 0
    public var downBytes = 0
  }

  public typealias TunnelDialer = (
    _ host: String,
    _ port: Int,
    _ completion: @escaping (Result<SangforRelayStream, Error>) -> Void
  ) -> Void

  static let maximumSessions = 256
  static let idleTimeout: Double = 120
  static let directDialTimeout: Double = 15
  /// Bytes allowed to wait for the client before upstream reads are paused.
  static let highWater = 256 * 1024
  static let lowWater = 64 * 1024

  private let policy: SangforProxyPolicy
  private let credential: String?
  private let queue: DispatchQueue
  private let tunnelDialer: TunnelDialer
  private let log: (String) -> Void

  private var listener: NWListener?
  private var sessions: [ObjectIdentifier: ProxySession] = [:]
  private var loggedDecisions = Set<String>()

  public private(set) var statistics = Statistics()

  /// [credential] is `user:password`; nil turns authentication off.
  public init(
    policy: SangforProxyPolicy,
    credential: String?,
    queue: DispatchQueue,
    tunnelDialer: @escaping TunnelDialer,
    log: @escaping (String) -> Void
  ) {
    self.policy = policy
    self.credential = credential
    self.queue = queue
    self.tunnelDialer = tunnelDialer
    self.log = log
  }

  /// Binds a loopback port chosen by the system and reports it once ready.
  public func start(completion: @escaping (Result<UInt16, Error>) -> Void) {
    do {
      let parameters = NWParameters.tcp
      // Strictly local: without the interface type the listener can end up on
      // en0 and be reachable from the network.
      parameters.requiredLocalEndpoint = NWEndpoint.hostPort(
        host: .ipv4(.loopback),
        port: .any
      )
      parameters.requiredInterfaceType = .loopback
      let listener = try NWListener(using: parameters)
      var reported = false
      listener.newConnectionHandler = { [weak self] connection in
        self?.accept(connection)
      }
      listener.stateUpdateHandler = { [weak self] state in
        switch state {
        case .ready:
          guard !reported else { return }
          reported = true
          if let port = listener.port?.rawValue {
            completion(.success(port))
          } else {
            completion(.failure(ProxyError.noPort))
          }
        case .failed(let error):
          self?.log("proxy listener failed: \(error.localizedDescription)")
          if !reported {
            reported = true
            completion(.failure(error))
          }
        default:
          break
        }
      }
      self.listener = listener
      listener.start(queue: queue)
    } catch {
      completion(.failure(error))
    }
  }

  public func stop() {
    listener?.cancel()
    listener = nil
    for session in Array(sessions.values) { session.close() }
    sessions.removeAll()
  }

  enum ProxyError: Error { case noPort, dialFailed }

  // MARK: - Sessions

  private func accept(_ connection: NWConnection) {
    if sessions.count >= Self.maximumSessions {
      statistics.rejected += 1
      connection.start(queue: queue)
      connection.send(
        content: SangforHttpProxyResponses.serviceUnavailable,
        completion: .contentProcessed { _ in connection.cancel() }
      )
      return
    }
    let session = ProxySession(server: self, client: connection)
    sessions[ObjectIdentifier(session)] = session
    statistics.sessions = sessions.count
    session.start()
  }

  fileprivate func remove(_ session: ProxySession) {
    sessions.removeValue(forKey: ObjectIdentifier(session))
    statistics.sessions = sessions.count
  }

  /// Logs a destination decision the first time it is seen, so a busy page
  /// does not flood the log.
  fileprivate func noteDecision(_ decision: SangforProxyDecision, host: String, port: Int) {
    let key = "\(decision)|\(host):\(port)"
    guard loggedDecisions.count < 512, loggedDecisions.insert(key).inserted else { return }
    log("proxy \(decision) \(host):\(port)")
  }

  fileprivate func decide(host: String, port: Int) -> SangforProxyDecision {
    let decision = policy.decide(host: host, port: port)
    noteDecision(decision, host: host, port: port)
    return decision
  }

  fileprivate func dialTunnel(
    host: String,
    port: Int,
    completion: @escaping (Result<SangforRelayStream, Error>) -> Void
  ) {
    tunnelDialer(host, port, completion)
  }

  fileprivate func credentialValue() -> String? { credential }
  fileprivate var serverQueue: DispatchQueue { queue }

  fileprivate func record(_ change: (inout Statistics) -> Void) {
    change(&statistics)
  }
}

private final class ProxySession {
  private unowned let server: SangforProxyServer
  private let client: NWConnection
  private var parser: SangforHttpProxyParser

  private var upstreamStream: SangforRelayStream?
  private var upstreamConnection: NWConnection?
  private var idleTask: DispatchWorkItem?
  private var dialTimeout: DispatchWorkItem?
  private var closed = false
  private var closeWhenFlushed = false
  private var pendingToClient = 0
  private var pendingToUpstream = 0
  private var upstreamPaused = false
  private var clientPaused = false
  private var lastActivity = DispatchTime.now()

  init(server: SangforProxyServer, client: NWConnection) {
    self.server = server
    self.client = client
    parser = SangforHttpProxyParser(credential: server.credentialValue())
  }

  func start() {
    client.stateUpdateHandler = { [weak self] state in
      switch state {
      case .failed, .cancelled:
        self?.close()
      default:
        break
      }
    }
    client.start(queue: server.serverQueue)
    touch()
    receiveHeader()
  }

  func close() {
    guard !closed else { return }
    closed = true
    idleTask?.cancel()
    dialTimeout?.cancel()
    upstreamStream?.onData = nil
    upstreamStream?.onClosed = nil
    upstreamStream?.close()
    upstreamStream = nil
    upstreamConnection?.stateUpdateHandler = nil
    upstreamConnection?.cancel()
    upstreamConnection = nil
    client.stateUpdateHandler = nil
    client.cancel()
    server.remove(self)
  }

  // MARK: Header

  private func receiveHeader() {
    client.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) {
      [weak self] data, _, isComplete, error in
      guard let self, !self.closed else { return }
      if error != nil || (data?.isEmpty ?? true) && isComplete {
        self.close()
        return
      }
      self.touch()
      switch self.parser.feed(data ?? Data()) {
      case .needMore:
        self.receiveHeader()
      case .failure(.badRequest):
        self.respondAndClose(SangforHttpProxyResponses.badRequest)
      case .failure(.proxyAuthenticationRequired):
        self.server.record { $0.rejected += 1 }
        self.respondAndClose(SangforHttpProxyResponses.proxyAuthenticationRequired)
      case .request(let request, let leftover):
        self.handle(request, leftover: leftover)
      }
    }
  }

  private func handle(_ request: SangforProxyRequest, leftover: Data) {
    let host: String
    let port: Int
    switch request {
    case .connect(let requestedHost, let requestedPort):
      host = requestedHost
      port = requestedPort
    case .forward(let requestedHost, let requestedPort, _, _):
      host = requestedHost
      port = requestedPort
    }
    switch server.decide(host: host, port: port) {
    case .reject:
      server.record { $0.rejected += 1 }
      respondAndClose(SangforHttpProxyResponses.forbidden)
    case .tunnel:
      server.record { $0.tunneled += 1 }
      server.dialTunnel(host: host, port: port) { [weak self] result in
        guard let self, !self.closed else {
          if case .success(let stream) = result { stream.close() }
          return
        }
        switch result {
        case .failure(let error):
          self.dialFailed(host: host, port: port, error: error)
        case .success(let stream):
          self.upstreamStream = stream
          self.established(request, leftover: leftover)
        }
      }
    case .direct:
      server.record { $0.direct += 1 }
      dialDirect(host: host, port: port) { [weak self] result in
        guard let self, !self.closed else {
          if case .success(let connection) = result { connection.cancel() }
          return
        }
        switch result {
        case .failure(let error):
          self.dialFailed(host: host, port: port, error: error)
        case .success(let connection):
          self.upstreamConnection = connection
          self.established(request, leftover: leftover)
        }
      }
    }
  }

  private func dialFailed(host: String, port: Int, error: Error) {
    server.record { $0.failures += 1 }
    server.noteDecision(.reject, host: host, port: port)
    respondAndClose(SangforHttpProxyResponses.badGateway)
  }

  private func dialDirect(
    host: String,
    port: Int,
    completion: @escaping (Result<NWConnection, Error>) -> Void
  ) {
    guard let endpointPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
      completion(.failure(SangforProxyServer.ProxyError.noPort))
      return
    }
    let connection = NWConnection(
      host: NWEndpoint.Host(host),
      port: endpointPort,
      using: .tcp
    )
    var settled = false
    let timeout = DispatchWorkItem { [weak connection] in
      guard !settled else { return }
      settled = true
      connection?.stateUpdateHandler = nil
      connection?.cancel()
      completion(.failure(SangforProxyServer.ProxyError.dialFailed))
    }
    dialTimeout = timeout
    server.serverQueue.asyncAfter(
      deadline: .now() + SangforProxyServer.directDialTimeout,
      execute: timeout
    )
    connection.stateUpdateHandler = { state in
      guard !settled else { return }
      switch state {
      case .ready:
        settled = true
        timeout.cancel()
        completion(.success(connection))
      case .failed(let error):
        settled = true
        timeout.cancel()
        connection.cancel()
        completion(.failure(error))
      case .cancelled:
        settled = true
        timeout.cancel()
        completion(.failure(SangforProxyServer.ProxyError.dialFailed))
      default:
        break
      }
    }
    connection.start(queue: server.serverQueue)
  }

  // MARK: Relay

  private func established(_ request: SangforProxyRequest, leftover: Data) {
    dialTimeout?.cancel()
    switch request {
    case .connect:
      sendToClient(SangforHttpProxyResponses.connectionEstablished)
      if !leftover.isEmpty { sendUpstream(leftover) }
    case .forward(_, _, let head, let body):
      sendUpstream(head)
      if !body.isEmpty { sendUpstream(body) }
    }
    attachUpstreamReader()
    receiveFromClient()
  }

  private func receiveFromClient() {
    client.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
      [weak self] data, _, isComplete, error in
      guard let self, !self.closed else { return }
      if let data, !data.isEmpty {
        self.touch()
        self.server.record { $0.upBytes += data.count }
        self.sendUpstream(data)
      }
      if error != nil || isComplete {
        self.close()
        return
      }
      // A direct upstream that is slower than the client holds the next read
      // back; tunnel streams buffer on their own.
      if self.pendingToUpstream > SangforProxyServer.highWater {
        self.clientPaused = true
      } else {
        self.receiveFromClient()
      }
    }
  }

  private func sendUpstream(_ data: Data) {
    if let stream = upstreamStream {
      stream.send(data)
    } else if let connection = upstreamConnection {
      pendingToUpstream += data.count
      connection.send(content: data, completion: .contentProcessed { [weak self] error in
        guard let self, !self.closed else { return }
        self.pendingToUpstream -= data.count
        if error != nil {
          self.close()
          return
        }
        if self.clientPaused, self.pendingToUpstream < SangforProxyServer.lowWater {
          self.clientPaused = false
          self.receiveFromClient()
        }
      })
    }
  }

  private func attachUpstreamReader() {
    if let stream = upstreamStream {
      stream.onData = { [weak self] data in
        self?.relayToClient(data)
      }
      stream.onClosed = { [weak self] _ in
        self?.upstreamEnded()
      }
    } else if let connection = upstreamConnection {
      receiveFromDirectUpstream(connection)
    }
  }

  private func receiveFromDirectUpstream(_ connection: NWConnection) {
    connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
      [weak self] data, _, isComplete, error in
      guard let self, !self.closed else { return }
      if let data, !data.isEmpty {
        self.relayToClient(data)
      }
      if error != nil || isComplete {
        self.upstreamEnded()
        return
      }
      if self.pendingToClient > SangforProxyServer.highWater {
        self.upstreamPaused = true
      } else {
        self.receiveFromDirectUpstream(connection)
      }
    }
  }

  private func relayToClient(_ data: Data) {
    touch()
    server.record { $0.downBytes += data.count }
    sendToClient(data)
    if pendingToClient > SangforProxyServer.highWater, !upstreamPaused {
      upstreamPaused = true
      upstreamStream?.setReadsPaused(true)
    }
  }

  private func sendToClient(_ data: Data) {
    pendingToClient += data.count
    client.send(content: data, completion: .contentProcessed { [weak self] error in
      guard let self, !self.closed else { return }
      self.pendingToClient -= data.count
      if error != nil {
        self.close()
        return
      }
      if self.closeWhenFlushed, self.pendingToClient == 0 {
        self.close()
        return
      }
      if self.upstreamPaused, self.pendingToClient < SangforProxyServer.lowWater {
        self.upstreamPaused = false
        if let stream = self.upstreamStream {
          stream.setReadsPaused(false)
        } else if let connection = self.upstreamConnection {
          self.receiveFromDirectUpstream(connection)
        }
      }
    })
  }

  private func upstreamEnded() {
    if pendingToClient == 0 {
      close()
    } else {
      closeWhenFlushed = true
    }
  }

  private func respondAndClose(_ response: Data) {
    client.send(content: response, completion: .contentProcessed { [weak self] _ in
      self?.close()
    })
  }

  /// Notes activity. One timer is armed per session and re-armed for the
  /// remaining time when it fires early, so a busy transfer does not allocate a
  /// timer per chunk.
  private func touch() {
    lastActivity = .now()
    if idleTask == nil { armIdleTimer(after: SangforProxyServer.idleTimeout) }
  }

  private func armIdleTimer(after seconds: Double) {
    let work = DispatchWorkItem { [weak self] in
      guard let self, !self.closed else { return }
      let idle = Double(
        DispatchTime.now().uptimeNanoseconds - self.lastActivity.uptimeNanoseconds
      ) / 1_000_000_000
      if idle >= SangforProxyServer.idleTimeout {
        self.close()
      } else {
        self.armIdleTimer(after: SangforProxyServer.idleTimeout - idle)
      }
    }
    idleTask = work
    server.serverQueue.asyncAfter(deadline: .now() + seconds, execute: work)
  }
}
