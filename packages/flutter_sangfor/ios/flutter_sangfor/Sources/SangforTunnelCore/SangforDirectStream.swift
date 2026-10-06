import Foundation
import Network

/// A plain TCP connection from the extension, presented as a relay stream.
///
/// It carries the flows the tunnel was never meant to carry: the plan routes the
/// addresses its host names resolved to, so other names and ports behind the
/// same address end up in the tunnel too, and this puts them back on the path
/// they would have taken without it. The connection refuses the tunnel's own
/// interface (a utun is an `.other` interface), so it can never be carried back
/// into the tunnel it is meant to go around.
///
/// Everything runs on the queue it is given, the data plane's.
public final class SangforDirectStream: SangforRelayStream {
  private let connection: NWConnection
  private var closed = false
  private var readsPaused = false
  private var receiving = false

  public var onData: ((Data) -> Void)?
  public var onClosed: ((Error?) -> Void)?
  public var isClosed: Bool { closed }

  /// The interface the connection settled on, for logs.
  public var interfaceName: String {
    connection.currentPath?.availableInterfaces.first?.name ?? "unknown"
  }

  private init(connection: NWConnection) {
    self.connection = connection
  }

  /// Dials `host:port`, giving up after [timeout] seconds. The completion runs on
  /// [queue].
  public static func dial(
    host: String,
    port: Int,
    queue: DispatchQueue,
    timeout: Double = 15,
    completion: @escaping (Result<SangforRelayStream, Error>) -> Void
  ) {
    guard let endpointPort = NWEndpoint.Port(rawValue: UInt16(truncatingIfNeeded: port)),
      (1...65535).contains(port)
    else {
      completion(.failure(SangforTunnelError.invalidPlan("bad port \(port)")))
      return
    }
    let parameters = NWParameters.tcp
    parameters.prohibitedInterfaceTypes = [.other]
    let connection = NWConnection(
      host: NWEndpoint.Host(host),
      port: endpointPort,
      using: parameters
    )
    let stream = SangforDirectStream(connection: connection)
    var settled = false
    let timeoutWork = DispatchWorkItem { [weak stream] in
      guard !settled else { return }
      settled = true
      stream?.close()
      completion(.failure(SangforTunnelError.channelClosed("direct connect timed out")))
    }
    queue.asyncAfter(deadline: .now() + timeout, execute: timeoutWork)
    // The handler holds the stream, not the other way round: nothing else owns
    // it until the completion hands it over, and a weak reference here is gone
    // by the time the connection is ready -- the dial would then never complete.
    // The cycle through the connection ends when the stream is closed or fails,
    // which clear the handler.
    connection.stateUpdateHandler = { state in
      switch state {
      case .ready:
        guard !settled else { return }
        settled = true
        timeoutWork.cancel()
        stream.startReceiving()
        completion(.success(stream))
      case .failed(let error):
        stream.handleFailure(error)
        if !settled {
          settled = true
          timeoutWork.cancel()
          completion(.failure(error))
        }
      case .cancelled:
        stream.handleFailure(nil)
        if !settled {
          settled = true
          timeoutWork.cancel()
          completion(.failure(SangforTunnelError.channelClosed("direct connection cancelled")))
        }
      default:
        break
      }
    }
    connection.start(queue: queue)
  }

  public func send(_ data: Data) {
    guard !closed, !data.isEmpty else { return }
    connection.send(content: data, completion: .contentProcessed { [weak self] error in
      if let error { self?.handleFailure(error) }
    })
  }

  public func closeWrite() {
    guard !closed else { return }
    connection.send(
      content: nil,
      contentContext: .finalMessage,
      isComplete: true,
      completion: .contentProcessed { _ in }
    )
  }

  public func setReadsPaused(_ paused: Bool) {
    let wasPaused = readsPaused
    readsPaused = paused
    if !paused, wasPaused, !closed, receiving { receiveNext() }
  }

  public func close() {
    guard !closed else { return }
    closed = true
    connection.stateUpdateHandler = nil
    onData = nil
    onClosed = nil
    connection.cancel()
  }

  private func startReceiving() {
    guard !receiving, !closed else { return }
    receiving = true
    receiveNext()
  }

  private func receiveNext() {
    guard !readsPaused, !closed else { return }
    connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
      [weak self] data, _, isComplete, error in
      guard let self, !self.closed else { return }
      if let data, !data.isEmpty { self.onData?(data) }
      if let error {
        self.handleFailure(error)
        return
      }
      if isComplete {
        self.handleFailure(nil)
        return
      }
      self.receiveNext()
    }
  }

  private func handleFailure(_ error: Error?) {
    guard !closed else { return }
    closed = true
    let callback = onClosed
    onClosed = nil
    onData = nil
    connection.stateUpdateHandler = nil
    connection.cancel()
    callback?(error)
  }
}
