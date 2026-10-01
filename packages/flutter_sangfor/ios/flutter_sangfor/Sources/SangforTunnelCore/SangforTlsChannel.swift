import Foundation
import Network
import Security

/// A TLS byte channel to a tunnel node, built on Network.framework.
///
/// aTrust nodes present certificates the platform trust store usually rejects,
/// so verification is a pin check against the digests the Runner collected
/// during login (anti-MITM). With no pins available the deployment's own
/// behaviour is mirrored and the certificate is accepted; pass
/// `acceptAnyCertificate: false` to fail closed instead.
public final class SangforTlsChannel: SangforByteChannel {
  private let connection: NWConnection
  private let queue: DispatchQueue
  private var closed = false
  private var receiving = false
  private var readsPaused = false

  public var onData: ((Data) -> Void)?
  public var onClosed: ((Error?) -> Void)?

  public var isClosed: Bool { closed }

  private init(connection: NWConnection, queue: DispatchQueue) {
    self.connection = connection
    self.queue = queue
  }

  /// Dials `host:port` over TLS. The completion runs on [queue].
  public static func dial(
    host: String,
    port: Int,
    certificateDigests: [String] = [],
    acceptAnyCertificate: Bool = true,
    queue: DispatchQueue,
    timeout: Double = 15,
    completion: @escaping (Result<SangforTlsChannel, Error>) -> Void
  ) {
    guard let endpointPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
      completion(.failure(SangforTunnelError.invalidPlan("bad node port \(port)")))
      return
    }
    let tls = NWProtocolTLS.Options()
    sec_protocol_options_set_verify_block(
      tls.securityProtocolOptions,
      { _, trust, verifyCompletion in
        let accepted = SangforTlsChannel.trustIsAcceptable(
          trust,
          digests: certificateDigests,
          acceptAny: acceptAnyCertificate
        )
        verifyCompletion(accepted)
      },
      queue
    )
    let parameters = NWParameters(tls: tls)
    // The tunnel must never route through itself: the caller keeps node
    // endpoints out of the tunnel routes, and pinning the physical interface
    // here would break handovers, so the default interface is used.
    let connection = NWConnection(
      host: NWEndpoint.Host(host),
      port: endpointPort,
      using: parameters
    )
    let channel = SangforTlsChannel(connection: connection, queue: queue)
    var settled = false
    let timeoutWork = DispatchWorkItem {
      guard !settled else { return }
      settled = true
      channel.close()
      completion(
        .failure(
          SangforTunnelError.channelClosed("TLS handshake timed out")
        )
      )
    }
    queue.asyncAfter(deadline: .now() + timeout, execute: timeoutWork)

    connection.stateUpdateHandler = { state in
      switch state {
      case .ready:
        guard !settled else { return }
        settled = true
        timeoutWork.cancel()
        channel.startReceiving()
        completion(.success(channel))
      case .failed(let error):
        channel.handleFailure(error)
        if !settled {
          settled = true
          timeoutWork.cancel()
          completion(.failure(error))
        }
      case .cancelled:
        channel.handleFailure(nil)
        if !settled {
          settled = true
          timeoutWork.cancel()
          completion(
            .failure(SangforTunnelError.channelClosed("connection cancelled"))
          )
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
      guard let self, let error else { return }
      self.handleFailure(error)
    })
  }

  public func close() {
    guard !closed else { return }
    closed = true
    connection.stateUpdateHandler = nil
    connection.cancel()
  }

  private func startReceiving() {
    guard !receiving, !closed else { return }
    receiving = true
    receiveNext()
  }

  private func receiveNext() {
    guard !readsPaused else { return }
    connection.receive(
      minimumIncompleteLength: 1,
      maximumLength: 64 * 1024
    ) { [weak self] data, _, isComplete, error in
      guard let self, !self.closed else { return }
      if let data, !data.isEmpty {
        self.onData?(data)
      }
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

  /// Backpressure: stop re-arming the receive until the consumer catches up.
  public func setReadsPaused(_ paused: Bool) {
    let wasPaused = readsPaused
    readsPaused = paused
    if paused == false, wasPaused, !closed, receiving {
      receiveNext()
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

  /// Pin check: the leaf certificate's identity digest must be one of
  /// [digests]. With no pins the deployment advertised no anti-MITM material,
  /// so [acceptAny] decides — matching the Dart client's opportunistic pinning.
  static func trustIsAcceptable(
    _ trust: sec_trust_t,
    digests: [String],
    acceptAny: Bool
  ) -> Bool {
    if digests.isEmpty {
      return acceptAny
    }
    let trustRef = sec_trust_copy_ref(trust).takeRetainedValue()
    guard let leaf = SangforTlsChannel.leafCertificateData(trustRef) else {
      return false
    }
    return SangforCertificateDigest.matches(leaf, digests: digests)
  }

  private static func leafCertificateData(_ trust: SecTrust) -> Data? {
    if #available(iOS 15.0, macOS 12.0, *) {
      var error: CFError?
      guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
        let leaf = chain.first
      else {
        _ = error
        return nil
      }
      return SecCertificateCopyData(leaf) as Data
    }
    guard let leaf = SecTrustGetCertificateAtIndex(trust, 0) else { return nil }
    return SecCertificateCopyData(leaf) as Data
  }
}
