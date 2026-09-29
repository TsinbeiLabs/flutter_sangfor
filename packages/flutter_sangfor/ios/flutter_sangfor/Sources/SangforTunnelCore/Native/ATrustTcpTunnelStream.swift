import Foundation

/// One live TCP tunnel connection, presented as a byte stream.
///
/// The gateway answers a dial with a server hello; after that the connection
/// is either *raw* (bytes flow unframed) or *reuse* (both directions use the
/// tunnel's data frames with an EOF marker). Which one applies is decided by
/// the hello, so callers just read and write.
public final class ATrustTcpTunnelStream: SangforRelayStream {
  private let channel: SangforByteChannel
  private let parser = ATrustTcpTunnelHandshakeParser()
  private let scheduler: SangforScheduler
  private let timeout: Double
  private var handshook = false
  private var reuse = false
  private var closed = false
  private var pending: [UInt8] = []
  private var inbound: [UInt8] = []
  private var timeoutTask: SangforScheduledTask?
  private let onReady: (Result<ATrustTcpTunnelStream, Error>) -> Void

  /// Keeps the stream alive until the handshake settles. Nothing else owns it
  /// yet: the caller only receives it through [onReady], and every callback
  /// here captures `self` weakly to avoid a cycle through the channel.
  private var selfRetention: ATrustTcpTunnelStream?

  public var onData: ((Data) -> Void)?
  public var onClosed: ((Error?) -> Void)?

  public var isClosed: Bool { closed }

  /// True when the gateway asked for framed (reuse) mode.
  public var isReuse: Bool { reuse }

  private init(
    channel: SangforByteChannel,
    scheduler: SangforScheduler,
    timeout: Double,
    onReady: @escaping (Result<ATrustTcpTunnelStream, Error>) -> Void
  ) {
    self.channel = channel
    self.scheduler = scheduler
    self.timeout = timeout
    self.onReady = onReady
  }

  /// Dials one TCP connection through the tunnel. The completion receives the
  /// stream once the gateway accepted it, or the failure.
  public static func connect(
    channel: SangforByteChannel,
    request: ATrustTcpTunnelAuthRequest,
    signKey: [UInt8],
    host: String,
    port: Int,
    zeroRtt: Bool = false,
    scheduler: SangforScheduler,
    timeout: Double = 18,
    completion: @escaping (Result<ATrustTcpTunnelStream, Error>) -> Void
  ) {
    let stream = ATrustTcpTunnelStream(
      channel: channel,
      scheduler: scheduler,
      timeout: timeout,
      onReady: completion
    )
    stream.selfRetention = stream
    stream.begin(request: request, signKey: signKey, host: host, port: port, zeroRtt: zeroRtt)
  }

  private func begin(
    request: ATrustTcpTunnelAuthRequest,
    signKey: [UInt8],
    host: String,
    port: Int,
    zeroRtt: Bool
  ) {
    var settled = false
    timeoutTask = scheduler.schedule(after: timeout) { [weak self] in
      guard let self, !self.handshook, !self.closed else { return }
      self.finish(
        .failure(
          SangforTunnelError.channelClosed("TCP tunnel handshake timed out")
        ),
        settled: &settled
      )
    }
    channel.onData = { [weak self] chunk in
      guard let self, !self.closed else { return }
      self.receive(chunk, zeroRtt: zeroRtt, settled: &settled)
    }
    channel.onClosed = { [weak self] error in
      guard let self else { return }
      if !self.handshook {
        self.finish(
          .failure(
            SangforTunnelError.channelClosed(
              error?.localizedDescription ?? "channel closed during handshake"
            )
          ),
          settled: &settled
        )
        return
      }
      self.handleClosed(error)
    }
    do {
      let message = try ATrustTcpTunnelProtocol.handshakeMessage(
        request,
        signKey: signKey,
        host: host,
        port: port,
        zeroRtt: zeroRtt
      )
      channel.send(message)
    } catch {
      finish(.failure(error), settled: &settled)
    }
  }

  private func receive(_ chunk: Data, zeroRtt: Bool, settled: inout Bool) {
    if !handshook {
      let leftover: Data?
      do {
        leftover = try parser.add(chunk)
      } catch {
        finish(.failure(error), settled: &settled)
        return
      }
      guard let response = parser.response else { return }
      guard response.authCode == 0 else {
        finish(
          .failure(
            SangforTunnelError.flowAuthFailed(
              "TCP tunnel authentication failed (code \(response.authCode)): "
                + response.authMessage
            )
          ),
          settled: &settled
        )
        return
      }
      guard response.connectStatus == 0 else {
        finish(
          .failure(
            SangforTunnelError.flowAuthFailed(
              ATrustTcpTunnelProtocol.connectStatusMessage(response.connectStatus)
            )
          ),
          settled: &settled
        )
        return
      }
      handshook = true
      reuse = zeroRtt && response.reuse
      timeoutTask?.cancel()
      timeoutTask = nil
      finish(.success(self), settled: &settled)
      if let leftover, !leftover.isEmpty {
        handlePayload(leftover)
      }
      return
    }
    handlePayload(chunk)
  }

  private func handlePayload(_ chunk: Data) {
    guard !reuse else {
      inbound.append(contentsOf: chunk)
      while true {
        do {
          guard let frame = try ATrustTcpTunnelProtocol.parseDataFrame(inbound)
          else { return }
          if frame.eof {
            inbound.removeAll()
            let callback = onClosed
            onClosed = nil
            callback?(nil)
            return
          }
          inbound.removeFirst(frame.consumed)
          if !frame.data.isEmpty { onData?(frame.data) }
        } catch {
          handleClosed(error)
          return
        }
      }
    }
    onData?(chunk)
  }

  private func finish(
    _ result: Result<ATrustTcpTunnelStream, Error>,
    settled: inout Bool
  ) {
    guard !settled else { return }
    settled = true
    // The caller owns the stream from here on (or nobody does, on failure).
    selfRetention = nil
    if case .failure = result {
      close()
    }
    onReady(result)
  }

  private func handleClosed(_ error: Error?) {
    guard !closed else { return }
    closed = true
    let callback = onClosed
    onClosed = nil
    onData = nil
    channel.close()
    callback?(error)
  }

  // MARK: - SangforRelayStream

  public func send(_ data: Data) {
    guard !closed, !data.isEmpty else { return }
    if reuse {
      for frame in ATrustTcpTunnelProtocol.dataFrames(data) {
        channel.send(frame)
      }
      return
    }
    channel.send(data)
  }

  public func closeWrite() {
    guard !closed else { return }
    if reuse {
      channel.send(ATrustTcpTunnelProtocol.eofFrame())
      return
    }
    // A raw connection has no half-close; the channel goes away instead.
    close()
  }

  public func setReadsPaused(_ paused: Bool) {
    channel.setReadsPaused(paused)
  }

  public func close() {
    guard !closed else { return }
    closed = true
    selfRetention = nil
    timeoutTask?.cancel()
    timeoutTask = nil
    channel.onData = nil
    channel.onClosed = nil
    channel.close()
    inbound.removeAll()
    pending.removeAll()
  }
}
