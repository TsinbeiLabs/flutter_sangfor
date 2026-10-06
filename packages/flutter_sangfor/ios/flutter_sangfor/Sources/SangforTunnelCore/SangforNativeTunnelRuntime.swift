import Foundation
import Network
import NetworkExtension

/// Runs the tunnel data plane inside the packet tunnel extension.
///
/// This is the alternative to the loopback bridge: instead of forwarding
/// packets to the containing app over a local socket — which dies as soon as
/// iOS suspends the Runner — the extension speaks the tunnel protocol itself.
/// The Runner hands over an [ATrustSessionPlan] through the App Group before
/// starting the tunnel; nothing credential-bearing is logged.
public final class SangforNativeTunnelRuntime {
  private let packetFlow: NEPacketTunnelFlow
  private let appGroupIdentifier: String?
  private let queue: DispatchQueue
  private let log: (String) -> Void

  private var plane: SangforNativeDataPlane?
  private var readLoopRunning = false
  private var statsTask: DispatchWorkItem?
  private var stopped = false

  public init(
    packetFlow: NEPacketTunnelFlow,
    appGroupIdentifier: String?,
    queue: DispatchQueue,
    log: @escaping (String) -> Void = { _ in }
  ) {
    self.packetFlow = packetFlow
    self.appGroupIdentifier = appGroupIdentifier
    self.queue = queue
    self.log = log
  }

  /// Loads the session plan, brings the tunnel up, and starts pumping packets.
  /// The completion receives the virtual IP the gateway assigned.
  public func start(completion: @escaping (Result<[String], Error>) -> Void) {
    guard let data = SangforSharedContainer.readSessionPlan(
      appGroupIdentifier: appGroupIdentifier
    ) else {
      completion(
        .failure(
          SangforTunnelError.invalidPlan(
            "no session plan in the App Group container"
          )
        )
      )
      return
    }
    let plan: ATrustSessionPlan
    do {
      plan = try ATrustSessionPlan.decode(data)
    } catch {
      completion(.failure(SangforTunnelError.invalidPlan("\(error)")))
      return
    }
    guard plan.schemaVersion == ATrustSessionPlan.currentSchemaVersion else {
      completion(
        .failure(
          SangforTunnelError.invalidPlan(
            "session plan schema \(plan.schemaVersion) is not supported"
          )
        )
      )
      return
    }
    let scheduler = SangforDispatchScheduler(queue: queue)
    let plane = SangforNativeDataPlane(
      plan: plan,
      scheduler: scheduler,
      dialer: { host, port, dialCompletion in
        SangforTlsChannel.dial(
          host: host,
          port: port,
          certificateDigests: plan.certificateDigests,
          acceptAnyCertificate: plan.acceptAnyCertificate,
          queue: self.queue
        ) { result in
          switch result {
          case .success(let channel):
            dialCompletion(.success(channel))
          case .failure(let error):
            dialCompletion(.failure(error))
          }
        }
      },
      log: { [weak self] message in self?.log(message) }
    )
    plane.onIngressPacket = { [weak self] packet in
      guard let self, !self.stopped else { return }
      self.packetFlow.writePackets([packet], withProtocols: [AF_INET as NSNumber])
    }
    plane.onFatalError = { [weak self] error in
      self?.log("fatal tunnel error: \(error)")
    }
    plane.onVirtualIP = { [weak self] addresses in
      self?.log("virtual IP updated: \(addresses.joined(separator: ","))")
    }
    self.plane = plane

    plane.start { [weak self] result in
      guard let self else { return }
      switch result {
      case .failure(let error):
        completion(.failure(error))
      case .success(let addresses):
        self.startPacketFlowReadLoop()
        self.scheduleStatisticsLogging()
        self.log("native data plane up: \(addresses.joined(separator: ","))")
        completion(.success(addresses))
      }
    }
  }

  /// Stops the read loop, the data plane, and every connection it owns.
  public func stop() {
    guard !stopped else { return }
    stopped = true
    readLoopRunning = false
    statsTask?.cancel()
    statsTask = nil
    plane?.close()
    plane = nil
  }

  /// Opens one TCP tunnel connection for the extension's HTTP proxy. Must be
  /// called on the runtime's queue.
  public func dialTcpTunnelForProxy(
    host: String,
    port: Int,
    completion: @escaping (Result<SangforRelayStream, Error>) -> Void
  ) {
    guard let plane, !stopped else {
      completion(.failure(SangforTunnelError.channelClosed("the tunnel is not running")))
      return
    }
    plane.dialTcpTunnelForProxy(host: host, port: port, completion: completion)
  }

  /// The counters the provider reports through `handleAppMessage`.
  public var statistics: SangforNativeDataPlane.Statistics? { plane?.statistics }

  private func startPacketFlowReadLoop() {
    guard !readLoopRunning else { return }
    readLoopRunning = true
    readPackets()
  }

  private func readPackets() {
    packetFlow.readPackets { [weak self] packets, protocols in
      guard let self, self.readLoopRunning else { return }
      for (packet, protocolFamily) in zip(packets, protocols) {
        // IPv4-only, matching the loopback bridge: anything else is dropped
        // rather than mislabelled.
        guard protocolFamily.intValue == AF_INET else { continue }
        self.queue.async {
          self.plane?.handleEgressPacket(packet)
        }
      }
      self.readPackets()
    }
  }

  private func scheduleStatisticsLogging() {
    let work = DispatchWorkItem { [weak self] in
      guard let self, !self.stopped else { return }
      if let statistics = self.plane?.statistics {
        self.log("native data plane: \(statistics.description)")
      }
      self.scheduleStatisticsLogging()
    }
    statsTask = work
    queue.asyncAfter(deadline: .now() + 30, execute: work)
  }
}
