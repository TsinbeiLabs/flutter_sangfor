import Foundation
import Network
import NetworkExtension

/// PacketTunnelProvider that bridges the iOS system VPN packet flow to the
/// Flutter app via a local TCP loopback socket. Each packet is framed with
/// a 4-byte big-endian length prefix in both directions.
///
/// This type lives in `SangforTunnelCore`, which deliberately does not
/// depend on Flutter: consumer apps embed a thin `.appex` wrapper around it
/// as their Packet Tunnel Provider extension target.
///
/// EXPERIMENTAL / FOREGROUND BRIDGE: the loopback design requires the
/// containing Flutter app to stay alive; see the repository docs before
/// relying on it for background VPN use.
open class SangforPacketTunnelProvider: NEPacketTunnelProvider {
  /// Fixed loopback port used by the Phase 2 bridge. Not a public API
  /// contract; future revisions may make it configurable or remove the
  /// loopback bridge entirely.
  private static let ipcPort: UInt16 = 6400

  /// Maximum accepted IPC frame payload (largest possible IP packet over
  /// the tunnel MTU plus headroom).
  private static let maxFrameLength = 0xffff

  /// Bounded queue of packets read from the system before the Dart bridge
  /// connects: at most 128 packets or 1 MB, whichever is hit first.
  private static let pendingPacketLimit = 128
  private static let pendingPacketByteLimit = 1 << 20

  /// Backpressure cap for packets waiting to be written into the IPC socket.
  private static let outgoingByteLimit = 4 << 20

  /// If the Dart bridge stays absent this long after tunnel start (or after
  /// a disconnect), the tunnel is torn down so users never see a connected
  /// VPN with a dead data plane.
  private static let bridgeReconnectTimeout: TimeInterval = 30

  /// Error domain shared with the Runner side.
  private static let errorDomain = "flutter_sangfor"

  private let queue = DispatchQueue(label: "com.tsinbei.flutter_sangfor.ne")

  private var listener: NWListener?
  private var bridge: IpcBridge?
  private var readLoopRunning = false

  /// Set while the extension runs its own data plane (`.extensionNative`).
  private var nativeRuntime: SangforNativeTunnelRuntime?

  /// Rebuilds the tunnel settings for a given interface address, so they can be
  /// re-applied when the gateway assigns a different one than was configured.
  private var settingsFactory: ((String) -> NEPacketTunnelNetworkSettings)?
  private var appliedAddress: String?

  /// The HTTP proxy published to the system while the native data plane runs.
  private var proxyServer: SangforProxyServer?
  private var proxyStatsTask: DispatchWorkItem?

  /// What the system needs to know to send traffic to [proxyServer].
  private struct PreparedProxy {
    let port: UInt16
    let matchDomains: [String]
    let exceptionList: [String]
  }

  // Packets from the system waiting for the Runner to connect.
  private var pendingPackets: [Data] = []
  private var pendingBytes = 0

  private var bridgeTimeoutWorkItem: DispatchWorkItem?

  // Runtime counters exposed through handleAppMessage. Guarded by `queue`.
  private var metrics = Metrics()

  /// IPC and packet statistics.
  public struct Metrics: Codable {
    public var packetsInFromSystem = 0
    public var bytesInFromSystem = 0
    public var packetsOutToSystem = 0
    public var bytesOutToSystem = 0
    public var droppedBeforeIpc = 0
    public var droppedBackpressure = 0
    public var droppedIPv6 = 0
    public var malformedFrames = 0
    public var ipcReconnects = 0
  }

  // MARK: - Tunnel lifecycle

  public override func startTunnel(
    options: [String: NSObject]?,
    completionHandler: @escaping (Error?) -> Void
  ) {
    let startOptions = options ?? [:]
    let sessionPlan = Self.readSessionPlan(
      appGroupIdentifier: resolvedAppGroupIdentifier(options: startOptions)
    )
    var resolved = Self.configuration(from: startOptions)
    // An app-initiated start always carries a `runtimeMode` key (empty when the
    // app does not choose); a start the system initiates -- the VPN switched on
    // from Settings, or iOS bringing the provider back after a network change
    // or a reboot -- carries no options at all. That start used to fall back to
    // the loopback bridge with a placeholder address and no routes: a tunnel
    // that reported connected and carried nothing. It now rebuilds its settings
    // from the plan, or fails with a reason.
    if startOptions["runtimeMode"] == nil {
      guard
        let plan = sessionPlan,
        let hint = plan.tunnelSettings,
        let address = hint.address ?? plan.virtualAddress
      else {
        SangforLog.providerError(
          "started without options and with no tunnel settings in the session plan"
        )
        completionHandler(
          NSError(
            domain: Self.errorDomain,
            code: Self.SettingsError.noConfiguration.rawValue,
            userInfo: [
              NSLocalizedDescriptionKey:
                "The VPN was started by the system and no session is stored. Open the app and connect again."
            ]
          )
        )
        return
      }
      resolved = SangforTunnelConfiguration(
        address: address,
        prefixLength: hint.prefixLength,
        routes: hint.routes,
        dnsServers: hint.dnsServers,
        searchDomains: hint.searchDomains,
        mtu: hint.mtu ?? plan.mtu,
        runtimeMode: .extensionNative
      )
      SangforLog.provider("system-initiated start: settings rebuilt from the session plan")
    }
    let configuration = resolved
    guard SangforIPv4.isValidIPv4Address(configuration.address) else {
      completionHandler(
        NSError(
          domain: Self.errorDomain,
          code: Self.SettingsError.invalidAddress.rawValue,
          userInfo: [
            NSLocalizedDescriptionKey:
              "Invalid tunnel address \(configuration.address)."
          ]
        )
      )
      return
    }
    SangforLog.provider(
      "startTunnel: address=\(configuration.address)/\(configuration.prefixLength) routes=\(configuration.routes.count) dns=\(configuration.dnsServers.count) mtu=\(configuration.mtu ?? 0) proxy=\(configuration.proxyEndpoint.map { "\($0.host):\($0.port)" } ?? "none")"
    )

    // Fail closed: a malformed route is logged and skipped, never silently
    // turned into a default route.
    var invalidRouteCount = 0
    let parsedRoutes = SangforIPv4.parseRoutes(configuration.routes) { _ in
      invalidRouteCount += 1
    }
    if invalidRouteCount > 0 {
      SangforLog.routing(
        "route validation dropped \(invalidRouteCount) malformed entr(ies)"
      )
    }

    guard
      let subnetMask = SangforIPv4.mask(
        forPrefixLength: configuration.prefixLength
      )
    else {
      completionHandler(
        NSError(
          domain: Self.errorDomain,
          code: Self.SettingsError.invalidPrefixLength.rawValue,
          userInfo: [
            NSLocalizedDescriptionKey:
              "Invalid tunnel prefix length \(configuration.prefixLength)."
          ]
        )
      )
      return
    }

    // The native data plane publishes its own proxy, so it has to be listening
    // before the settings that name its port are applied.
    guard configuration.runtimeMode == .extensionNative else {
      applyTunnelSettings(
        configuration: configuration,
        parsedRoutes: parsedRoutes,
        subnetMask: subnetMask,
        plan: sessionPlan,
        proxy: nil,
        startOptions: startOptions,
        completionHandler: completionHandler
      )
      return
    }
    prepareDomainProxy(plan: sessionPlan) { [weak self] proxy in
      self?.applyTunnelSettings(
        configuration: configuration,
        parsedRoutes: parsedRoutes,
        subnetMask: subnetMask,
        plan: sessionPlan,
        proxy: proxy,
        startOptions: startOptions,
        completionHandler: completionHandler
      )
    }
  }

  private func applyTunnelSettings(
    configuration: SangforTunnelConfiguration,
    parsedRoutes: [SangforIPv4.Route],
    subnetMask: String,
    plan: ATrustSessionPlan?,
    proxy preparedProxy: PreparedProxy?,
    startOptions: [String: NSObject],
    completionHandler: @escaping (Error?) -> Void
  ) {
    // Never-tunnel destinations (the VPN gateway) and the gateway's own nodes
    // stay out of the tunnel whatever the routes cover; the tunnel's transport
    // must not be routed back into itself.
    var excluded: [SangforIPv4.Route] = []
    if configuration.runtimeMode == .extensionNative {
      excluded = SangforIPv4.parseRoutes(plan?.tunnelSettings?.excludedRoutes ?? [])
      for endpoints in (plan?.nodes ?? [:]).values {
        for endpoint in endpoints {
          if let node = ATrustNodeEndpoint(endpoint),
            SangforIPv4.isValidIPv4Address(node.host)
          {
            excluded.append(
              SangforIPv4.Route(destinationAddress: node.host, prefixLength: 32)
            )
          }
        }
      }
    }
    let excludedRoutes = excluded
    let makeSettings: (String) -> NEPacketTunnelNetworkSettings = { address in
      let settings = NEPacketTunnelNetworkSettings(
        tunnelRemoteAddress: address
      )
      let ipv4 = NEIPv4Settings(
        addresses: [address],
        subnetMasks: [subnetMask]
      )
      ipv4.includedRoutes = parsedRoutes.map { route in
        NEIPv4Route(
          destinationAddress: route.destinationAddress,
          subnetMask: SangforIPv4.mask(forPrefixLength: route.prefixLength)!
        )
      }
      if !excludedRoutes.isEmpty {
        ipv4.excludedRoutes = excludedRoutes.map { route in
          NEIPv4Route(
            destinationAddress: route.destinationAddress,
            subnetMask: SangforIPv4.mask(forPrefixLength: route.prefixLength)!
          )
        }
      }
      settings.ipv4Settings = ipv4
      if !configuration.dnsServers.isEmpty {
        let dns = NEDNSSettings(servers: configuration.dnsServers)
        dns.searchDomains = configuration.searchDomains.isEmpty
          ? nil
          : configuration.searchDomains
        settings.dnsSettings = dns
      }
      if configuration.runtimeMode == .loopbackBridge,
        let proxy = configuration.proxyEndpoint
      {
        // Advertise the caller's loopback HTTP proxy as the system proxy for
        // the tunnel's lifetime. Gateways commonly publish resources as
        // TCP-tunnel-only, which the raw packet flow cannot carry; proxy-aware
        // clients (CFNetwork/NSURLSession) then reach them through the caller's
        // proxy instead of being dropped as unrouted. An empty match-domain
        // matches every host name, so all HTTP(S) traffic is proxied.
        //
        // The native data plane terminates those flows itself, so it must not
        // advertise a proxy that only exists while the Runner is awake.
        let proxySettings = NEProxySettings()
        let server = NEProxyServer(address: proxy.host, port: proxy.port)
        proxySettings.httpEnabled = true
        proxySettings.httpServer = server
        proxySettings.httpsEnabled = true
        proxySettings.httpsServer = server
        proxySettings.matchDomains = [""]
        settings.proxySettings = proxySettings
        SangforLog.network(
          "system proxy advertised at \(proxy.host):\(proxy.port)"
        )
      }
      if let preparedProxy {
        // The extension's own proxy: apps that honor the system proxy send their
        // campus traffic here by host name, so domains the routing table cannot
        // express (wildcards, names that resolve to other addresses) still reach
        // the tunnel. Only the matching domains are sent; hosts that must keep
        // the user's own address (the VPN gateway) are exceptions.
        let proxySettings = NEProxySettings()
        // No credential: the system does not attach one on its own, it asks the
        // user for it instead. The proxy is limited by what it will serve, not
        // by who asks (see `SangforProxyPolicy`).
        let server = NEProxyServer(address: "127.0.0.1", port: Int(preparedProxy.port))
        proxySettings.httpEnabled = true
        proxySettings.httpServer = server
        proxySettings.httpsEnabled = true
        proxySettings.httpsServer = server
        proxySettings.matchDomains = preparedProxy.matchDomains
        proxySettings.exceptionList = preparedProxy.exceptionList
        proxySettings.excludeSimpleHostnames = true
        settings.proxySettings = proxySettings
        SangforLog.network(
          "extension proxy at 127.0.0.1:\(preparedProxy.port) for "
            + "\(preparedProxy.matchDomains.count) domain suffix(es)"
        )
      }
      if let mtu = configuration.mtu, mtu > 0 {
        settings.mtu = mtu as NSNumber
      }
      // IPv4-only MVP: a documented limitation. IPv6 packets are dropped
      // with a counter instead of being mislabeled as IPv4.
      return settings
    }
    settingsFactory = makeSettings
    appliedAddress = configuration.address

    setTunnelNetworkSettings(makeSettings(configuration.address)) { [weak self] error in
      if let error {
        SangforLog.network(
          "applying tunnel settings failed: \(error.localizedDescription)"
        )
        completionHandler(error)
        return
      }
      guard let self else {
        completionHandler(nil)
        return
      }
      switch configuration.runtimeMode {
      case .loopbackBridge:
        self.startIpcListener()
        self.startPacketFlowReadLoop()
        self.scheduleBridgeTimeout()
        completionHandler(nil)
      case .extensionNative:
        self.startNativeDataPlane(
          appGroupIdentifier: self.resolvedAppGroupIdentifier(
            options: startOptions
          ),
          completionHandler: completionHandler
        )
      }
    }
  }

  /// Runs the tunnel from inside this extension: the session plan the Runner
  /// left in the App Group container is enough to bring the tunnel up, so the
  /// VPN keeps working after iOS suspends the app.
  private func startNativeDataPlane(
    appGroupIdentifier: String?,
    completionHandler: @escaping (Error?) -> Void
  ) {
    let runtime = SangforNativeTunnelRuntime(
      packetFlow: packetFlow,
      appGroupIdentifier: appGroupIdentifier,
      queue: queue,
      log: { SangforLog.network($0) }
    )
    nativeRuntime = runtime
    runtime.onVirtualAddressChange = { [weak self] addresses in
      self?.reapplyAddress(addresses)
    }
    runtime.start { [weak self] result in
      guard let self else {
        completionHandler(nil)
        return
      }
      switch result {
      case .failure(let error):
        SangforLog.providerError("native data plane failed: \(error)")
        self.nativeRuntime = nil
        completionHandler(error)
      case .success(let addresses):
        // The interface was configured with the address the app queried from
        // the gateway; the handshake is the authority. A reply addressed to
        // anything else is dropped by the kernel.
        self.reapplyAddress(addresses, completion: completionHandler)
      }
    }
  }

  /// Re-applies the tunnel settings when the gateway assigned an address other
  /// than the one the interface was configured with.
  private func reapplyAddress(
    _ addresses: [String],
    completion: ((Error?) -> Void)? = nil
  ) {
    guard
      let address = addresses.first,
      SangforIPv4.isValidIPv4Address(address),
      address != appliedAddress,
      let factory = settingsFactory
    else {
      completion?(nil)
      return
    }
    SangforLog.network(
      "the gateway assigned \(address) but the interface has "
        + "\(appliedAddress ?? "none"); re-applying the tunnel settings"
    )
    appliedAddress = address
    setTunnelNetworkSettings(factory(address)) { error in
      if let error {
        SangforLog.providerError(
          "re-applying the tunnel settings failed: \(error.localizedDescription)"
        )
      }
      completion?(error)
    }
  }

  /// The App Group normally comes from the saved provider configuration; the
  /// start options win so a caller can override it per connection.
  private func resolvedAppGroupIdentifier(
    options: [String: NSObject]
  ) -> String? {
    if let fromOptions = options["appGroupIdentifier"] as? String,
      !fromOptions.isEmpty
    {
      return fromOptions
    }
    let providerConfiguration =
      (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
    return providerConfiguration?[
      SangforTunnelConfigurationKeys.appGroupIdentifier
    ] as? String
  }

  public override func stopTunnel(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {
    SangforLog.provider("stopping tunnel, reason: \(Self.describe(reason))")
    cancelBridgeTimeout()
    readLoopRunning = false
    listener?.cancel()
    listener = nil
    bridge?.close()
    bridge = nil
    settingsFactory = nil
    appliedAddress = nil
    proxyStatsTask?.cancel()
    proxyStatsTask = nil
    proxyServer?.stop()
    proxyServer = nil
    nativeRuntime?.stop()
    nativeRuntime = nil
    // The plan carries the tunnel signing key. Wipe it when the tunnel is
    // really going away, but keep it across a transient stop: iOS restarts the
    // provider after a network change or a reboot, and the extension has to
    // come back up on its own — the Runner may not be running at all.
    switch reason {
    case .userInitiated, .providerDisabled, .appUpdate:
      SangforSharedContainer.removeSessionPlan(
        appGroupIdentifier: resolvedAppGroupIdentifier(options: [:])
      )
    default:
      SangforLog.provider("keeping the session plan for a tunnel restart")
    }
    completionHandler()
  }

  /// Settings validation failures reported from `startTunnel`.
  public enum SettingsError: Int {
    case invalidPrefixLength = 1
    case invalidAddress = 2
    case noConfiguration = 200
  }

  /// Answers control messages from the Runner (via
  /// `NETunnelProviderSession.sendProviderMessage`). Currently supports
  /// `{"action": "getStats"}`.
  override open func handleAppMessage(
    _ messageData: Data,
    completionHandler: ((Data?) -> Void)? = nil
  ) {
    guard
      let message = try? JSONDecoder().decode(
        ProviderMessage.self,
        from: messageData
      ),
      message.action == "getStats"
    else {
      completionHandler?(nil)
      return
    }
    let snapshot = queue.sync { metrics }
    var payload =
      (try? JSONSerialization.jsonObject(
        with: JSONEncoder().encode(snapshot)
      )) as? [String: Any] ?? [:]
    // The native data plane keeps its own counters; surface them under a
    // `native` key so the Runner can log both halves.
    if let native = queue.sync(execute: { nativeRuntime?.statistics }) {
      payload["native"] = [
        "egress": native.egress,
        "routed": native.routed,
        "terminated": native.terminated,
        "direct": native.direct,
        "unrouted": native.unrouted,
        "ingress": native.ingress,
        "egressBytes": native.egressBytes,
        "ingressBytes": native.ingressBytes,
        "reconnects": native.reconnects,
      ]
    }
    if let proxy = queue.sync(execute: { proxyServer?.statistics }) {
      payload["proxy"] = [
        "sessions": proxy.sessions,
        "tunneled": proxy.tunneled,
        "direct": proxy.direct,
        "rejected": proxy.rejected,
        "failures": proxy.failures,
        "upBytes": proxy.upBytes,
        "downBytes": proxy.downBytes,
      ]
    }
    completionHandler?(
      try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
    )
  }

  private struct ProviderMessage: Codable {
    var action: String
  }

  private static func readSessionPlan(appGroupIdentifier: String?) -> ATrustSessionPlan? {
    guard
      let data = SangforSharedContainer.readSessionPlan(
        appGroupIdentifier: appGroupIdentifier
      )
    else { return nil }
    return try? ATrustSessionPlan.decode(data)
  }

  // MARK: - Domain proxy

  /// Reads the plan, decides whether a proxy is worth running and starts it.
  /// Anything that stops it from being useful (no plan, proxy switched off, no
  /// domain resources, listener failure) yields nil, and the tunnel carries on
  /// without it: the IP routes still work.
  private func prepareDomainProxy(
    plan: ATrustSessionPlan?,
    completion: @escaping (PreparedProxy?) -> Void
  ) {
    guard let plan else {
      completion(nil)
      return
    }
    // Opt-in: a plan without the key (any consumer that predates it) gets no
    // proxy, so adding the feature changes nothing for them.
    guard let routing = plan.domainRouting, routing.proxyEnabled else {
      SangforLog.network("extension proxy off: not requested by the plan")
      completion(nil)
      return
    }
    let candidates = routing.policy == .custom
      ? routing.customEntries
      : plan.routes.map(\.host)
    let domains = SangforDnsDomains.derive(candidates)
    guard !domains.isEmpty else {
      SangforLog.network("extension proxy skipped: no domain resources")
      completion(nil)
      return
    }
    let policy = SangforProxyPolicy(
      matcher: SangforRouteMatcher(
        policy: routing.policy,
        customEntries: routing.customEntries,
        serverRoutes: plan.routes
      ),
      neverTunnelHosts: routing.neverTunnelHosts,
      matchDomains: domains
    )
    let server = SangforProxyServer(
      policy: policy,
      queue: queue,
      tunnelDialer: { [weak self] host, port, done in
        guard let runtime = self?.nativeRuntime else {
          done(.failure(SangforTunnelError.channelClosed("the tunnel is not running")))
          return
        }
        runtime.dialTcpTunnelForProxy(host: host, port: port, completion: done)
      },
      log: { SangforLog.network($0) }
    )
    server.start { [weak self] result in
      switch result {
      case .success(let port):
        self?.proxyServer = server
        self?.scheduleProxyStatsLogging()
        completion(
          PreparedProxy(
            port: port,
            matchDomains: domains,
            exceptionList: routing.neverTunnelHosts
          )
        )
      case .failure(let error):
        SangforLog.network(
          "extension proxy failed to start: \(error.localizedDescription)"
        )
        server.stop()
        completion(nil)
      }
    }
  }

  /// Logs the proxy's counters every 30 s so a run can be judged from the
  /// device log alone.
  private func scheduleProxyStatsLogging() {
    let work = DispatchWorkItem { [weak self] in
      guard let self, let proxy = self.proxyServer else { return }
      let stats = proxy.statistics
      SangforLog.network(
        "proxy: sessions=\(stats.sessions) tunneled=\(stats.tunneled) "
          + "direct=\(stats.direct) rejected=\(stats.rejected) "
          + "failures=\(stats.failures) up=\(stats.upBytes) down=\(stats.downBytes)"
      )
      self.scheduleProxyStatsLogging()
    }
    proxyStatsTask = work
    queue.asyncAfter(deadline: .now() + 30, execute: work)
  }

  // MARK: - Configuration

  private static func configuration(
    from options: [String: NSObject]
  ) -> SangforTunnelConfiguration {
    SangforTunnelConfiguration(
      address: (options["address"] as? String) ?? "10.0.0.2",
      prefixLength: (options["prefixLength"] as? Int) ?? 32,
      routes: (options["routes"] as? [String]) ?? [],
      dnsServers: (options["dnsServers"] as? [String]) ?? [],
      searchDomains: (options["searchDomains"] as? [String]) ?? [],
      proxyHost: options["proxyHost"] as? String,
      proxyPort: (options["proxyPort"] as? Int).flatMap { $0 > 0 ? $0 : nil },
      mtu: (options["mtu"] as? Int).flatMap { $0 > 0 ? $0 : nil },
      // An unknown or absent mode keeps the loopback bridge, so a Runner built
      // against an older core never silently loses its data plane.
      runtimeMode: SangforRuntimeMode(
        rawValue: (options["runtimeMode"] as? String) ?? ""
      ) ?? .loopbackBridge
    )
  }

  // MARK: - System packet flow

  private func startPacketFlowReadLoop() {
    guard !readLoopRunning else { return }
    readLoopRunning = true
    readPackets()
  }

  private func readPackets() {
    packetFlow.readPackets { [weak self] packets, _ in
      guard let self, self.readLoopRunning else { return }
      for packet in packets {
        // IPv4 only in this milestone: drop IPv6 with a counter instead of
        // mislabeling it when writing back.
        guard SangforIPv4.packetFamily(packet) == 4 else {
          self.queue.async { self.metrics.droppedIPv6 += 1 }
          continue
        }
        self.queue.async {
          self.metrics.packetsInFromSystem += 1
          self.metrics.bytesInFromSystem += packet.count
          self.enqueueToBridge(packet)
        }
      }
      self.readPackets()
    }
  }

  /// Must run on `queue`.
  private func enqueueToBridge(_ packet: Data) {
    if let bridge, bridge.isConnected {
      bridge.send(framed: packet) { self.metrics.droppedBackpressure += 1 }
      return
    }
    // The Runner has not connected yet: buffer a bounded amount and flush
    // once it does; anything beyond the cap is dropped with a counter.
    if pendingPackets.count >= Self.pendingPacketLimit
      || pendingBytes + packet.count > Self.pendingPacketByteLimit {
      metrics.droppedBeforeIpc += 1
      return
    }
    pendingPackets.append(packet)
    pendingBytes += packet.count
  }

  // MARK: - IPC bridge

  private func startIpcListener() {
    do {
      let params = NWParameters.tcp
      // The bridge is strictly local to the device. Without pinning the
      // endpoint to loopback, Network.framework registers the listener on
      // the primary interface only (en0), which both drops connections from
      // the Runner to 127.0.0.1 and exposes the port to the local network.
      params.requiredLocalEndpoint = NWEndpoint.hostPort(
        host: .ipv4(.loopback),
        port: NWEndpoint.Port(rawValue: Self.ipcPort)!
      )
      params.requiredInterfaceType = .loopback
      let listener = try NWListener(using: params)
      listener.newConnectionHandler = { [weak self] connection in
        self?.acceptBridgeConnection(connection)
      }
      listener.stateUpdateHandler = { state in
        if case .failed(let error) = state {
          SangforLog.ipcError("listener failed: \(error.localizedDescription)")
        }
      }
      listener.start(queue: queue)
      self.listener = listener
      SangforLog.ipc("listening on loopback:\(Self.ipcPort)")
    } catch {
      SangforLog.ipcError("IPC listener error: \(error.localizedDescription)")
    }
  }

  /// Must run on `queue`.
  private func acceptBridgeConnection(_ connection: NWConnection) {
    // New connection wins: cancel the previous generation and start a new
    // one so a Runner restart recovers cleanly.
    if bridge != nil {
      metrics.ipcReconnects += 1
    }
    bridge?.close()
    bridge = nil
    cancelBridgeTimeout()

    let bridge = IpcBridge(
      connection: connection,
      maxFrameLength: Self.maxFrameLength,
      outgoingByteLimit: Self.outgoingByteLimit
    )
    let bridgeBox = ObjectIdentifier(bridge)
    bridge.onPacket = { [weak self] packet in
      self?.inject(packet: packet)
    }
    bridge.onMalformedFrame = { [weak self] in
      self?.queue.async { self?.metrics.malformedFrames += 1 }
    }
    bridge.onReady = { [weak self] in
      guard let self else { return }
      self.flushPendingPackets()
      SangforLog.ipc("bridge connected")
    }
    bridge.onClosed = { [weak self, weak bridge] in
      guard let self else { return }
      if let current = self.bridge, ObjectIdentifier(current) == bridgeBox {
        self.bridge = nil
        // The Runner may restart and reconnect; give it a bounded window
        // before failing the tunnel.
        self.scheduleBridgeTimeout()
      }
    }
    bridge.start(queue: queue)
    self.bridge = bridge
  }

  private func inject(packet: Data) {
    guard !packet.isEmpty else { return }
    let family = SangforIPv4.packetFamily(packet) ?? 4
    let protocolFamily = family == 6 ? AF_INET6 : AF_INET
    packetFlow.writePackets([packet], withProtocols: [protocolFamily as NSNumber])
    queue.async {
      self.metrics.packetsOutToSystem += 1
      self.metrics.bytesOutToSystem += packet.count
    }
  }

  /// Must run on `queue`.
  private func flushPendingPackets() {
    guard !pendingPackets.isEmpty else { return }
    SangforLog.ipc("flushing \(pendingPackets.count) buffered packet(s)")
    for packet in pendingPackets {
      bridge?.send(framed: packet) { self.metrics.droppedBackpressure += 1 }
    }
    pendingPackets.removeAll()
    pendingBytes = 0
  }

  // MARK: - Bridge timeout

  /// Must run on `queue`.
  private func scheduleBridgeTimeout() {
    cancelBridgeTimeout()
    let work = DispatchWorkItem { [weak self] in
      guard let self, self.bridge == nil else { return }
      SangforLog.providerError(
        "no Dart bridge within \(Int(Self.bridgeReconnectTimeout))s; "
          + "cancelling tunnel"
      )
      self.cancelTunnelWithError(
        NSError(
          domain: Self.errorDomain,
          code: 100,
          userInfo: [
            NSLocalizedDescriptionKey:
              "The VPN data bridge (app side) did not connect in time."
          ]
        )
      )
    }
    bridgeTimeoutWorkItem = work
    queue.asyncAfter(
      deadline: .now() + Self.bridgeReconnectTimeout,
      execute: work
    )
  }

  /// Must run on `queue`.
  private func cancelBridgeTimeout() {
    bridgeTimeoutWorkItem?.cancel()
    bridgeTimeoutWorkItem = nil
  }

  private static func describe(_ reason: NEProviderStopReason) -> String {
    switch reason {
    case .none: "none"
    case .userInitiated: "userInitiated"
    case .providerFailed: "providerFailed"
    case .noNetworkAvailable: "noNetworkAvailable"
    case .unrecoverableNetworkChange: "unrecoverableNetworkChange"
    case .providerDisabled: "providerDisabled"
    case .authenticationCanceled: "authenticationCanceled"
    case .configurationFailed: "configurationFailed"
    case .idleTimeout: "idleTimeout"
    case .connectionFailed: "connectionFailed"
    case .appUpdate: "appUpdate"
    default: "reason(\(reason.rawValue))"
    }
  }
}

/// One framed TCP connection to the Runner's Dart bridge.
private final class IpcBridge {
  private let connection: NWConnection
  private let maxFrameLength: Int
  private let outgoingByteLimit: Int

  private var outgoing: [Data] = []
  private var outgoingBytes = 0
  private var writing = false
  private var ready = false
  private var closed = false

  var onPacket: ((Data) -> Void)?
  var onMalformedFrame: (() -> Void)?
  var onReady: (() -> Void)?
  var onClosed: (() -> Void)?

  var isConnected: Bool { ready && !closed }

  init(
    connection: NWConnection,
    maxFrameLength: Int,
    outgoingByteLimit: Int
  ) {
    self.connection = connection
    self.maxFrameLength = maxFrameLength
    self.outgoingByteLimit = outgoingByteLimit
  }

  func start(queue: DispatchQueue) {
    connection.stateUpdateHandler = { [weak self] state in
      guard let self, !self.closed else { return }
      switch state {
      case .ready:
        self.ready = true
        self.onReady?()
        self.receiveFrameHeader()
      case .failed(let error):
        SangforLog.ipcError("bridge failed: \(error.localizedDescription)")
        self.finish()
      case .cancelled:
        self.finish()
      default:
        break
      }
    }
    connection.start(queue: queue)
  }

  func close() {
    connection.cancel()
  }

  /// Sends one length-framed packet, dropping it when the outgoing queue
  /// exceeds the byte cap (bounded backpressure with a drop policy).
  func send(framed packet: Data, onDrop: @escaping () -> Void) {
    guard ready, !closed else {
      onDrop()
      return
    }
    var frame = Data(capacity: 4 + packet.count)
    var length = UInt32(packet.count).bigEndian
    withUnsafeBytes(of: &length) { frame.append(contentsOf: $0) }
    frame.append(packet)
    if outgoingBytes + frame.count > outgoingByteLimit {
      // The consumer cannot keep up; drop rather than buffer unboundedly.
      onDrop()
      return
    }
    outgoing.append(frame)
    outgoingBytes += frame.count
    drainWrites()
  }

  private func drainWrites() {
    guard !writing, !outgoing.isEmpty else { return }
    writing = true
    let frame = outgoing.removeFirst()
    outgoingBytes -= frame.count
    connection.send(content: frame, completion: .contentProcessed { [weak self] _ in
      guard let self else { return }
      self.writing = false
      self.drainWrites()
    })
  }

  private func receiveFrameHeader() {
    connection.receive(minimumIncompleteLength: 4, maximumLength: 4) {
      [weak self] data, _, isComplete, error in
      guard let self, !self.closed else { return }
      if let error {
        SangforLog.ipcError("bridge read error: \(error.localizedDescription)")
        return
      }
      if isComplete {
        // Peer closed the stream mid-session.
        self.finish()
        return
      }
      guard let data, data.count == 4 else {
        // A short, non-final header read: malformed framing.
        self.onMalformedFrame?()
        self.receiveFrameHeader()
        return
      }
      data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
        let length = UInt32(bigEndian: raw.load(as: UInt32.self))
        guard length > 0, length <= self.maxFrameLength else {
          // Zero-length or oversized: reject the frame and keep the
          // stream readable.
          self.onMalformedFrame?()
          self.receiveFrameHeader()
          return
        }
        self.receiveFramePayload(Int(length))
      }
    }
  }

  private func receiveFramePayload(_ length: Int) {
    connection.receive(
      minimumIncompleteLength: length,
      maximumLength: length
    ) { [weak self] data, _, isComplete, error in
      guard let self, !self.closed else { return }
      if let error {
        SangforLog.ipcError(
          "bridge payload error: \(error.localizedDescription)"
        )
        return
      }
      if let data, data.count == length {
        self.onPacket?(data)
      } else {
        self.onMalformedFrame?()
      }
      if isComplete {
        self.finish()
        return
      }
      self.receiveFrameHeader()
    }
  }

  private func finish() {
    guard !closed else { return }
    closed = true
    outgoing.removeAll()
    outgoingBytes = 0
    onClosed?()
  }
}
