import Foundation
import NetworkExtension
import Network

/// PacketTunnelProvider that bridges the iOS system VPN packet flow to the
/// Flutter app via a local TCP loopback socket (port 6400). Each packet is
/// framed with a 4-byte big-endian length prefix in both directions.
class SangforPacketTunnelProvider: NEPacketTunnelProvider {
  private var listener: NWListener?
  private var connection: NWConnection?
  private var readLoopRunning = false
  private let queue = DispatchQueue(label: "flutter_sangfor.ne")
  private let ipcPort: UInt16 = 6400
  private var address = "10.0.0.2"
  private var prefixLength: Int = 32
  private var routes: [String] = []
  private var dnsServers: [String] = []

  override func startTunnel(
    options: [String: NSObject]?,
    completionHandler: @escaping (Error?) -> Void
  ) {
    if let options = options {
      address = options["address"] as? String ?? address
      prefixLength = options["prefixLength"] as? Int ?? prefixLength
      routes = options["routes"] as? [String] ?? routes
      dnsServers = options["dnsServers"] as? [String] ?? dnsServers
    }
    let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: address)
    let ipv4 = NEIPv4Settings(addresses: [address], subnetMasks: ["255.255.255.255"])
    ipv4.includedRoutes = routes.map { route in
      let parts = route.split(separator: "/")
      guard parts.count == 2, let prefix = UInt32(parts[1]) else {
        return NEIPv4Route.default()
      }
      return NEIPv4Route(destinationAddress: String(parts[0]), subnetMask: prefixToMask(prefix))
    }
    settings.ipv4Settings = ipv4
    settings.dnsSettings = NEDNSSettings(servers: dnsServers)
    setTunnelNetworkSettings(settings) { [weak self] error in
      if let error = error {
        completionHandler(error)
        return
      }
      self?.startIpcListener()
      self?.startPacketFlowReadLoop()
      completionHandler(nil)
    }
  }

  private func prefixToMask(_ prefix: UInt32) -> String {
    if prefix == 0 { return "0.0.0.0" }
    let mask = prefix >= 32 ? 0xffffffff : (0xffffffff << (32 - prefix))
    return String(
      format: "%d.%d.%d.%d",
      (mask >> 24) & 0xff,
      (mask >> 16) & 0xff,
      (mask >> 8) & 0xff,
      mask & 0xff
    )
  }

  override func stopTunnel(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {
    listener?.cancel()
    listener = nil
    connection?.cancel()
    connection = nil
    readLoopRunning = false
    completionHandler()
  }

  private func startIpcListener() {
    do {
      let params = NWParameters.tcp
      params.allowLocalEndpointReuse = true
      let listener = try NWListener(using: params, on: NWEndpoint.Port(rawValue: ipcPort)!)
      listener.newConnectionHandler = { [weak self] connection in
        self?.connection = connection
        self?.startIpcReadLoop(connection: connection)
      }
      listener.start(queue: queue)
      self.listener = listener
    } catch {
      NSLog("flutter_sangfor NE: IPC listener error: \(error)")
    }
  }

  private func startPacketFlowReadLoop() {
    guard !readLoopRunning else { return }
    readLoopRunning = true
    readPackets()
  }

  private func readPackets() {
    packetFlow.readPackets { [weak self] packets, _ in
      guard let self = self else { return }
      for packet in packets {
        self.sendToApp(packet)
           }
      if self.readLoopRunning {
        self.readPackets()
      }
    }
  }

  private func sendToApp(_ packet: Data) {
    guard let connection = connection else { return }
    var framed = Data()
    var length = UInt32(packet.count).bigEndian
    withUnsafeBytes(of: &length) { framed.append(contentsOf: $0) }
    framed.append(packet)
    connection.send(content: framed, completion: .contentProcessed { _ in })
  }

  private func startIpcReadLoop(connection: NWConnection) {
    connection.start(queue: queue)
    readFromApp(connection: connection)
  }

  private func readFromApp(connection: NWConnection) {
    // Length prefix.
    connection.receive(minimumIncompleteLength: 4, maximumLength: 4) { [weak self] data, _, isComplete, error in
      guard let self = self else { return }
      if let error = error {
        NSLog("flutter_sangfor NE: read error: \(error)")
        return
      }
      guard let data = data, data.count == 4 else { return }
      data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
        let length = UInt32(bigEndian: raw.load(as: UInt32.self))
        guard length > 0, length <= 0xffff else {
          self.readFromApp(connection: connection)
          return
        }
        connection.receive(
          minimumIncompleteLength: Int(length),
          maximumLength: Int(length)
        ) { packetData, _, _, packetError in
          if let packetError = packetError {
            NSLog("flutter_sangfor NE: packet read error: \(packetError)")
            return
          }
          if let packetData = packetData {
            self.packetFlow.writePackets([packetData], withProtocols: [AF_INET as NSNumber])
          }
          self.readFromApp(connection: connection)
        }
      }
    }
  }
}
