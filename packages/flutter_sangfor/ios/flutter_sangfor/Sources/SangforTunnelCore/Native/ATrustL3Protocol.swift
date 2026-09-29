import Foundation

/// Errors raised while encoding or decoding tunnel protocol data.
public enum SangforProtocolError: Error, CustomStringConvertible, Equatable {
  case truncated(String)
  case unexpectedVersion(UInt8)
  case unexpectedCommand(UInt8)
  case unexpectedMarker(String)
  case invalidLength(String)
  case unsupportedAddressType(UInt8)
  case invalidStatus(String)

  public var description: String {
    switch self {
    case .truncated(let what): "truncated \(what)"
    case .unexpectedVersion(let value):
      "unexpected protocol version 0x\(String(value, radix: 16))"
    case .unexpectedCommand(let value):
      "unknown tunnel command 0x\(String(value, radix: 16))"
    case .unexpectedMarker(let what): "unexpected \(what)"
    case .invalidLength(let what): "invalid \(what) length"
    case .unsupportedAddressType(let value):
      "unsupported address type 0x\(String(value, radix: 16))"
    case .invalidStatus(let what): what
    }
  }
}

/// L3 tunnel commands (the high bit marks a response).
public enum ATrustL3Command: UInt8 {
  case authRequest = 0x13
  case dataRequest = 0x14
  case heartbeatRequest = 0x15
  case authResponse = 0x93
  case dataResponse = 0x94
  case heartbeatResponse = 0x95
  case secondVipResponse = 0x96

  /// True when the frame header carries a one-byte status field.
  var hasStatus: Bool {
    self == .authResponse || self == .secondVipResponse
  }
}

/// One decoded L3 frame.
public struct ATrustL3Frame {
  public let command: ATrustL3Command
  public let status: Int
  public let payload: Data

  public init(command: ATrustL3Command, status: Int, payload: Data) {
    self.command = command
    self.status = status
    self.payload = payload
  }
}

/// The five-tuple of a flow, as the gateway expects it in an auth request.
public struct ATrustL3IpInfo: Equatable {
  public let atype: Int
  /// The IP protocol number; the JSON key stays `protocol`.
  public let protocolNumber: Int
  public let destinationAddress: String
  public let destinationPort: Int
  public let sourceAddress: String
  public let sourcePort: Int

  public init(
    atype: Int,
    protocolNumber: Int,
    destinationAddress: String,
    destinationPort: Int,
    sourceAddress: String,
    sourcePort: Int
  ) {
    self.atype = atype
    self.protocolNumber = protocolNumber
    self.destinationAddress = destinationAddress
    self.destinationPort = destinationPort
    self.sourceAddress = sourceAddress
    self.sourcePort = sourcePort
  }

  /// Field order matters: the body is signed.
  func jsonValue() -> SangforJsonValue {
    .object([
      SangforJsonMember("atype", .int(atype)),
      SangforJsonMember("protocol", .int(protocolNumber)),
      SangforJsonMember("destAddr", .string(destinationAddress)),
      SangforJsonMember("destPort", .int(destinationPort)),
      SangforJsonMember("srcAddr", .string(sourceAddress)),
      SangforJsonMember("srcPort", .int(sourcePort)),
    ])
  }
}

/// The process identity reported with every request.
public struct ATrustProcessInfo: Equatable {
  public let name: String
  public let path: String
  public let platform: String
  public let digitalSignature: String
  public let description: String
  public let version: String
  public let securityEnv: String

  public init(
    name: String,
    path: String,
    platform: String,
    digitalSignature: String = "TrustAppClosed",
    description: String = "TrustAppClosed",
    version: String = "TrustAppClosed",
    securityEnv: String = "normal"
  ) {
    self.name = name
    self.path = path
    self.platform = platform
    self.digitalSignature = digitalSignature
    self.description = description
    self.version = version
    self.securityEnv = securityEnv
  }

  /// `sha256(path)`, uppercase hex — what the gateway calls the fingerprint.
  public var fingerprint: String {
    SangforSha256.hex(SangforSha256.hash(ofString: path))
  }

  func jsonValue() -> SangforJsonValue {
    .object([
      SangforJsonMember("name", .string(name)),
      SangforJsonMember("digital_signature", .string(digitalSignature)),
      SangforJsonMember("platform", .string(platform)),
      SangforJsonMember("fingerprint", .string(fingerprint)),
      SangforJsonMember("description", .string(description)),
      SangforJsonMember("path", .string(path)),
      SangforJsonMember("version", .string(version)),
      SangforJsonMember("security_env", .string(securityEnv)),
    ])
  }

  /// The `env` block of a signed request.
  public func envJsonValue() -> SangforJsonValue {
    .object([
      SangforJsonMember(
        "application",
        .object([
          SangforJsonMember(
            "runtime",
            .object([
              SangforJsonMember("process", jsonValue()),
              SangforJsonMember("process_trusted", .string("TRUSTED")),
            ])
          )
        ])
      )
    ])
  }
}

/// A per-flow L3 authentication request.
public struct ATrustL3AuthRequest {
  public let sid: String
  public let appId: String
  public let url: String
  public let deviceId: String
  public let connectionId: String
  public let lang: String
  public let conntrackHash: Int
  public let ip: ATrustL3IpInfo
  public let procHash: String?
  public let appToken: String?
  public let rcAppliedInfo: Int
  public let env: ATrustProcessInfo?
  public let domain: String?

  public init(
    sid: String,
    appId: String,
    url: String,
    deviceId: String,
    connectionId: String,
    lang: String,
    conntrackHash: Int,
    ip: ATrustL3IpInfo,
    procHash: String? = nil,
    appToken: String? = nil,
    rcAppliedInfo: Int = 0,
    env: ATrustProcessInfo? = nil,
    domain: String? = nil
  ) {
    self.sid = sid
    self.appId = appId
    self.url = url
    self.deviceId = deviceId
    self.connectionId = connectionId
    self.lang = lang
    self.conntrackHash = conntrackHash
    self.ip = ip
    self.procHash = procHash
    self.appToken = appToken
    self.rcAppliedInfo = rcAppliedInfo
    self.env = env
    self.domain = domain
  }

  /// The signed body, in the exact key order the gateway expects.
  public func unsignedMembers() -> [SangforJsonMember] {
    var members: [SangforJsonMember] = [
      SangforJsonMember("sid", .string(sid)),
      SangforJsonMember("appId", .string(appId)),
    ]
    if let procHash {
      members.append(SangforJsonMember("procHash", .string(procHash)))
    }
    if let appToken {
      members.append(SangforJsonMember("appToken", .string(appToken)))
    }
    members.append(contentsOf: [
      SangforJsonMember("url", .string(url)),
      SangforJsonMember("deviceId", .string(deviceId)),
      SangforJsonMember("connectionId", .string(connectionId)),
      SangforJsonMember("rcAppliedInfo", .int(rcAppliedInfo)),
      SangforJsonMember("lang", .string(lang)),
    ])
    if let env {
      members.append(SangforJsonMember("env", env.envJsonValue()))
    }
    members.append(SangforJsonMember("conntrackHash", .int(conntrackHash)))
    members.append(SangforJsonMember("ip", ip.jsonValue()))
    if let domain {
      members.append(SangforJsonMember("domain", .string(domain)))
    }
    return members
  }

  public func unsignedJsonBytes() -> [UInt8] {
    SangforJsonEncoder.encodeToBytes(.object(unsignedMembers()))
  }

  public func signature(signKey: [UInt8]) -> String {
    SangforSha256.hex(
      SangforSha256.hmac(key: signKey, message: unsignedJsonBytes())
    )
  }

  public func signedMembers(signKey: [UInt8]) -> [SangforJsonMember] {
    unsignedMembers()
      + [SangforJsonMember("xRequestSig", .string(signature(signKey: signKey)))]
  }
}

/// Frame construction and parsing for the aTrust L3 tunnel.
public enum ATrustL3Protocol {
  public static let version: UInt8 = 0x05

  /// Opens the tunnel and asks for the client virtual IP.
  public static func authTunnelRequest(sid: String) throws -> Data {
    let payload = SangforJsonEncoder.encode(
      .object([SangforJsonMember("sid", .string(sid))])
    )
    guard payload.count <= 0xffff else {
      throw SangforProtocolError.invalidLength("authTunnel payload")
    }
    var frame = Data([version, 0x01, 0xD0, 0x53, 0x00])
    frame.append(bigEndian16(UInt16(payload.count)))
    frame.append(payload)
    frame.append(
      Data([0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    )
    return frame
  }

  /// Carries one raw IP packet, addressed by its flow token.
  public static func dataRequest(token: String, packet: Data) throws -> Data {
    let tokenBytes = Data(token.utf8)
    guard tokenBytes.count <= 255 else {
      throw SangforProtocolError.invalidLength("flow token")
    }
    guard packet.count <= 0xffff else {
      throw SangforProtocolError.invalidLength("data payload")
    }
    var frame = Data([version, ATrustL3Command.dataRequest.rawValue])
    frame.append(UInt8(tokenBytes.count))
    frame.append(tokenBytes)
    frame.append(Data([0x00, 0x00, 0x01]))
    frame.append(bigEndian16(UInt16(packet.count)))
    frame.append(packet)
    return frame
  }

  public static func heartbeatRequest() -> Data {
    Data([version, ATrustL3Command.heartbeatRequest.rawValue, 0x00, 0x00])
  }

  /// A flow authentication request frame (command 0x13).
  public static func authRequestFrame(
    _ request: ATrustL3AuthRequest,
    signKey: [UInt8]
  ) throws -> Data {
    let payload = SangforJsonEncoder.encode(
      .object(request.signedMembers(signKey: signKey))
    )
    guard payload.count <= 0xffff else {
      throw SangforProtocolError.invalidLength("auth request payload")
    }
    var frame = Data([version, ATrustL3Command.authRequest.rawValue])
    frame.append(bigEndian16(UInt16(payload.count)))
    frame.append(payload)
    return frame
  }

  /// Decodes exactly one complete frame.
  public static func decodeFrame(_ bytes: Data) throws -> ATrustL3Frame {
    let raw = [UInt8](bytes)
    guard raw.count >= 4 else {
      throw SangforProtocolError.truncated("frame header")
    }
    guard raw[0] == version else {
      throw SangforProtocolError.unexpectedVersion(raw[0])
    }
    guard let command = ATrustL3Command(rawValue: raw[1]) else {
      throw SangforProtocolError.unexpectedCommand(raw[1])
    }
    var offset = 2
    var status = 0
    if command.hasStatus {
      guard raw.count >= 5 else {
        throw SangforProtocolError.truncated("frame status")
      }
      status = Int(raw[offset])
      offset += 1
    }
    let length = Int(raw[offset]) << 8 | Int(raw[offset + 1])
    offset += 2
    guard length <= 0xffff, raw.count == offset + length else {
      throw SangforProtocolError.invalidLength("frame payload")
    }
    return ATrustL3Frame(
      command: command,
      status: status,
      payload: Data(raw[offset..<(offset + length)])
    )
  }

  /// The length of the virtual-IP data that follows an initial VIP header.
  public static func parseInitialVIPHeader(_ header: Data) throws -> Int {
    let raw = [UInt8](header)
    guard raw.count == 4 else {
      throw SangforProtocolError.invalidLength("VIP header")
    }
    guard raw[0] == version else {
      throw SangforProtocolError.unexpectedVersion(raw[0])
    }
    guard raw[1] == 0 else {
      throw SangforProtocolError.invalidStatus("VIP status \(raw[1])")
    }
    switch raw[3] {
    case 1: return 6
    case 4: return 18
    case 5: return 22
    default: throw SangforProtocolError.unsupportedAddressType(raw[3])
    }
  }

  /// The addresses carried by an initial VIP payload.
  public static func parseVirtualIPData(_ data: Data) throws -> [String] {
    let raw = [UInt8](data)
    switch raw.count {
    case 6:
      return ["\(raw[0]).\(raw[1]).\(raw[2]).\(raw[3])"]
    case 18:
      return [SangforAddressText.ipv6(Array(raw[0..<16]))]
    case 22:
      return [
        "\(raw[0]).\(raw[1]).\(raw[2]).\(raw[3])",
        SangforAddressText.ipv6(Array(raw[4..<20])),
      ]
    default:
      throw SangforProtocolError.invalidLength("VIP data")
    }
  }

  /// The addresses of a second-VIP (0x96) response body.
  public static func extractVIPs(_ payload: Data) -> [String] {
    guard let object = SangforJsonObject.parse(payload) else { return [] }
    var addresses: [String] = []
    let nested = object.object("data")
    for key in ["vip", "vip6"] {
      let value = object.string(key) ?? nested?.string(key) ?? ""
      guard !value.isEmpty else { continue }
      addresses.append(value)
    }
    return addresses
  }

  /// Splits the packets of a data-response body when the gateway frames them
  /// with a token and per-packet lengths.
  public static func parseDataPayload(_ payload: Data) throws -> [Data] {
    let raw = [UInt8](payload)
    guard raw.count >= 4 else {
      throw SangforProtocolError.truncated("data payload")
    }
    var index = 1 + Int(raw[0])
    guard raw.count >= index + 3 else {
      throw SangforProtocolError.truncated("data payload token")
    }
    index += 2
    let count = Int(raw[index])
    index += 1
    var packets: [Data] = []
    for _ in 0..<count {
      guard index + 2 <= raw.count else {
        throw SangforProtocolError.truncated("packet length")
      }
      let length = Int(raw[index]) << 8 | Int(raw[index + 1])
      index += 2
      guard index + length <= raw.count else {
        throw SangforProtocolError.truncated("packet data")
      }
      packets.append(Data(raw[index..<(index + length)]))
      index += length
    }
    return packets
  }

  static func bigEndian16(_ value: UInt16) -> Data {
    Data([UInt8(value >> 8), UInt8(value & 0xff)])
  }
}

/// Incremental decoder that turns transport chunks into L3 frames.
///
/// The buffer is a plain byte array rather than `Data`: `Data` slices keep
/// their parent's index base, which silently shifts every `subdata(in:)` range.
public final class ATrustL3FrameStreamDecoder {
  private var buffer: [UInt8] = []

  public init() {}

  /// Appends a chunk and returns every frame that is now complete.
  public func add(_ chunk: Data) throws -> [ATrustL3Frame] {
    buffer.append(contentsOf: chunk)
    var frames: [ATrustL3Frame] = []
    while let (frame, consumed) = try decodeOne() {
      frames.append(frame)
      buffer.removeFirst(consumed)
    }
    return frames
  }

  public func reset() {
    buffer.removeAll(keepingCapacity: true)
  }

  private func decodeOne() throws -> (ATrustL3Frame, Int)? {
    let raw = buffer
    guard raw.count >= 2 else { return nil }
    guard raw[0] == ATrustL3Protocol.version else {
      throw SangforProtocolError.unexpectedVersion(raw[0])
    }
    guard let command = ATrustL3Command(rawValue: raw[1]) else {
      throw SangforProtocolError.unexpectedCommand(raw[1])
    }
    let headerLength = command.hasStatus ? 5 : 4
    guard raw.count >= headerLength else { return nil }
    let lengthOffset = command.hasStatus ? 3 : 2
    let length = Int(raw[lengthOffset]) << 8 | Int(raw[lengthOffset + 1])
    let total = headerLength + length
    guard raw.count >= total else { return nil }
    let frame = try ATrustL3Protocol.decodeFrame(Data(raw[0..<total]))
    return (frame, total)
  }
}

/// The result of the initial tunnel handshake.
public struct ATrustL3TunnelAuthResult: Equatable {
  public let authStatus: Int
  public let deviceId: String?
  public let virtualIP: [String]

  public init(authStatus: Int, deviceId: String?, virtualIP: [String]) {
    self.authStatus = authStatus
    self.deviceId = deviceId
    self.virtualIP = virtualIP
  }
}

/// Incremental parser for the authTunnel response sequence:
/// method ack, auth response, auth payload, VIP header, VIP data.
///
/// Like the frame decoder this buffers plain bytes: `Data` slices carry their
/// parent's index base, which would shift every range computed against them.
public final class ATrustL3HandshakeParser {
  private enum Phase: Int {
    case methodAck, authHeader, authPayload, vipHeader, vipData
  }

  private var buffer: [UInt8] = []
  private var phase: Phase = .methodAck
  private var authLength = 0
  private var vipLength = 0
  private var deviceId: String?

  public init() {}

  /// Feeds a chunk. Returns the result plus the unconsumed leftover bytes once
  /// the whole sequence has arrived.
  public func add(_ chunk: Data) throws -> (ATrustL3TunnelAuthResult, Data)? {
    buffer.append(contentsOf: chunk)
    while true {
      switch phase {
      case .methodAck:
        guard buffer.count >= 2 else { return nil }
        guard buffer[0] == ATrustL3Protocol.version, buffer[1] == 0xD0 else {
          throw SangforProtocolError.unexpectedMarker(
            "L3 tunnel auth method response 0x\(String(buffer[0], radix: 16)) "
              + "0x\(String(buffer[1], radix: 16))"
          )
        }
        buffer.removeFirst(2)
        phase = .authHeader

      case .authHeader:
        guard buffer.count >= 4 else { return nil }
        guard buffer[0] == 0x53 else {
          throw SangforProtocolError.unexpectedMarker(
            "L3 tunnel auth response version 0x\(String(buffer[0], radix: 16))"
          )
        }
        let status = Int(buffer[1])
        authLength = Int(buffer[2]) << 8 | Int(buffer[3])
        buffer.removeFirst(4)
        guard status == 0 else {
          throw SangforProtocolError.invalidStatus(
            "L3 tunnel auth status \(status)"
          )
        }
        phase = .authPayload

      case .authPayload:
        guard buffer.count >= authLength else { return nil }
        let payload = Data(buffer[0..<authLength])
        buffer.removeFirst(authLength)
        if authLength > 0, let object = SangforJsonObject.parse(payload) {
          let code = object.int("code") ?? 0
          if code != 0 {
            throw SangforProtocolError.invalidStatus(
              "L3 tunnel auth failed: code \(code): "
                + "\(object.string("message") ?? "")"
            )
          }
          deviceId = object.object("data")?.string("deviceId")
        }
        phase = .vipHeader

      case .vipHeader:
        guard buffer.count >= 4 else { return nil }
        vipLength = try ATrustL3Protocol.parseInitialVIPHeader(
          Data(buffer[0..<4])
        )
        buffer.removeFirst(4)
        phase = .vipData

      case .vipData:
        guard buffer.count >= vipLength else { return nil }
        let payload = Data(buffer[0..<vipLength])
        buffer.removeFirst(vipLength)
        let addresses = try ATrustL3Protocol.parseVirtualIPData(payload)
        let leftover = Data(buffer)
        buffer.removeAll(keepingCapacity: false)
        return (
          ATrustL3TunnelAuthResult(
            authStatus: 0,
            deviceId: deviceId,
            virtualIP: addresses
          ),
          leftover
        )
      }
    }
  }
}

/// Text formatting for addresses, matching the reference client.
public enum SangforAddressText {
  /// Compressed textual form of an IPv6 address.
  public static func ipv6(_ bytes: [UInt8]) -> String {
    guard bytes.count == 16 else { return "" }
    var groups: [String] = []
    for index in stride(from: 0, to: 16, by: 2) {
      let value = Int(bytes[index]) << 8 | Int(bytes[index + 1])
      groups.append(String(value, radix: 16))
    }
    // Longest run of zero groups collapses to "::".
    var bestStart = -1
    var bestLength = 0
    var start = -1
    var length = 0
    for (index, group) in groups.enumerated() {
      if group == "0" {
        if start < 0 {
          start = index
          length = 1
        } else {
          length += 1
        }
        if length > bestLength {
          bestStart = start
          bestLength = length
        }
      } else {
        start = -1
        length = 0
      }
    }
    guard bestLength > 1 else { return groups.joined(separator: ":") }
    let head = groups[0..<bestStart].joined(separator: ":")
    let tail = groups[(bestStart + bestLength)...].joined(separator: ":")
    if head.isEmpty && tail.isEmpty { return "::" }
    if head.isEmpty { return "::" + tail }
    if tail.isEmpty { return head + "::" }
    return head + "::" + tail
  }

  /// Dotted-quad form of an IPv4 address.
  public static func ipv4(_ bytes: [UInt8]) -> String {
    guard bytes.count == 4 else { return "" }
    return "\(bytes[0]).\(bytes[1]).\(bytes[2]).\(bytes[3])"
  }
}
