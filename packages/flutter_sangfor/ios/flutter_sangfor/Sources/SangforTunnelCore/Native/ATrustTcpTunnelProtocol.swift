import Foundation

/// A TCP-tunnel (SOCKS5-like) authentication request.
public struct ATrustTcpTunnelAuthRequest {
  public let sid: String
  public let appId: String
  public let url: String
  public let deviceId: String
  public let connectionId: String
  public let procHash: String
  public let userName: String
  public let lang: String
  public let destAddr: String
  public let destIp: String?
  public let rcAppliedInfo: Int
  public let process: ATrustProcessInfo?

  public init(
    sid: String,
    appId: String,
    url: String,
    deviceId: String,
    connectionId: String,
    procHash: String,
    userName: String,
    lang: String,
    destAddr: String,
    destIp: String? = nil,
    rcAppliedInfo: Int = 0,
    process: ATrustProcessInfo? = nil
  ) {
    self.sid = sid
    self.appId = appId
    self.url = url
    self.deviceId = deviceId
    self.connectionId = connectionId
    self.procHash = procHash
    self.userName = userName
    self.lang = lang
    self.destAddr = destAddr
    self.destIp = destIp
    self.rcAppliedInfo = rcAppliedInfo
    self.process = process
  }

  /// Field order is part of the signed bytes.
  public func unsignedMembers() -> [SangforJsonMember] {
    var members: [SangforJsonMember] = [
      SangforJsonMember("sid", .string(sid)),
      SangforJsonMember("appId", .string(appId)),
      SangforJsonMember("url", .string(url)),
      SangforJsonMember("deviceId", .string(deviceId)),
      SangforJsonMember("connectionId", .string(connectionId)),
      SangforJsonMember("procHash", .string(procHash)),
      SangforJsonMember("userName", .string(userName)),
      SangforJsonMember("rcAppliedInfo", .int(rcAppliedInfo)),
      SangforJsonMember("lang", .string(lang)),
      SangforJsonMember("destAddr", .string(destAddr)),
    ]
    if let destIp {
      members.append(SangforJsonMember("destIP", .string(destIp)))
    }
    let processValue: SangforJsonValue = process?.envJsonValue() ?? .object([])
    members.append(
      SangforJsonMember(
        "env",
        process.map { info in
          SangforJsonValue.object([
            SangforJsonMember(
              "application",
              .object([
                SangforJsonMember(
                  "runtime",
                  .object([
                    SangforJsonMember("process", info.jsonValue()),
                    SangforJsonMember("process_trusted", .string("TRUSTED")),
                  ])
                )
              ])
            )
          ])
        } ?? processValue
      )
    )
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

/// The gateway's answer to a TCP-tunnel handshake.
public struct ATrustTcpTunnelServerResponse: Equatable {
  public let authCode: Int
  public let authMessage: String
  public let connectStatus: Int
  public let reuse: Bool
  public let consumed: Int

  public init(
    authCode: Int,
    authMessage: String,
    connectStatus: Int,
    reuse: Bool,
    consumed: Int
  ) {
    self.authCode = authCode
    self.authMessage = authMessage
    self.connectStatus = connectStatus
    self.reuse = reuse
    self.consumed = consumed
  }
}

/// Frame construction and parsing for the aTrust TCP tunnel.
public enum ATrustTcpTunnelProtocol {
  public static let version: UInt8 = 0x05
  public static let maximumFramePayload = 0xffff

  /// The opening message: auth header, signed JSON, then the destination.
  public static func handshakeMessage(
    _ request: ATrustTcpTunnelAuthRequest,
    signKey: [UInt8],
    host: String,
    port: Int,
    zeroRtt: Bool = false
  ) throws -> Data {
    let authJson = SangforJsonEncoder.encode(
      .object(request.signedMembers(signKey: signKey))
    )
    guard authJson.count <= maximumFramePayload else {
      throw SangforProtocolError.invalidLength("TCP tunnel auth request")
    }
    var message = Data([version, 0x01, 0x81, 0x53, 0x03])
    message.append(ATrustL3Protocol.bigEndian16(UInt16(authJson.count)))
    message.append(authJson)
    message.append(try destinationMessage(host, port: port, zeroRtt: zeroRtt))
    return message
  }

  /// The destination record: address type, address, port.
  public static func destinationMessage(
    _ host: String,
    port: Int,
    zeroRtt: Bool = false
  ) throws -> Data {
    var message = Data([version, 0x01, zeroRtt ? 1 : 0])
    if let ipv4 = SangforAddressBytes.ipv4(host) {
      message.append(0x01)
      message.append(contentsOf: ipv4)
    } else if let ipv6 = SangforAddressBytes.ipv6(host) {
      message.append(0x04)
      message.append(contentsOf: ipv6)
    } else {
      let hostBytes = Data(host.utf8)
      guard hostBytes.count <= 255 else {
        throw SangforProtocolError.invalidLength("TCP tunnel destination host")
      }
      message.append(0x03)
      message.append(UInt8(hostBytes.count))
      message.append(hostBytes)
    }
    message.append(ATrustL3Protocol.bigEndian16(UInt16(port & 0xffff)))
    return message
  }

  public static func dataFrame(_ data: Data) throws -> Data {
    guard data.count <= maximumFramePayload else {
      throw SangforProtocolError.invalidLength("TCP tunnel data frame")
    }
    var frame = Data([0x01, 0x00])
    frame.append(ATrustL3Protocol.bigEndian16(UInt16(data.count)))
    frame.append(data)
    return frame
  }

  /// Splits [data] into as many frames as the 16-bit length allows.
  public static func dataFrames(_ data: Data) -> [Data] {
    guard !data.isEmpty else { return [] }
    let bytes = [UInt8](data)
    var frames: [Data] = []
    var offset = 0
    while offset < bytes.count {
      let end = min(offset + maximumFramePayload, bytes.count)
      frames.append(try! dataFrame(Data(bytes[offset..<end])))
      offset = end
    }
    return frames
  }

  public static func eofFrame() -> Data {
    Data([0x01, 0x01, 0x00, 0x00])
  }

  /// Parses one complete data frame, or nil when more bytes are needed.
  public static func parseDataFrame(
    _ bytes: [UInt8]
  ) throws -> (data: Data, eof: Bool, consumed: Int)? {
    guard bytes.count >= 4 else { return nil }
    guard bytes[0] == 0x01 else {
      throw SangforProtocolError.unexpectedMarker("TCP tunnel data frame header")
    }
    if bytes[1] == 0x01 {
      return (Data(), true, bytes.count)
    }
    guard bytes[1] == 0x00 else {
      throw SangforProtocolError.unexpectedMarker("TCP tunnel data frame type")
    }
    let length = Int(bytes[2]) << 8 | Int(bytes[3])
    guard bytes.count >= 4 + length else { return nil }
    return (Data(bytes[4..<(4 + length)]), false, 4 + length)
  }

  public static func parseServerResponse(_ data: Data) throws
    -> ATrustTcpTunnelServerResponse
  {
    try ATrustTcpTunnelHandshakeParser.parseComplete(data)
  }

  public static func connectStatusMessage(_ status: Int) -> String {
    switch status {
    case 0x00: "success"
    case 0x01: "tcp tunnel server failure"
    case 0x02: "tcp tunnel connection not allowed"
    case 0x03: "network is unreachable"
    case 0x04: "host is unreachable"
    case 0x05: "connection refused"
    case 0x06: "tcp tunnel TTL expired"
    case 0x07: "tcp tunnel command not supported"
    case 0x08: "tcp tunnel address type not supported"
    default:
      "tcp tunnel connect failed with status 0x\(String(status, radix: 16))"
    }
  }
}

/// Incremental parser for the TCP tunnel server hello.
///
/// The hello is `05 81 53 00 <len16> <auth json> 05 <status> <reuse> <atype>
/// <bind address> <port>`; anything after it is already tunnel payload.
public final class ATrustTcpTunnelHandshakeParser {
  private var buffer: [UInt8] = []
  public private(set) var response: ATrustTcpTunnelServerResponse?

  public init() {}

  /// Feeds a chunk. Returns the bytes that follow the handshake once it has
  /// completed, or nil while more bytes are needed.
  public func add(_ chunk: Data) throws -> Data? {
    guard response == nil else { return chunk }
    buffer.append(contentsOf: chunk)
    let parsed = try Self.parse(from: buffer)
    guard let parsed else { return nil }
    response = parsed.response
    let leftover = Data(parsed.consumed < buffer.count
      ? buffer[parsed.consumed...]
      : [])
    buffer.removeAll(keepingCapacity: false)
    return leftover
  }

  static func parseComplete(_ data: Data) throws -> ATrustTcpTunnelServerResponse {
    guard let parsed = try parse(from: [UInt8](data)) else {
      throw SangforProtocolError.truncated("TCP tunnel server hello")
    }
    return parsed.response
  }

  private static func parse(
    from bytes: [UInt8]
  ) throws -> (response: ATrustTcpTunnelServerResponse, consumed: Int)? {
    guard bytes.count >= 2 else { return nil }
    guard bytes[0] == ATrustTcpTunnelProtocol.version, bytes[1] == 0x81 else {
      throw SangforProtocolError.unexpectedMarker("TCP tunnel server hello")
    }
    guard bytes.count >= 4 else { return nil }
    guard bytes[2] == 0x53, bytes[3] == 0x00 else {
      throw SangforProtocolError.unexpectedMarker("TCP tunnel auth response")
    }
    guard bytes.count >= 6 else { return nil }
    let authLength = Int(bytes[4]) << 8 | Int(bytes[5])
    guard bytes.count >= 6 + authLength else { return nil }
    let authPayload = Data(bytes[6..<(6 + authLength)])
    var offset = 6 + authLength
    guard bytes.count >= offset + 4 else { return nil }
    guard bytes[offset] == ATrustTcpTunnelProtocol.version else {
      throw SangforProtocolError.unexpectedMarker(
        "TCP tunnel connect reply version"
      )
    }
    let connectStatus = Int(bytes[offset + 1])
    var authCode = 0
    var authMessage = ""
    if authLength > 0, let object = SangforJsonObject.parse(authPayload) {
      authCode = object.int("code") ?? -1
      authMessage = object.string("message") ?? ""
    } else if authLength > 0 {
      authCode = -1
      authMessage = "invalid auth response"
    }
    if connectStatus != 0 {
      return (
        ATrustTcpTunnelServerResponse(
          authCode: authCode,
          authMessage: authMessage,
          connectStatus: connectStatus,
          reuse: false,
          consumed: offset + 4
        ),
        offset + 4
      )
    }
    let reuse = bytes[offset + 2] == 0x01
    let addressType = bytes[offset + 3]
    let addressLength: Int
    switch addressType {
    case 0x01: addressLength = 4
    case 0x04: addressLength = 16
    default:
      throw SangforProtocolError.unsupportedAddressType(addressType)
    }
    let total = offset + 4 + addressLength + 2
    guard bytes.count >= total else { return nil }
    return (
      ATrustTcpTunnelServerResponse(
        authCode: authCode,
        authMessage: authMessage,
        connectStatus: connectStatus,
        reuse: reuse,
        consumed: total
      ),
      total
    )
  }
}

/// Address parsing helpers shared by the protocol encoders.
public enum SangforAddressBytes {
  /// The four bytes of a dotted-quad address, or nil when [text] is not one.
  public static func ipv4(_ text: String) -> [UInt8]? {
    let parts = text.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return nil }
    var bytes: [UInt8] = []
    for part in parts {
      guard part.count <= 3, let value = Int(part), (0...255).contains(value)
      else { return nil }
      bytes.append(UInt8(value))
    }
    return bytes
  }

  /// The sixteen bytes of a textual IPv6 address, or nil when [text] is not
  /// one. Handles `::` compression and an embedded trailing IPv4 quad.
  public static func ipv6(_ text: String) -> [UInt8]? {
    guard text.contains(":") else { return nil }
    var head = text
    var embeddedIPv4: [UInt8] = []
    if let lastColon = head.lastIndex(of: ":"),
      head[head.index(after: lastColon)...].contains(".")
    {
      guard let ipv4 = ipv4(String(head[head.index(after: lastColon)...])) else {
        return nil
      }
      embeddedIPv4 = ipv4
      head = String(head[..<lastColon]) + ":0:0"
    }
    let halves = head.components(separatedBy: "::").map { Substring($0) }
    guard halves.count <= 2 else { return nil }

    func groups(_ text: Substring) -> [UInt16]? {
      guard !text.isEmpty else { return [] }
      var result: [UInt16] = []
      for part in text.split(separator: ":", omittingEmptySubsequences: false) {
        guard part.count <= 4, let value = UInt16(part, radix: 16) else {
          return nil
        }
        result.append(value)
      }
      return result
    }

    let leading = halves.count == 2 ? groups(halves[0]) : groups(Substring(head))
    guard let leading else { return nil }
    let trailing: [UInt16]? = halves.count == 2 ? groups(halves[1]) : []
    guard let trailing else { return nil }
    let total = leading.count + trailing.count
    guard total <= 8 else { return nil }
    var all = leading
    all.append(contentsOf: [UInt16](repeating: 0, count: 8 - total))
    all.append(contentsOf: trailing)
    var bytes: [UInt8] = []
    for group in all {
      bytes.append(UInt8(group >> 8))
      bytes.append(UInt8(group & 0xff))
    }
    if !embeddedIPv4.isEmpty {
      bytes.replaceSubrange(12..<16, with: embeddedIPv4)
    }
    return bytes.count == 16 ? bytes : nil
  }
}
