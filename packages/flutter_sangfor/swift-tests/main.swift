// Test harness for the pure-Swift aTrust core that runs inside the iOS packet
// tunnel extension. It is compiled and executed on Linux/Windows/macOS with a
// plain `swiftc` invocation (see tool/run_swift_tests.*), which is what keeps
// the native data plane honest: the expected values are the golden fixtures
// emitted by the Dart reference implementation.
//
// Usage: swift-tests-runner <path-to-native_atrust.json>
import Foundation

var failures = 0
var checks = 0

func check(_ condition: Bool, _ message: String) {
  checks += 1
  if !condition {
    failures += 1
    print("FAIL: \(message)")
  }
}

func checkEqual<T: Equatable>(_ actual: T, _ expected: T, _ message: String) {
  checks += 1
  if actual != expected {
    failures += 1
    print("FAIL: \(message)\n  expected: \(expected)\n  actual:   \(actual)")
  }
}

func hexFromData(_ data: Data) -> String {
  SangforSha256.hex([UInt8](data), uppercase: false)
}

func bytesFromHex(_ text: String) -> [UInt8] {
  var bytes = [UInt8]()
  var index = text.startIndex
  while index < text.endIndex {
    let next = text.index(index, offsetBy: 2, limitedBy: text.endIndex) ?? text.endIndex
    bytes.append(UInt8(text[index..<next], radix: 16) ?? 0)
    index = next
  }
  return bytes
}

// MARK: - Fixture loading

let arguments = CommandLine.arguments
guard arguments.count > 1 else {
  print("usage: runner <native_atrust.json>")
  exit(2)
}
let fixtureURL = URL(fileURLWithPath: arguments[1])
guard
  let fixtureData = try? Data(contentsOf: fixtureURL),
  let fixtureObject = try? JSONSerialization.jsonObject(with: fixtureData),
  let fixture = fixtureObject as? [String: Any]
else {
  print("cannot read fixture at \(arguments[1])")
  exit(2)
}

func string(_ path: [String]) -> String {
  var node: Any = fixture
  for key in path {
    guard let map = node as? [String: Any], let value = map[key] else {
      fatalError("fixture is missing \(path.joined(separator: "."))")
    }
    node = value
  }
  guard let text = node as? String else {
    fatalError("fixture \(path.joined(separator: ".")) is not a string")
  }
  return text
}

func int(_ path: [String]) -> Int {
  var node: Any = fixture
  for key in path {
    guard let map = node as? [String: Any], let value = map[key] else {
      fatalError("fixture is missing \(path.joined(separator: "."))")
    }
    node = value
  }
  if let number = node as? Int { return number }
  if let number = node as? NSNumber { return number.intValue }
  fatalError("fixture \(path.joined(separator: ".")) is not an integer")
}

// MARK: - SHA-256 / HMAC

checkEqual(
  hexFromData(Data(SangforSha256.hash([]))),
  string(["sha256", "empty"]),
  "sha256 of the empty input"
)
checkEqual(
  hexFromData(Data(SangforSha256.hash(ofString: "abc"))),
  string(["sha256", "abc"]),
  "sha256 of abc"
)
checkEqual(
  hexFromData(Data(SangforSha256.hash((0..<1000).map { UInt8($0 % 251) }))),
  string(["sha256", "long"]),
  "sha256 of a 1000-byte input (multi-block padding)"
)
checkEqual(
  hexFromData(
    Data(
      SangforSha256.hmac(
        key: [UInt8]("abc".utf8),
        message: [UInt8]("abc".utf8)
      )
    )
  ),
  string(["hmacSha256", "abcKeyAbcData"]),
  "hmac-sha256 with a short key"
)

let signKey = bytesFromHex(string(["signKeyHex"]))
checkEqual(signKey.count, 32, "the fixture sign key is 32 bytes")
let authJson = string(["l3", "authUnsignedJson"])
checkEqual(
  SangforSha256.hex(
    SangforSha256.hmac(key: signKey, message: [UInt8](authJson.utf8))
  ),
  string(["l3", "authSignature"]),
  "the L3 flow-auth request signature"
)
checkEqual(
  SangforSha256.hex(SangforSha256.hash(ofString: "/var/mobile/Containers/Bundle/Application/Luotopia.app")),
  string(["processFingerprint"]),
  "the process fingerprint is sha256(path) uppercased"
)

// MARK: - Canonical JSON

/// Rebuilds the escaping fixture and compares it byte for byte with what Dart
/// produced.
let escapingFixture = SangforJsonValue.object([
  SangforJsonMember("quote", .string("a\"b")),
  SangforJsonMember("backslash", .string("a\\b")),
  SangforJsonMember("tab", .string("a\tb")),
  SangforJsonMember("newline", .string("a\nb")),
  SangforJsonMember("carriageReturn", .string("a\rb")),
  SangforJsonMember("backspace", .string("a\u{08}b")),
  SangforJsonMember("formFeed", .string("a\u{0c}b")),
  SangforJsonMember("control", .string("a\u{01}b\u{1f}b")),
  SangforJsonMember("delete", .string("a\u{7f}b")),
  SangforJsonMember("nonAscii", .string("a\u{e9}\u{4e2d}b")),
  SangforJsonMember("int", .int(7)),
  SangforJsonMember("negativeInt", .int(-12)),
  SangforJsonMember("true", .bool(true)),
  SangforJsonMember("false", .bool(false)),
  SangforJsonMember("null", .null),
  SangforJsonMember(
    "array",
    .array([.int(1), .string("two"), .object([SangforJsonMember("three", .int(3))])])
  ),
  SangforJsonMember("emptyObject", .object([])),
  SangforJsonMember("emptyArray", .array([])),
])
checkEqual(
  SangforJsonEncoder.encodeToString(escapingFixture),
  string(["jsonEscaping"]),
  "canonical JSON matches Dart's jsonEncode byte for byte"
)

// MARK: - L3 protocol frames

let process = ATrustProcessInfo(
  name: "Luotopia",
  path: "/var/mobile/Containers/Bundle/Application/Luotopia.app",
  platform: "iOS"
)
let authRequest = ATrustL3AuthRequest(
  sid: "REDACTED_SID",
  appId: "app-42",
  url: "tcp:203.0.113.7:443",
  deviceId: "REDACTED_DEVICE",
  connectionId: "REDACTED_CONNECTION",
  lang: "zh-CN",
  conntrackHash: 7,
  ip: ATrustL3IpInfo(
    atype: 0x0800,
    protocolNumber: 6,
    destinationAddress: "203.0.113.7",
    destinationPort: 443,
    sourceAddress: "10.0.0.42",
    sourcePort: 51000
  ),
  env: process
)
checkEqual(
  String(decoding: authRequest.unsignedJsonBytes(), as: UTF8.self),
  string(["l3", "authUnsignedJson"]),
  "the unsigned L3 auth body matches Dart's jsonEncode"
)
do {
  let frame = try ATrustL3Protocol.authRequestFrame(authRequest, signKey: signKey)
  checkEqual(
    SangforSha256.hex(frame, uppercase: false),
    string(["l3", "authRequestFrameHex"]),
    "the L3 flow-auth request frame"
  )
} catch {
  check(false, "authRequestFrame threw \(error)")
}
do {
  let frame = try ATrustL3Protocol.authTunnelRequest(sid: "REDACTED_SID")
  checkEqual(
    SangforSha256.hex(frame, uppercase: false),
    string(["l3", "authTunnelRequestHex"]),
    "the authTunnel request frame"
  )
} catch {
  check(false, "authTunnelRequest threw \(error)")
}
do {
  let packet = Data(bytesFromHex(string(["packet", "sampleHex"])))
  let frame = try ATrustL3Protocol.dataRequest(token: "tok-1", packet: packet)
  checkEqual(
    SangforSha256.hex(frame, uppercase: false),
    string(["l3", "dataRequestFrameHex"]),
    "the L3 data request frame"
  )
} catch {
  check(false, "dataRequest threw \(error)")
}
checkEqual(
  SangforSha256.hex(ATrustL3Protocol.heartbeatRequest(), uppercase: false),
  string(["l3", "heartbeatFrameHex"]),
  "the L3 heartbeat frame"
)
checkEqual(
  (try? ATrustL3Protocol.parseInitialVIPHeader(Data([0x05, 0x00, 0x00, 0x01])))
    ?? -1,
  int(["l3", "vipHeaderLengths", "ipv4"]),
  "the IPv4 VIP payload length"
)
checkEqual(
  (try? ATrustL3Protocol.parseInitialVIPHeader(Data([0x05, 0x00, 0x00, 0x04])))
    ?? -1,
  int(["l3", "vipHeaderLengths", "ipv6"]),
  "the IPv6 VIP payload length"
)
checkEqual(
  (try? ATrustL3Protocol.parseInitialVIPHeader(Data([0x05, 0x00, 0x00, 0x05])))
    ?? -1,
  int(["l3", "vipHeaderLengths", "dual"]),
  "the dual-stack VIP payload length"
)

// The handshake parser must consume a fragmented sequence and hand back the
// leftover bytes of the next frame.
do {
  let response = Data(bytesFromHex(string(["l3", "handshakeResponseHex"])))
  let parser = ATrustL3HandshakeParser()
  let trailing = ATrustL3Protocol.heartbeatRequest()
  var result: (ATrustL3TunnelAuthResult, Data)?
  // One byte at a time: nothing may decode before the sequence is complete.
  for index in 0..<response.count {
    result = try parser.add(response.subdata(in: index..<(index + 1)))
    if result != nil { break }
  }
  check(result != nil, "the handshake parser completes on the fixture")
  if let result {
    checkEqual(result.0.virtualIP, [string(["l3", "handshakeVip"])], "the parsed VIP")
    checkEqual(result.0.deviceId, "REDACTED_DEVICE", "the parsed deviceId")
    checkEqual(result.1.count, 0, "no leftover bytes")
  }
  let parser2 = ATrustL3HandshakeParser()
  var combined = response
  combined.append(trailing)
  let whole = try parser2.add(combined)
  checkEqual(whole?.1 ?? Data(), trailing, "leftover bytes survive the handshake")
} catch {
  check(false, "the handshake parser threw \(error)")
}

// The streaming frame decoder must survive chunk boundaries and coalescing.
// Responses are fed, since request frames carry a token the response decoder
// does not know about.
do {
  let heartbeat = Data([0x05, 0x95, 0x00, 0x00])
  let packet = Data(bytesFromHex(string(["packet", "sampleHex"])))
  var data = Data([0x05, 0x94])
  data.append(Data([UInt8(packet.count >> 8), UInt8(packet.count & 0xff)]))
  data.append(packet)
  let decoder = ATrustL3FrameStreamDecoder()
  var decoded: [ATrustL3Frame] = []
  var combined = Data()
  combined.append(heartbeat)
  combined.append(data)
  for index in 0..<combined.count {
    decoded.append(
      contentsOf: try decoder.add(combined.subdata(in: index..<(index + 1)))
    )
  }
  checkEqual(decoded.count, 2, "two frames decode from a byte-at-a-time feed")
  if decoded.count == 2 {
    checkEqual(
      decoded[0].command,
      ATrustL3Command.heartbeatResponse,
      "heartbeat command"
    )
    checkEqual(decoded[1].command, ATrustL3Command.dataResponse, "data command")
    checkEqual(decoded[1].payload, packet, "the data payload round-trips")
  }
} catch {
  check(false, "the frame decoder threw \(error)")
}

// MARK: - TCP tunnel protocol

let tcpRequest = ATrustTcpTunnelAuthRequest(
  sid: "REDACTED_SID",
  appId: "app-42",
  url: "tcp://vpn.example.test:443",
  deviceId: "REDACTED_DEVICE",
  connectionId: "REDACTED_CONNECTION",
  procHash: string(["processFingerprint"]),
  userName: "alice",
  lang: "zh-CN",
  destAddr: "vpn.example.test:443",
  destIp: "203.0.113.7",
  process: process
)
checkEqual(
  String(decoding: tcpRequest.unsignedJsonBytes(), as: UTF8.self),
  string(["tcpTunnel", "unsignedJson"]),
  "the unsigned TCP tunnel body matches Dart's jsonEncode"
)
checkEqual(
  tcpRequest.signature(signKey: signKey),
  string(["tcpTunnel", "signature"]),
  "the TCP tunnel request signature"
)
do {
  let handshake = try ATrustTcpTunnelProtocol.handshakeMessage(
    tcpRequest,
    signKey: signKey,
    host: "vpn.example.test",
    port: 443
  )
  checkEqual(
    SangforSha256.hex(handshake, uppercase: false),
    string(["tcpTunnel", "handshakeHex"]),
    "the TCP tunnel handshake message"
  )
  checkEqual(
    SangforSha256.hex(
      try ATrustTcpTunnelProtocol.destinationMessage("vpn.example.test", port: 443),
      uppercase: false
    ),
    string(["tcpTunnel", "destinationDomainHex"]),
    "a domain destination record"
  )
  checkEqual(
    SangforSha256.hex(
      try ATrustTcpTunnelProtocol.destinationMessage("203.0.113.7", port: 443),
      uppercase: false
    ),
    string(["tcpTunnel", "destinationIpv4Hex"]),
    "an IPv4 destination record"
  )
  checkEqual(
    SangforSha256.hex(
      try ATrustTcpTunnelProtocol.dataFrame(Data([1, 2, 3, 4, 5])),
      uppercase: false
    ),
    string(["tcpTunnel", "dataFrameHex"]),
    "a TCP tunnel data frame"
  )
  checkEqual(
    SangforSha256.hex(ATrustTcpTunnelProtocol.eofFrame(), uppercase: false),
    string(["tcpTunnel", "eofFrameHex"]),
    "the TCP tunnel EOF frame"
  )
  let response = Data(bytesFromHex(string(["tcpTunnel", "serverResponseHex"])))
  let parsed = try ATrustTcpTunnelProtocol.parseServerResponse(response)
  checkEqual(parsed.authCode, int(["tcpTunnel", "serverResponse", "authCode"]), "server hello authCode")
  checkEqual(
    parsed.connectStatus,
    int(["tcpTunnel", "serverResponse", "connectStatus"]),
    "server hello connectStatus"
  )
  checkEqual(parsed.consumed, int(["tcpTunnel", "serverResponse", "consumed"]), "server hello consumed")

  // The incremental parser must reach the same answer one byte at a time.
  let parser = ATrustTcpTunnelHandshakeParser()
  var leftover: Data?
  for index in 0..<response.count {
    leftover = try parser.add(response.subdata(in: index..<(index + 1)))
    if parser.response != nil { break }
  }
  checkEqual(parser.response, parsed, "the incremental handshake parser agrees")
  checkEqual(leftover?.count ?? -1, 0, "no leftover after the hello")
} catch {
  check(false, "the TCP tunnel protocol threw \(error)")
}

// MARK: - Packet codec

do {
  let sample = Data(bytesFromHex(string(["packet", "sampleHex"])))
  let meta = buildPacketMeta(sample)
  check(meta != nil, "the sample packet parses")
  if let meta {
    checkEqual(meta.atype, int(["packet", "meta", "atype"]), "meta atype")
    checkEqual(
      meta.protocolNumber,
      int(["packet", "meta", "protocol"]),
      "meta protocol"
    )
    checkEqual(
      meta.sourceAddress,
      string(["packet", "meta", "sourceAddress"]),
      "meta source address"
    )
    checkEqual(meta.sourcePort, int(["packet", "meta", "sourcePort"]), "meta source port")
    checkEqual(
      meta.destinationAddress,
      string(["packet", "meta", "destinationAddress"]),
      "meta destination address"
    )
    checkEqual(
      meta.destinationPort,
      int(["packet", "meta", "destinationPort"]),
      "meta destination port"
    )
  }

  var doubled = sample
  doubled.append(sample)
  let split = try ATrustPacketCodec.splitIncomingIPPackets([UInt8](doubled))
  checkEqual(split.packets.count, 2, "a doubled stream splits into two packets")
  checkEqual(split.remaining.count, 0, "nothing is left over")
  if split.packets.count == 2 {
    checkEqual(
      SangforSha256.hex(split.packets[0], uppercase: false),
      string(["packet", "sampleHex"]),
      "the first split packet matches the input"
    )
  }

  // Truncated input keeps the tail buffered instead of dropping it.
  let partial = try ATrustPacketCodec.splitIncomingIPPackets(
    Array(doubled.prefix(sample.count + 5))
  )
  checkEqual(partial.packets.count, 1, "a partial trailing packet is not emitted")
  checkEqual(partial.remaining.count, 5, "the tail stays buffered")

  let built = try ATrustPacketCodec.buildTcp(
    sourceAddress: "203.0.113.7",
    destinationAddress: "10.0.0.42",
    sourcePort: 443,
    destinationPort: 51000,
    sequenceNumber: 0x11223344,
    acknowledgmentNumber: 0x55667788,
    flags: ATrustTcpFlag.syn | ATrustTcpFlag.ack,
    window: 64240,
    payload: [1, 2, 3, 4, 5],
    mss: 1400,
    identification: 7
  )
  checkEqual(
    SangforSha256.hex(built, uppercase: false),
    string(["packet", "builtTcpHex"]),
    "the native IPv4/TCP builder matches Dart byte for byte"
  )
  let bare = try ATrustPacketCodec.buildTcp(
    sourceAddress: "203.0.113.7",
    destinationAddress: "10.0.0.42",
    sourcePort: 443,
    destinationPort: 51000,
    sequenceNumber: 1,
    acknowledgmentNumber: 2,
    flags: ATrustTcpFlag.ack,
    window: 65535,
    identification: 9
  )
  checkEqual(
    SangforSha256.hex(bare, uppercase: false),
    string(["packet", "builtTcpNoPayloadHex"]),
    "a payload-less packet matches Dart byte for byte"
  )

  // Round-trip: what the builder emits must parse back, and its checksums must
  // verify to zero.
  let parsedBuilt = ATrustIPv4Packet(built)
  check(parsedBuilt != nil, "the built packet parses")
  if let parsedBuilt {
    checkEqual(
      ATrustPacketCodec.ipv4HeaderChecksum([UInt8](built)),
      Int(built[10]) << 8 | Int(built[11]),
      "the stored IPv4 checksum verifies"
    )
    // The TCP checksum covers its own field, so verification means zeroing it
    // first and comparing, exactly like the Dart reference does.
    var zeroed = [UInt8](built)
    let storedTcp = Int(zeroed[36]) << 8 | Int(zeroed[37])
    zeroed[36] = 0
    zeroed[37] = 0
    checkEqual(
      ATrustPacketCodec.tcpChecksum(zeroed),
      storedTcp,
      "the stored TCP checksum verifies"
    )
    // Summing a valid packet with its checksum in place folds to all ones.
    checkEqual(
      ATrustPacketCodec.tcpChecksum([UInt8](built)),
      0,
      "a valid packet's TCP checksum complements to zero"
    )
    checkEqual(parsedBuilt.destinationAddress, "10.0.0.42", "built destination")
  }
  checkEqual(tcpSequenceAdd(0xffff_ffff, 2), 1, "sequence addition wraps")
  checkEqual(tcpSequenceDifference(0xffff_ffff, 1), 2, "sequence distance is positive")
  checkEqual(tcpSequenceDifference(1, 0xffff_ffff), -2, "sequence distance is signed")
} catch {
  check(false, "the packet codec threw \(error)")
}

// MARK: - Test doubles

/// A manually advanced clock, so retransmits and heartbeats are deterministic.
final class VirtualScheduler: SangforScheduler {
  private final class Task: SangforScheduledTask {
    let deadline: () -> Double
    var due: Double
    let action: () -> Void
    let repeating: Double?
    var cancelled = false
    init(due: Double, repeating: Double?, action: @escaping () -> Void, deadline: @escaping () -> Double) {
      self.due = due
      self.repeating = repeating
      self.action = action
      self.deadline = deadline
    }
    func cancel() { cancelled = true }
  }

  private var tasks: [Task] = []
  private var clock: Double = 0

  var now: Double { clock }

  func schedule(after seconds: Double, _ action: @escaping () -> Void) -> SangforScheduledTask {
    let task = Task(due: clock + seconds, repeating: nil, action: action, deadline: { [weak self] in self?.clock ?? 0 })
    tasks.append(task)
    return task
  }

  func scheduleRepeating(every seconds: Double, _ action: @escaping () -> Void) -> SangforScheduledTask {
    let task = Task(due: clock + seconds, repeating: seconds, action: action, deadline: { [weak self] in self?.clock ?? 0 })
    tasks.append(task)
    return task
  }

  /// Advances the clock, running everything that fell due.
  func advance(_ seconds: Double) {
    let target = clock + seconds
    while true {
      let due = tasks
        .filter { !$0.cancelled && $0.due <= target }
        .sorted { $0.due < $1.due }
      guard let next = due.first else { break }
      clock = next.due
      if let interval = next.repeating {
        next.due = clock + interval
      } else {
        next.cancel()
      }
      next.action()
    }
    clock = target
  }
}

/// An in-memory relay stream: what a TCP tunnel dial hands back.
final class FakeRelayStream: SangforRelayStream {
  private(set) var sent: [UInt8] = []
  var closed = false
  var writeClosed = false
  var readsPaused = false
  var onData: ((Data) -> Void)?
  var onClosed: ((Error?) -> Void)?

  var isClosed: Bool { closed }

  func send(_ data: Data) { sent.append(contentsOf: data) }
  func closeWrite() { writeClosed = true }
  func close() { closed = true }
  func setReadsPaused(_ paused: Bool) { readsPaused = paused }

  func deliver(_ bytes: [UInt8]) { onData?(Data(bytes)) }
  func finish() { onClosed?(nil) }
  func fail(_ error: Error) { onClosed?(error) }
}

/// An in-memory tunnel channel.
final class FakeChannel: SangforByteChannel {
  private(set) var sent: [UInt8] = []
  var closed = false
  var onData: ((Data) -> Void)?
  var onClosed: ((Error?) -> Void)?

  var isClosed: Bool { closed }

  func send(_ data: Data) { sent.append(contentsOf: data) }
  func close() { closed = true }
  func setReadsPaused(_ paused: Bool) {}
  func clearSent() { sent.removeAll() }

  func deliver(_ bytes: [UInt8]) { onData?(Data(bytes)) }
  func deliver(_ data: Data) { onData?(data) }

  /// The frames written so far, split by the L3 frame decoder.
  func drainFrames() throws -> [ATrustL3Frame] {
    let bytes = sent
    sent.removeAll()
    return try ATrustL3FrameStreamDecoder().add(Data(bytes))
  }
}

func makePlan(signKey: [UInt8]) -> ATrustSessionPlan {
  ATrustSessionPlan(
    sid: "REDACTED_SID",
    deviceId: "REDACTED_DEVICE",
    connectionId: "REDACTED_CONNECTION",
    username: "alice",
    signKeyBase64: Data(signKey).base64EncodedString(),
    lang: "zh-CN",
    processName: "Luotopia",
    processPath: "/var/mobile/Containers/Bundle/Application/Luotopia.app",
    processPlatform: "iOS",
    nodes: ["group-1": ["203.0.113.9:441"]],
    majorNodeGroup: "group-1",
    routes: [
      ATrustRoute(
        host: "10.9.0.0/16",
        protocolName: "tcp",
        portMin: 0,
        portMax: 65535,
        appId: "app-tcp",
        nodeGroupId: "group-1",
        addrPretend: false,
        enableTcpPrefL3: false
      ),
      ATrustRoute(
        host: "10.1.0.0/16",
        protocolName: "tcp",
        portMin: 0,
        portMax: 65535,
        appId: "app-l3",
        nodeGroupId: "group-1",
        addrPretend: false,
        enableTcpPrefL3: true
      ),
      ATrustRoute(
        host: "vpn.example.test",
        protocolName: "tcp",
        portMin: 443,
        portMax: 443,
        appId: "app-domain",
        nodeGroupId: "group-1",
        addrPretend: false,
        enableTcpPrefL3: false
      ),
    ],
    dnsServers: ["203.0.113.53"],
    virtualAddress: "10.0.0.42",
    dialHosts: ["203.0.113.7": "vpn.example.test"]
  )
}

/// Builds a client packet for terminator tests.
func clientPacket(
  sequence: Int,
  acknowledgment: Int,
  flags: UInt8,
  payload: [UInt8] = [],
  window: Int = 65535,
  mss: Int? = 1460,
  source: String = "10.0.0.42",
  destination: String = "10.9.1.2",
  sourcePort: Int = 51000,
  destinationPort: Int = 443
) throws -> Data {
  try ATrustPacketCodec.buildTcp(
    sourceAddress: source,
    destinationAddress: destination,
    sourcePort: sourcePort,
    destinationPort: destinationPort,
    sequenceNumber: sequence,
    acknowledgmentNumber: acknowledgment,
    flags: flags,
    window: window,
    payload: payload,
    mss: mss
  )
}

func segments(_ packets: [Data]) -> [ATrustTcpSegmentHeader] {
  packets.compactMap { packet in
    guard let ip = ATrustIPv4Packet(packet) else { return nil }
    return ATrustTcpSegmentHeader(ip.payload)
  }
}

// MARK: - Route table

do {
  let table = makePlan(signKey: signKey).routeTable
  check(
    table.matchL3(destinationAddress: "10.1.2.3", protocolName: "tcp", port: 443) != nil,
    "an L3-preferred resource is forwardable as raw IP"
  )
  check(
    table.matchL3(destinationAddress: "10.9.1.2", protocolName: "tcp", port: 443) == nil,
    "a TCP-tunnel resource is not forwardable as raw IP"
  )
  check(
    table.matchTcp(destinationHost: "10.9.1.2", port: 443)?.appId == "app-tcp",
    "an IP-published TCP resource matches by address"
  )
  check(
    table.matchTcp(destinationHost: "vpn.example.test", port: 443)?.appId == "app-domain",
    "a domain-published resource matches by name"
  )
  check(
    table.matchTcp(destinationHost: "203.0.113.7", port: 443) == nil,
    "a resolved address does not match a domain resource without its alias"
  )
  check(
    table.matchTcp(destinationHost: "8.8.8.8", port: 443) == nil,
    "an uncovered destination matches nothing"
  )
  check(
    ATrustRouteTable.hostCovers("10.0.0.0/8", address: "10.9.1.2"),
    "CIDR coverage"
  )
  check(
    !ATrustRouteTable.hostCovers("10.0.0.0/8", address: "11.9.1.2"),
    "CIDR non-coverage"
  )
  check(
    ATrustRouteTable.hostCovers("10.0.0.5~10.0.0.20", address: "10.0.0.7"),
    "range coverage"
  )
  check(
    ATrustRouteTable.domainCovers(".whu.edu.cn", host: "ids.whu.edu.cn"),
    "wildcard domain coverage"
  )
  check(
    !ATrustRouteTable.domainCovers("*.whu.edu.cn", host: "whu.edu.cn"),
    "a wildcard does not cover the apex"
  )
  checkEqual(
    ATrustNodeEndpoint("203.0.113.9:441")?.port,
    441,
    "node endpoint parsing"
  )
  checkEqual(
    ATrustNodeEndpoint("203.0.113.9")?.port,
    441,
    "a node endpoint without a port defaults to 441"
  )
}

// MARK: - TCP terminator

do {
  let scheduler = VirtualScheduler()
  var relay: FakeRelayStream?
  var dialed: [String] = []
  let terminator = ATrustTcpTerminator(
    dialer: { host, port, completion in
      dialed.append("\(host):\(port)")
      let stream = FakeRelayStream()
      relay = stream
      completion(.success(stream))
    },
    shouldTerminate: { address, port in
      makePlan(signKey: signKey).routeTable.matchL3(
        destinationAddress: address,
        protocolName: "tcp",
        port: port
      ) == nil
        && makePlan(signKey: signKey).routeTable.matchTcp(
          destinationHost: address,
          port: port
        ) != nil
    },
    dialHostResolver: { address, _ in
      makePlan(signKey: signKey).dialHosts[address]
    },
    scheduler: scheduler
  )
  var emitted: [Data] = []
  terminator.onPacket = { emitted.append($0) }

  let syn = try clientPacket(
    sequence: 1000,
    acknowledgment: 0,
    flags: ATrustTcpFlag.syn,
    mss: 1460
  )
  check(terminator.accept(syn), "a SYN for a TCP-tunnel resource is claimed")
  checkEqual(dialed, ["10.9.1.2:443"], "the terminator dials the destination")
  checkEqual(emitted.count, 1, "one SYN-ACK is emitted")
  if let synAck = segments(emitted).first {
    check(synAck.flags & ATrustTcpFlag.syn != 0, "the reply is a SYN")
    check(synAck.flags & ATrustTcpFlag.ack != 0, "the reply is an ACK")
    checkEqual(synAck.acknowledgmentNumber, 1001, "the SYN is acknowledged")
    checkEqual(synAck.maximumSegmentSize, 1400, "the MSS is clamped")
    checkEqual(synAck.window, 65535, "the advertised window")

    // Complete the handshake and relay a request.
    emitted.removeAll()
    let body = [UInt8]("GET / HTTP/1.1\r\n\r\n".utf8)
    _ = try terminator.accept(
      clientPacket(
        sequence: 1001,
        acknowledgment: synAck.sequenceNumber + 1,
        flags: ATrustTcpFlag.ack | ATrustTcpFlag.psh,
        payload: body,
        mss: nil
      )
    )
    checkEqual(String(decoding: relay?.sent ?? [], as: UTF8.self), "GET / HTTP/1.1\r\n\r\n", "client bytes reach the tunnel")
    let ack = segments(emitted).last
    checkEqual(ack?.acknowledgmentNumber, 1001 + body.count, "the request is acknowledged")

    // The response comes back segmented at the MSS.
    emitted.removeAll()
    relay?.deliver([UInt8](repeating: 7, count: 3000))
    let dataSegments = segments(emitted)
    check(dataSegments.count >= 3, "a 3000-byte response is segmented")
    var delivered = 0
    var expectedSequence = synAck.sequenceNumber + 1
    for segment in dataSegments {
      delivered += segment.payload.count
      checkEqual(segment.sequenceNumber, expectedSequence, "sequence numbers advance by the payload length")
      expectedSequence = tcpSequenceAdd(expectedSequence, segment.payload.count)
      check(segment.payload.count <= 1400, "no segment exceeds the MSS")
    }
    checkEqual(delivered, 3000, "every byte is delivered exactly once")

    // Upstream finishing does not let the terminator FIN while its own
    // segments are still unacknowledged.
    emitted.removeAll()
    relay?.finish()
    check(
      segments(emitted).allSatisfy { $0.flags & ATrustTcpFlag.fin == 0 },
      "no FIN while segments are still unacknowledged"
    )

    // One cumulative ACK covering all three segments opens the window again and
    // releases the FIN.
    _ = try terminator.accept(
      clientPacket(
        sequence: 1001 + body.count,
        acknowledgment: expectedSequence,
        flags: ATrustTcpFlag.ack,
        mss: nil
      )
    )
    check(
      segments(emitted).contains { $0.flags & ATrustTcpFlag.fin != 0 },
      "a cumulative ACK releases the pending FIN"
    )
    let fin = segments(emitted).first { $0.flags & ATrustTcpFlag.fin != 0 }
    checkEqual(fin?.sequenceNumber, expectedSequence, "the FIN follows the data")

    // The client's FIN half-closes upstream; acknowledging ours retires it.
    emitted.removeAll()
    _ = try terminator.accept(
      clientPacket(
        sequence: 1001 + body.count,
        acknowledgment: expectedSequence,
        flags: ATrustTcpFlag.fin | ATrustTcpFlag.ack,
        mss: nil
      )
    )
    check(relay?.writeClosed ?? false, "a client FIN half-closes upstream")
    _ = try terminator.accept(
      clientPacket(
        sequence: 1002 + body.count,
        acknowledgment: tcpSequenceAdd(expectedSequence, 1),
        flags: ATrustTcpFlag.ack,
        mss: nil
      )
    )
    checkEqual(terminator.connectionCount, 0, "the flow retires once both FINs are acknowledged")
    check(relay?.closed ?? false, "the relay stream is closed with the flow")
  }

  // A reset tears the flow down and closes the relay.
  let scheduler2 = VirtualScheduler()
  var relay2: FakeRelayStream?
  let terminator2 = ATrustTcpTerminator(
    dialer: { _, _, completion in
      let stream = FakeRelayStream()
      relay2 = stream
      completion(.success(stream))
    },
    shouldTerminate: { _, _ in true },
    scheduler: scheduler2
  )
  var emitted2: [Data] = []
  terminator2.onPacket = { emitted2.append($0) }
  _ = try terminator2.accept(
    clientPacket(sequence: 500, acknowledgment: 0, flags: ATrustTcpFlag.syn)
  )
  checkEqual(terminator2.connectionCount, 1, "one connection is live")
  let synAck2 = segments(emitted2).first
  _ = try terminator2.accept(
    clientPacket(
      sequence: 501,
      acknowledgment: (synAck2?.sequenceNumber ?? 0) + 1,
      flags: ATrustTcpFlag.ack
    )
  )
  _ = try terminator2.accept(
    clientPacket(sequence: 501, acknowledgment: 0, flags: ATrustTcpFlag.rst)
  )
  checkEqual(terminator2.connectionCount, 0, "a reset retires the connection")
  check(relay2?.closed ?? false, "the relay stream is closed")

  // A failed dial resets the client instead of leaving it hanging.
  let scheduler3 = VirtualScheduler()
  var errors: [Error] = []
  let terminator3 = ATrustTcpTerminator(
    dialer: { _, _, completion in
      completion(.failure(SangforTunnelError.flowAuthFailed("denied")))
    },
    shouldTerminate: { _, _ in true },
    scheduler: scheduler3,
    onError: { errors.append($0) }
  )
  var emitted3: [Data] = []
  terminator3.onPacket = { emitted3.append($0) }
  _ = try terminator3.accept(
    clientPacket(sequence: 900, acknowledgment: 0, flags: ATrustTcpFlag.syn)
  )
  checkEqual(errors.count, 1, "the dial failure is reported")
  check(
    segments(emitted3).contains { $0.flags & ATrustTcpFlag.rst != 0 },
    "a failed dial resets the client"
  )
  checkEqual(terminator3.connectionCount, 0, "the failed connection is gone")

  // Packets the terminator does not own are left for the tunnel.
  check(
    !terminator3.accept(
      try clientPacket(
        sequence: 1,
        acknowledgment: 1,
        flags: ATrustTcpFlag.ack,
        payload: [1, 2, 3]
      )
    ),
    "a data packet for an unknown flow is not claimed"
  )
}

// MARK: - L3 connection

do {
  let scheduler = VirtualScheduler()
  let channel = FakeChannel()
  let plan = makePlan(signKey: signKey)
  let connection = ATrustL3Connection(
    channel: channel,
    plan: plan,
    scheduler: scheduler
  )
  var inbound: [Data] = []
  var vips: [[String]] = []
  var errors: [Error] = []
  connection.onPacket = { inbound.append($0) }
  connection.onVirtualIP = { vips.append($0) }
  connection.onError = { errors.append($0) }

  var started: Result<[String], Error>?
  connection.start { started = $0 }
  check(connection.isHandshook == false, "the handshake is still in flight")
  checkEqual(
    SangforSha256.hex(channel.sent, uppercase: false),
    string(["l3", "authTunnelRequestHex"]),
    "the connection opens with the authTunnel request"
  )

  // Feed the handshake response one byte at a time.
  let handshake = Data(bytesFromHex(string(["l3", "handshakeResponseHex"])))
  for index in 0..<handshake.count {
    channel.deliver(handshake.subdata(in: index..<(index + 1)))
  }
  check(connection.isHandshook, "the handshake completes")
  if case .success(let addresses)? = started {
    checkEqual(addresses, ["10.0.0.42"], "the virtual IP is reported")
  } else {
    check(false, "start did not succeed")
  }
  checkEqual(vips, [["10.0.0.42"]], "onVirtualIP fires once")

  // Sending a packet for a TCP-tunnel resource cannot be forwarded as raw IP;
  // the L3 route matcher refuses it, so nothing is written.
  let sample = Data(bytesFromHex(string(["packet", "sampleHex"])))
  let tcpRoute = plan.routes.first { $0.appId == "app-tcp" }!
  let l3Route = plan.routes.first { $0.appId == "app-l3" }!
  channel.clearSent()
  let l3Packet = try ATrustPacketCodec.buildTcp(
    sourceAddress: "10.0.0.42",
    destinationAddress: "10.1.2.3",
    sourcePort: 51000,
    destinationPort: 443,
    sequenceNumber: 1,
    acknowledgmentNumber: 0,
    flags: ATrustTcpFlag.syn,
    window: 65535
  )
  connection.sendPacket(l3Packet, route: l3Route)
  let authFrames = try channel.drainFrames()
  checkEqual(authFrames.count, 1, "one auth request is written for a new flow")
  if let frame = authFrames.first,
    let object = SangforJsonObject.parse(frame.payload)
  {
    checkEqual(frame.command, ATrustL3Command.authRequest, "it is an auth request")
    checkEqual(object.string("sid"), "REDACTED_SID", "auth body sid")
    checkEqual(object.string("appId"), "app-l3", "auth body appId")
    checkEqual(object.string("url"), "tcp:10.1.2.3:443", "auth body url")
    checkEqual(object.int("conntrackHash"), 1, "auth body conntrackHash")
    let ip = object.object("ip")
    checkEqual(ip?.string("destAddr"), "10.1.2.3", "auth body destination")
    checkEqual(ip?.int("destPort"), 443, "auth body destination port")
    checkEqual(ip?.string("srcAddr"), "10.0.0.42", "auth body source")
    checkEqual(ip?.int("srcPort"), 51000, "auth body source port")
    checkEqual(ip?.int("atype"), 0x0800, "auth body address type")
    checkEqual(
      object.string("xRequestSig")?.count ?? 0,
      64,
      "the body is signed with a 64-character HMAC"
    )
  } else {
    check(false, "the auth request body is valid JSON")
  }

  // Answering with a token flushes the queued packet as a data frame.
  let token = "tok-99"
  let authResponsePayload = SangforJsonEncoder.encode(
    .object([
      SangforJsonMember("code", .int(0)),
      SangforJsonMember("message", .string("ok")),
      SangforJsonMember(
        "data",
        .object([
          SangforJsonMember("conntrackHash", .int(1)),
          SangforJsonMember("connectToken", .string(token)),
        ])
      ),
    ])
  )
  var response = Data([0x05, 0x93, 0x00])
  response.append(Data([UInt8(authResponsePayload.count >> 8), UInt8(authResponsePayload.count & 0xff)]))
  response.append(authResponsePayload)
  channel.deliver(response)
  let flushed = channel.sent
  channel.clearSent()
  // A data request is `05 14 <tokenLen> <token> 00 00 01 <len16> <packet>`;
  // the frame decoder above only understands responses, so check the layout
  // directly against the bytes the Dart reference produces.
  check(flushed.count >= 8, "the queued packet was flushed")
  if flushed.count >= 8 {
    checkEqual(flushed[0], 0x05, "data frame version")
    checkEqual(flushed[1], 0x14, "data frame command")
    let tokenLength = Int(flushed[2])
    let tokenBytes = Array(flushed[3..<(3 + tokenLength)])
    checkEqual(
      String(decoding: tokenBytes, as: UTF8.self),
      token,
      "the data frame carries the flow token"
    )
    let trailer = Array(flushed[(3 + tokenLength)..<(6 + tokenLength)])
    checkEqual(trailer, [0x00, 0x00, 0x01], "the data frame trailer")
    let length = Int(flushed[6 + tokenLength]) << 8 | Int(flushed[7 + tokenLength])
    checkEqual(length, l3Packet.count, "the data frame length")
    checkEqual(
      Data(Array(flushed.suffix(length))),
      l3Packet,
      "the data frame carries the packet verbatim"
    )
    let expected = try ATrustL3Protocol.dataRequest(token: token, packet: l3Packet)
    checkEqual(Data(flushed), expected, "the whole data frame matches the builder")
  }

  // Inbound data frames become raw packets.
  var inboundFrame = Data([0x05, 0x94])
  inboundFrame.append(Data([UInt8(sample.count >> 8), UInt8(sample.count & 0xff)]))
  inboundFrame.append(sample)
  channel.deliver(inboundFrame)
  checkEqual(inbound.count, 1, "an inbound data frame yields one packet")
  checkEqual(inbound.first, sample, "the packet is delivered verbatim")

  // Heartbeats keep the connection alive; three missed responses kill it.
  // The first idle tick only consumes the "we wrote something" flag, exactly
  // like the reference client, so the heartbeat lands on the second tick.
  channel.clearSent()
  scheduler.advance(5)
  checkEqual(channel.sent.count, 0, "an interval with traffic skips the heartbeat")
  scheduler.advance(5)
  checkEqual(
    SangforSha256.hex(channel.sent, uppercase: false),
    string(["l3", "heartbeatFrameHex"]),
    "an idle interval sends a heartbeat"
  )
  channel.deliver(Data([0x05, 0x95, 0x00, 0x00]))
  scheduler.advance(5)
  scheduler.advance(5)
  check(errors.isEmpty, "an answered heartbeat keeps the connection up")
  scheduler.advance(5)
  scheduler.advance(5)
  scheduler.advance(5)
  scheduler.advance(5)
  checkEqual(errors.count, 1, "three unanswered heartbeats fail the connection")
  check(connection.isClosed, "the connection closes itself after a failure")
}

// MARK: - Native data plane

do {
  let scheduler = VirtualScheduler()
  let plan = makePlan(signKey: signKey)
  // The first channel is the L3 node connection; every later one is a TCP
  // tunnel dial.
  var channels: [FakeChannel] = []
  let plane = SangforNativeDataPlane(
    plan: plan,
    scheduler: scheduler,
    dialer: { _, _, completion in
      let channel = FakeChannel()
      channels.append(channel)
      completion(.success(channel))
    },
    log: { _ in }
  )
  var ingress: [Data] = []
  plane.onIngressPacket = { ingress.append($0) }

  var startResult: Result<[String], Error>?
  plane.start { startResult = $0 }
  checkEqual(channels.count, 1, "start dials the major node group")
  let l3Channel = channels[0]
  checkEqual(
    SangforSha256.hex(l3Channel.sent, uppercase: false),
    string(["l3", "authTunnelRequestHex"]),
    "the data plane opens with the authTunnel request"
  )
  l3Channel.deliver(Data(bytesFromHex(string(["l3", "handshakeResponseHex"]))))
  if case .success(let addresses)? = startResult {
    checkEqual(addresses, ["10.0.0.42"], "the data plane reports the virtual IP")
  } else {
    check(false, "the data plane did not start")
  }

  // A TCP flow the gateway only publishes for the TCP tunnel is terminated
  // locally instead of being dropped.
  let terminatedSyn = try clientPacket(
    sequence: 4000,
    acknowledgment: 0,
    flags: ATrustTcpFlag.syn,
    destination: "10.9.1.2"
  )
  plane.handleEgressPacket(terminatedSyn)
  checkEqual(plane.statistics.terminated, 1, "the TCP-tunnel flow is terminated")
  checkEqual(channels.count, 2, "terminating it dials the TCP tunnel")
  l3Channel.clearSent()

  // Complete the TCP tunnel handshake; the client must then see a SYN-ACK.
  let tunnelChannel = channels[1]
  check(tunnelChannel.sent.count > 6, "the TCP tunnel dial sends a handshake")
  checkEqual(tunnelChannel.sent[0], 0x05, "the handshake starts with the version")
  checkEqual(tunnelChannel.sent[1], 0x01, "the handshake command")
  tunnelChannel.deliver(Data(bytesFromHex(string(["tcpTunnel", "serverResponseHex"]))))
  checkEqual(ingress.count, 1, "the terminated flow answers with one packet")
  if let synAck = segments(ingress).first {
    check(synAck.flags & ATrustTcpFlag.syn != 0, "it is a SYN-ACK")
    check(synAck.flags & ATrustTcpFlag.ack != 0, "it acknowledges the SYN")
    checkEqual(synAck.sourcePort, 443, "the SYN-ACK comes from the service port")
  } else {
    check(false, "the synthesized packet parses")
  }

  // An L3-preferred flow is forwarded as raw IP, with a signed flow auth.
  ingress.removeAll()
  let l3Syn = try clientPacket(
    sequence: 5000,
    acknowledgment: 0,
    flags: ATrustTcpFlag.syn,
    destination: "10.1.2.3"
  )
  plane.handleEgressPacket(l3Syn)
  checkEqual(plane.statistics.routed, 1, "the L3-preferred flow is routed")
  checkEqual(plane.statistics.terminated, 1, "it is not terminated")
  let authFrames = try l3Channel.drainFrames()
  checkEqual(authFrames.count, 1, "one flow auth request is written")
  checkEqual(authFrames.first?.command, ATrustL3Command.authRequest, "it is an auth request")

  // A destination no resource covers is counted and dropped.
  let unrouted = try clientPacket(
    sequence: 6000,
    acknowledgment: 0,
    flags: ATrustTcpFlag.syn,
    destination: "192.0.2.7"
  )
  plane.handleEgressPacket(unrouted)
  checkEqual(plane.statistics.unrouted, 1, "an uncovered destination is dropped")

  // Inbound data frames reach the packet flow.
  let sample = Data(bytesFromHex(string(["packet", "sampleHex"])))
  var inbound = Data([0x05, 0x94])
  inbound.append(Data([UInt8(sample.count >> 8), UInt8(sample.count & 0xff)]))
  inbound.append(sample)
  ingress.removeAll()
  l3Channel.deliver(inbound)
  checkEqual(ingress, [sample], "an inbound data frame reaches the packet flow")
  checkEqual(
    plane.statistics.ingress,
    2,
    "ingress counts the synthesized SYN-ACK and the tunneled packet"
  )

  // A domain-published resource is reachable through its resolved address.
  check(
    plane.shouldTerminate(address: "203.0.113.7", port: 443),
    "a resolved domain resource is terminated"
  )
  check(
    !plane.shouldTerminate(address: "10.1.2.3", port: 443),
    "an L3-preferred resource is not terminated"
  )

  plane.close()
  check(l3Channel.closed, "closing the plane closes the node connection")
  check(tunnelChannel.closed, "closing the plane closes relayed connections")
}

// MARK: - Session hand-off

do {
  let document = string(["sessionPlan"])
  let plan = try ATrustSessionPlan.decode(Data(document.utf8))
  checkEqual(plan.schemaVersion, ATrustSessionPlan.currentSchemaVersion, "plan schema")
  checkEqual(plan.sid, "REDACTED_SID", "plan sid")
  checkEqual(plan.deviceId, "REDACTED_DEVICE", "plan deviceId")
  checkEqual(plan.connectionId, "REDACTED_CONNECTION", "plan connectionId")
  checkEqual(plan.username, "alice", "plan username")
  checkEqual(plan.lang, "zh-CN", "plan language")
  checkEqual(plan.processPlatform, "iOS", "plan platform")
  checkEqual(plan.signKey?.count, 32, "the signing key survives base64")
  checkEqual(plan.signKey, signKey, "the signing key round-trips")
  checkEqual(plan.majorNodeGroup, "group-1", "plan major node group")
  checkEqual(plan.virtualAddress, "10.0.0.42", "plan virtual address")
  checkEqual(plan.dnsServers, ["203.0.113.53"], "plan DNS servers")
  checkEqual(plan.dialHosts["203.0.113.7"], "vpn.example.test", "plan dial alias")
  checkEqual(plan.nodeEndpoint(for: "group-1")?.host, "203.0.113.9", "the best node first")
  checkEqual(plan.nodeEndpoint(for: "group-1")?.port, 441, "the node port")
  checkEqual(
    plan.nodeEndpoint(for: "missing")?.host,
    "203.0.113.9",
    "an unknown group falls back to the major group"
  )
  checkEqual(plan.routes.count, 3, "plan routes")
  checkEqual(plan.process.fingerprint, string(["processFingerprint"]), "plan fingerprint")

  // The decoded routes must drive the same decisions the Dart side makes.
  let table = plan.routeTable
  checkEqual(
    table.matchL3(destinationAddress: "10.1.2.3", protocolName: "tcp", port: 443)?.appId,
    "app-l3",
    "the L3-preferred resource is forwardable as raw IP"
  )
  check(
    table.matchL3(destinationAddress: "10.9.1.2", protocolName: "tcp", port: 443) == nil,
    "the TCP-tunnel resource is not forwardable as raw IP"
  )
  checkEqual(
    table.matchTcp(destinationHost: "10.9.1.2", port: 443)?.appId,
    "app-tcp",
    "the TCP-tunnel resource matches by address"
  )
  checkEqual(
    table.matchTcp(destinationHost: plan.dialHosts["203.0.113.7"] ?? "", port: 443)?.appId,
    "app-domain",
    "the domain resource matches through its alias"
  )
  checkEqual(
    table.matchTcp(destinationHost: "203.0.113.7", port: 443)?.appId,
    nil,
    "a resolved address does not match a domain resource on its own"
  )
} catch {
  check(false, "the session plan did not decode: \(error)")
}

// MARK: - Certificate pinning

if let der = Data(base64Encoded: string(["certificateDigest", "derBase64"])) {
  checkEqual(
    SangforCertificateDigest.hex(der),
    string(["certificateDigest", "digest"]),
    "the anti-MITM pin digest matches the Dart reference"
  )
  check(
    SangforCertificateDigest.matches(
      der,
      digests: [string(["certificateDigest", "digest"]).lowercased()]
    ),
    "pin comparison ignores case"
  )
  check(
    !SangforCertificateDigest.matches(der, digests: []),
    "an empty pin list never matches, so the caller decides"
  )
} else {
  check(false, "the fixture certificate decodes from base64")
}

// MARK: - Domain routing

/// The shared case table, if the runner was given one. The Dart matcher in the
/// app reads the same file.
if arguments.count > 2 {
  guard
    let caseData = try? Data(contentsOf: URL(fileURLWithPath: arguments[2])),
    let caseObject = try? JSONSerialization.jsonObject(with: caseData) as? [String: Any],
    let routeObjects = caseObject["routes"] as? [[String: Any]],
    let caseObjects = caseObject["cases"] as? [[String: Any]]
  else {
    print("cannot read route matcher cases at \(arguments[2])")
    exit(2)
  }
  let matcherRoutes = routeObjects.map { entry in
    ATrustRoute(
      host: entry["host"] as! String,
      protocolName: entry["protocol"] as! String,
      portMin: entry["portMin"] as! Int,
      portMax: entry["portMax"] as! Int,
      appId: entry["appId"] as! String,
      nodeGroupId: entry["nodeGroupId"] as! String,
      addrPretend: entry["addrPretend"] as! Bool,
      enableTcpPrefL3: entry["enableTcpPrefL3"] as! Bool
    )
  }
  for entry in caseObjects {
    let matcher = SangforRouteMatcher(
      policy: SangforRouteMatcher.Policy(rawValue: entry["policy"] as! String)!,
      customEntries: entry["customEntries"] as! [String],
      serverRoutes: matcherRoutes
    )
    checkEqual(
      matcher.shouldTunnel(host: entry["host"] as! String, port: entry["port"] as! Int),
      entry["expect"] as! Bool,
      "route matcher: \(entry["name"] as! String)"
    )
  }
  check(caseObjects.count >= 40, "the shared case table has real coverage")
}

do {
  checkEqual(
    SangforDnsDomains.derive(["*.whu.edu.cn", "whu.edu.cn", "lib.whu.edu.cn"]),
    ["whu.edu.cn"],
    "a suffix covered by a shorter one is dropped"
  )
  checkEqual(
    SangforDnsDomains.derive([".example.org", "A.B.CN", "10.0.0.0/8", "1.2.3.4", "9.9.9.1~9.9.9.9"]),
    ["a.b.cn", "example.org"],
    "addresses, CIDRs and ranges are skipped and names are normalized"
  )
  checkEqual(
    SangforDnsDomains.derive(["a*.b.cn", "localhost", "", "  ", "x.y."]),
    ["x.y"],
    "inner wildcards and dotless names are dropped, trailing dots trimmed"
  )

  let routes = [
    ATrustRoute(
      host: "*.whu.edu.cn", protocolName: "tcp", portMin: 1, portMax: 65535,
      appId: "a", nodeGroupId: "g", addrPretend: false, enableTcpPrefL3: false),
    ATrustRoute(
      host: "10.0.0.0/8", protocolName: "tcp", portMin: 1, portMax: 65535,
      appId: "b", nodeGroupId: "g", addrPretend: false, enableTcpPrefL3: false),
  ]
  let policy = SangforProxyPolicy(
    matcher: SangforRouteMatcher(policy: .followServer, customEntries: [], serverRoutes: routes),
    neverTunnelHosts: ["cas.whu.edu.cn", "vpn.whu.edu.cn"],
    matchDomains: ["whu.edu.cn"]
  )
  checkEqual(policy.decide(host: "a.whu.edu.cn", port: 443), .tunnel, "a covered host tunnels")
  checkEqual(policy.decide(host: "A.WHU.EDU.CN.", port: 443), .tunnel, "case and a trailing dot are ignored")
  checkEqual(policy.decide(host: "cas.whu.edu.cn", port: 443), .direct, "a never-tunnel host goes direct")
  checkEqual(policy.decide(host: "CAS.whu.edu.cn", port: 443), .direct, "the never-tunnel match ignores case")
  checkEqual(policy.decide(host: "x.cas.whu.edu.cn", port: 443), .tunnel, "never-tunnel is exact, not a suffix")
  checkEqual(policy.decide(host: "whu.edu.cn", port: 443), .direct, "inside the match domains but not a resource goes direct")
  checkEqual(policy.decide(host: "example.com", port: 443), .reject, "outside the match domains is refused")
  checkEqual(policy.decide(host: "evilwhu.edu.cn", port: 443), .reject, "a suffix needs a dot boundary")
  checkEqual(policy.decide(host: "10.1.2.3", port: 443), .tunnel, "a covered address tunnels")
  checkEqual(policy.decide(host: "8.8.8.8", port: 443), .reject, "an uncovered address is refused")
  checkEqual(policy.decide(host: "::1", port: 443), .reject, "ipv6 is refused")
  checkEqual(policy.decide(host: "", port: 443), .reject, "an empty host is refused")

  let custom = SangforProxyPolicy(
    matcher: SangforRouteMatcher(policy: .custom, customEntries: ["lib.whu.edu.cn"], serverRoutes: routes),
    neverTunnelHosts: [],
    matchDomains: ["whu.edu.cn"]
  )
  checkEqual(custom.decide(host: "lib.whu.edu.cn", port: 443), .tunnel,
    "a custom entry the server wildcard also covers tunnels")
  checkEqual(custom.decide(host: "other.whu.edu.cn", port: 443), .direct,
    "a server-covered host the custom list leaves out goes direct, not through the tunnel")
  let customWide = SangforProxyPolicy(
    matcher: SangforRouteMatcher(policy: .custom, customEntries: ["*.whu.edu.cn"], serverRoutes: routes),
    neverTunnelHosts: [],
    matchDomains: ["whu.edu.cn"]
  )
  checkEqual(customWide.decide(host: "lib.whu.edu.cn", port: 443), .tunnel, "custom narrows but keeps covered hosts")

  // Configuration decoding tolerates plans written by older apps.
  let bare = try JSONDecoder().decode(
    SangforDomainRoutingConfiguration.self,
    from: Data("{}".utf8)
  )
  checkEqual(bare, SangforDomainRoutingConfiguration(), "missing keys take the defaults")
  let full = try JSONDecoder().decode(
    SangforDomainRoutingConfiguration.self,
    from: Data(
      """
      {"policy":"custom","customEntries":["a.cn"],"neverTunnelHosts":["cas.cn"],"proxyEnabled":false}
      """.utf8)
  )
  checkEqual(full.policy, .custom, "the policy decodes")
  checkEqual(full.customEntries, ["a.cn"], "custom entries decode")
  checkEqual(full.neverTunnelHosts, ["cas.cn"], "never-tunnel hosts decode")
  checkEqual(full.proxyEnabled, false, "the proxy switch decodes")

  let planWithRouting = ATrustSessionPlan(
    sid: "s", deviceId: "d", connectionId: "c", username: "u", signKeyBase64: "AA==",
    lang: "zh-CN", processName: "p", processPath: "/p", processPlatform: "iOS",
    nodes: ["g": ["203.0.113.9:441"]], majorNodeGroup: "g", routes: routes, dnsServers: [],
    domainRouting: SangforDomainRoutingConfiguration(policy: .custom, customEntries: ["x.cn"])
  )
  let roundTrip = try ATrustSessionPlan.decode(planWithRouting.encoded())
  checkEqual(roundTrip.domainRouting?.policy, .custom, "the plan carries the routing policy")
  let planWithout = try ATrustSessionPlan.decode(
    ATrustSessionPlan(
      sid: "s", deviceId: "d", connectionId: "c", username: "u", signKeyBase64: "AA==",
      lang: "zh-CN", processName: "p", processPath: "/p", processPlatform: "iOS",
      nodes: ["g": ["203.0.113.9:441"]], majorNodeGroup: "g", routes: routes, dnsServers: []
    ).encoded()
  )
  check(planWithout.domainRouting == nil, "a plan without the key decodes with no routing")
}

// MARK: - Tunnel settings carried in the plan

do {
  let bare = try JSONDecoder().decode(SangforPlanTunnelSettings.self, from: Data("{}".utf8))
  checkEqual(bare, SangforPlanTunnelSettings(), "missing keys take the defaults")
  checkEqual(bare.prefixLength, 32, "the default prefix is a single host")
  check(bare.address == nil, "no address means the plan's own virtual address")

  let full = try JSONDecoder().decode(
    SangforPlanTunnelSettings.self,
    from: Data(
      """
      {"address":"10.130.1.2","prefixLength":32,"routes":["10.0.0.0/8"],
       "excludedRoutes":["210.42.1.1/32"],"dnsServers":["1.2.3.4"],
       "searchDomains":["whu.edu.cn"],"mtu":1400}
      """.utf8)
  )
  checkEqual(full.address, "10.130.1.2", "the address decodes")
  checkEqual(full.routes, ["10.0.0.0/8"], "the routes decode")
  checkEqual(full.excludedRoutes, ["210.42.1.1/32"], "the excluded routes decode")
  checkEqual(full.dnsServers, ["1.2.3.4"], "the DNS servers decode")
  checkEqual(full.searchDomains, ["whu.edu.cn"], "the search domains decode")
  checkEqual(full.mtu, 1400, "the MTU decodes")

  let withSettings = ATrustSessionPlan(
    sid: "s", deviceId: "d", connectionId: "c", username: "u", signKeyBase64: "AA==",
    lang: "zh-CN", processName: "p", processPath: "/p", processPlatform: "iOS",
    nodes: ["g": ["203.0.113.9:441"]], majorNodeGroup: "g", routes: [], dnsServers: [],
    virtualAddress: "10.130.1.2",
    tunnelSettings: full
  )
  let decoded = try ATrustSessionPlan.decode(withSettings.encoded())
  checkEqual(decoded.tunnelSettings, full, "the plan carries the tunnel settings")
  let without = try ATrustSessionPlan.decode(
    ATrustSessionPlan(
      sid: "s", deviceId: "d", connectionId: "c", username: "u", signKeyBase64: "AA==",
      lang: "zh-CN", processName: "p", processPath: "/p", processPlatform: "iOS",
      nodes: ["g": ["203.0.113.9:441"]], majorNodeGroup: "g", routes: [], dnsServers: []
    ).encoded()
  )
  check(without.tunnelSettings == nil, "a plan without the key decodes with none")
}

// MARK: - HTTP proxy parser

do {
  func feed(_ text: String, credential: String? = nil) -> SangforProxyParseResult {
    var parser = SangforHttpProxyParser(credential: credential)
    return parser.feed(Data(text.utf8))
  }

  if case .request(.connect(let host, let port), let leftover) = feed(
    "CONNECT Ca.Whu.edu.cn:8443 HTTP/1.1\r\nHost: ca.whu.edu.cn:8443\r\n\r\n")
  {
    checkEqual(host, "ca.whu.edu.cn", "CONNECT lower-cases the host")
    checkEqual(port, 8443, "CONNECT carries the port")
    check(leftover.isEmpty, "nothing follows a bare CONNECT")
  } else {
    check(false, "a CONNECT request parses")
  }
  if case .request(.connect(_, let port), _) = feed("CONNECT a.cn HTTP/1.1\r\n\r\n") {
    checkEqual(port, 443, "CONNECT without a port means 443")
  } else {
    check(false, "CONNECT without a port parses")
  }
  if case .request(.connect(let host, let port), _) = feed("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n") {
    checkEqual(host, "2001:db8::1", "a bracketed IPv6 authority parses")
    checkEqual(port, 8443, "and keeps its port")
  } else {
    check(false, "a bracketed IPv6 authority parses")
  }
  if case .request(.connect, let leftover) = feed("CONNECT a.cn:443 HTTP/1.1\r\n\r\nHELLO") {
    checkEqual(String(data: leftover, encoding: .utf8), "HELLO", "bytes after the header are returned")
  } else {
    check(false, "pipelined bytes after CONNECT are kept")
  }

  if case .request(.forward(let host, let port, let head, let body), _) = feed(
    "GET http://Xgbnew.whu.edu.cn/a/b?x=1&y=2 HTTP/1.1\r\nHost: xgbnew.whu.edu.cn\r\n"
      + "Proxy-Connection: keep-alive\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\nBODY")
  {
    checkEqual(host, "xgbnew.whu.edu.cn", "a forwarded request lower-cases the host")
    checkEqual(port, 80, "http defaults to port 80")
    let text = String(data: head, encoding: .isoLatin1) ?? ""
    check(text.hasPrefix("GET /a/b?x=1&y=2 HTTP/1.1\r\n"), "the target is rewritten to origin-form")
    check(!text.lowercased().contains("proxy-connection"), "Proxy-Connection is dropped")
    check(!text.contains("keep-alive"), "keep-alive is dropped so one connection serves one request")
    check(text.contains("Accept: */*\r\n"), "other headers are kept")
    check(text.hasSuffix("Connection: close\r\n\r\n"), "Connection: close is forced")
    checkEqual(String(data: body, encoding: .utf8), "BODY", "a body in the same read is passed on")
  } else {
    check(false, "an absolute-form request parses")
  }
  if case .request(.forward(_, let port, let head, _), _) = feed("GET http://a.cn HTTP/1.1\r\n\r\n") {
    checkEqual(port, 80, "an empty path is fine")
    check(String(data: head, encoding: .isoLatin1)?.hasPrefix("GET / HTTP/1.1") ?? false, "an empty path becomes /")
  } else {
    check(false, "an absolute-form request without a path parses")
  }

  // Headers arrive in pieces.
  var split = SangforHttpProxyParser(credential: nil)
  checkEqual(split.feed(Data("CONNECT a.cn:4".utf8)), .needMore, "an incomplete line waits")
  checkEqual(split.feed(Data("43 HTTP/1.1\r\nHost".utf8)), .needMore, "an incomplete header block waits")
  if case .request(.connect(_, let port), _) = split.feed(Data(": a.cn\r\n\r\n".utf8)) {
    checkEqual(port, 443, "the request completes across reads")
  } else {
    check(false, "a request split across reads parses")
  }

  checkEqual(feed("GARBAGE\r\n\r\n"), .failure(.badRequest), "a malformed request line is refused")
  checkEqual(feed("GET /relative HTTP/1.1\r\n\r\n"), .failure(.badRequest), "an origin-form request is not a proxy request")
  checkEqual(feed("CONNECT :443 HTTP/1.1\r\n\r\n"), .failure(.badRequest), "an empty host is refused")
  checkEqual(feed("CONNECT a.cn:0 HTTP/1.1\r\n\r\n"), .failure(.badRequest), "port 0 is refused")
  checkEqual(feed("CONNECT a.cn:99999 HTTP/1.1\r\n\r\n"), .failure(.badRequest), "a port above 65535 is refused")
  checkEqual(feed("GET ftp://a.cn/ HTTP/1.1\r\n\r\n"), .failure(.badRequest), "other schemes are refused")

  var oversized = SangforHttpProxyParser(credential: nil)
  checkEqual(
    oversized.feed(Data(repeating: 0x41, count: SangforHttpProxyParser.maximumHeaderBytes + 1)),
    .failure(.badRequest),
    "an oversized header block is refused"
  )

  let good = "Basic " + Data("luotopia:secret".utf8).base64EncodedString()
  if case .request(.connect, _) = feed(
    "CONNECT a.cn:443 HTTP/1.1\r\nProxy-Authorization: \(good)\r\n\r\n", credential: "luotopia:secret")
  {
    check(true, "the right credential is accepted")
  } else {
    check(false, "the right credential is accepted")
  }
  checkEqual(
    feed("CONNECT a.cn:443 HTTP/1.1\r\n\r\n", credential: "luotopia:secret"),
    .failure(.proxyAuthenticationRequired),
    "a missing credential gets a 407"
  )
  checkEqual(
    feed("CONNECT a.cn:443 HTTP/1.1\r\nProxy-Authorization: Basic AAAA\r\n\r\n", credential: "luotopia:secret"),
    .failure(.proxyAuthenticationRequired),
    "a wrong credential gets a 407"
  )
  check(
    String(data: SangforHttpProxyResponses.connectionEstablished, encoding: .utf8)
      == "HTTP/1.1 200 Connection established\r\n\r\n",
    "the CONNECT response matches the Dart proxy"
  )
}

// MARK: - Proxy dial

do {
  let scheduler = VirtualScheduler()
  let plan = makePlan(signKey: signKey)
  var channels: [FakeChannel] = []
  let plane = SangforNativeDataPlane(
    plan: plan,
    scheduler: scheduler,
    dialer: { _, _, completion in
      let channel = FakeChannel()
      channels.append(channel)
      completion(.success(channel))
    },
    log: { _ in }
  )
  plane.start { _ in }
  channels[0].deliver(Data(bytesFromHex(string(["l3", "handshakeResponseHex"]))))

  var dialed: Result<SangforRelayStream, Error>?
  plane.dialTcpTunnelForProxy(host: "vpn.example.test", port: 443) { dialed = $0 }
  checkEqual(channels.count, 2, "a proxy dial opens a TCP tunnel connection")
  let proxyDial = String(decoding: channels[1].sent, as: UTF8.self)
  check(!proxyDial.contains("destIp"), "a proxy dial claims no resolved address")
  check(proxyDial.contains("vpn.example.test:443"), "a proxy dial names the host it was asked for")
  channels[1].deliver(Data(bytesFromHex(string(["tcpTunnel", "serverResponseHex"]))))
  if case .success? = dialed {
    check(true, "the proxy dial completes")
  } else {
    check(false, "the proxy dial completes")
  }

  var refused: Result<SangforRelayStream, Error>?
  plane.dialTcpTunnelForProxy(host: "nowhere.example.test", port: 443) { refused = $0 }
  if case .failure? = refused {
    check(true, "a host no resource covers is refused")
  } else {
    check(false, "a host no resource covers is refused")
  }
}

// MARK: - Summary

if failures > 0 {
  print("\(failures) of \(checks) checks failed")
  exit(1)
}
print("all \(checks) native checks passed")
