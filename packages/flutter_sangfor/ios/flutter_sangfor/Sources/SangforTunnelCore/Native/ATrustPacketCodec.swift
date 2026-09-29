import Foundation

/// IP protocol numbers used by the data plane.
public enum ATrustIpProtocol {
  public static let icmp = 1
  public static let tcp = 6
  public static let udp = 17
  public static let icmp6 = 58
}

/// TCP flag bits (RFC 793).
public enum ATrustTcpFlag {
  public static let fin: UInt8 = 0x01
  public static let syn: UInt8 = 0x02
  public static let rst: UInt8 = 0x04
  public static let psh: UInt8 = 0x08
  public static let ack: UInt8 = 0x10
}

/// A parsed IPv4 packet. The bytes are copied out on construction so the view
/// stays valid regardless of who owns the buffer.
public struct ATrustIPv4Packet {
  public let bytes: [UInt8]

  public init?(_ data: Data) {
    let raw = [UInt8](data)
    guard raw.count >= 20, raw[0] >> 4 == 4 else { return nil }
    let headerLength = Int(raw[0] & 0x0f) * 4
    guard headerLength >= 20, raw.count >= headerLength else { return nil }
    bytes = raw
  }

  public var headerLength: Int { Int(bytes[0] & 0x0f) * 4 }
  public var totalLength: Int { Int(bytes[2]) << 8 | Int(bytes[3]) }
  public var timeToLive: Int { Int(bytes[8]) }
  /// The IP protocol number; `protocol` is a Swift keyword.
  public var protocolNumber: Int { Int(bytes[9]) }
  public var sourceAddress: String { SangforAddressText.ipv4(Array(bytes[12..<16])) }
  public var destinationAddress: String {
    SangforAddressText.ipv4(Array(bytes[16..<20]))
  }
  public var payload: [UInt8] {
    let end = min(totalLength, bytes.count)
    guard end > headerLength else { return [] }
    return Array(bytes[headerLength..<end])
  }
}

/// A parsed TCP segment (the bytes start at the TCP header).
public struct ATrustTcpSegmentHeader {
  public let bytes: [UInt8]

  public init?(_ bytes: [UInt8]) {
    guard bytes.count >= 20 else { return nil }
    self.bytes = bytes
  }

  public var dataOffset: Int { Int(bytes[12] >> 4) * 4 }
  public var sourcePort: Int { Int(bytes[0]) << 8 | Int(bytes[1]) }
  public var destinationPort: Int { Int(bytes[2]) << 8 | Int(bytes[3]) }
  public var sequenceNumber: Int {
    Int(bytes[4]) << 24 | Int(bytes[5]) << 16 | Int(bytes[6]) << 8 | Int(bytes[7])
  }
  public var acknowledgmentNumber: Int {
    Int(bytes[8]) << 24 | Int(bytes[9]) << 16 | Int(bytes[10]) << 8
      | Int(bytes[11])
  }
  public var flags: UInt8 { bytes[13] }
  public var window: Int { Int(bytes[14]) << 8 | Int(bytes[15]) }
  public var payload: [UInt8] {
    guard bytes.count > dataOffset else { return [] }
    return Array(bytes[dataOffset...])
  }

  /// The MSS option the sender offered, or 0 when absent.
  public var maximumSegmentSize: Int {
    let end = min(dataOffset, bytes.count)
    var index = 20
    while index < end {
      let kind = bytes[index]
      if kind == 0 { break }
      if kind == 1 {
        index += 1
        continue
      }
      guard index + 1 < end else { break }
      let length = Int(bytes[index + 1])
      guard length >= 2, index + length <= end else { break }
      if kind == 2, length == 4 {
        return Int(bytes[index + 2]) << 8 | Int(bytes[index + 3])
      }
      index += length
    }
    return 0
  }
}

/// Routing metadata for one packet.
public struct ATrustPacketMeta: Equatable {
  public let atype: Int
  /// The IP protocol number; `protocol` is a Swift keyword.
  public let protocolNumber: Int
  public let sourceAddress: String
  public let sourcePort: Int
  public let destinationAddress: String
  public let destinationPort: Int

  public var reversed: ATrustPacketMeta {
    ATrustPacketMeta(
      atype: atype,
      protocolNumber: protocolNumber,
      sourceAddress: destinationAddress,
      sourcePort: destinationPort,
      destinationAddress: sourceAddress,
      destinationPort: sourcePort
    )
  }

  /// The flow key, from the packet's own point of view.
  public var flowKey: String {
    "\(protocolNumber):\(sourceAddress):\(sourcePort)"
      + "-\(destinationAddress):\(destinationPort)"
  }

  public var protocolName: String {
    switch protocolNumber {
    case ATrustIpProtocol.tcp: "tcp"
    case ATrustIpProtocol.udp: "udp"
    case ATrustIpProtocol.icmp: "icmp"
    case ATrustIpProtocol.icmp6: "icmp6"
    default: "ip"
    }
  }
}

/// Extracts routing metadata from a raw IP packet, or nil when the packet is
/// malformed or carries a protocol the tunnel cannot describe.
public func buildPacketMeta(_ packet: Data) -> ATrustPacketMeta? {
  guard let ip = ATrustIPv4Packet(packet) else { return nil }
  let payload = ip.payload
  switch ip.protocolNumber {
  case ATrustIpProtocol.icmp:
    return ATrustPacketMeta(
      atype: 4,
      protocolNumber: ATrustIpProtocol.icmp,
      sourceAddress: ip.sourceAddress,
      sourcePort: 0,
      destinationAddress: ip.destinationAddress,
      destinationPort: 0
    )
  case ATrustIpProtocol.tcp:
    guard let tcp = ATrustTcpSegmentHeader(payload) else { return nil }
    return ATrustPacketMeta(
      atype: 4,
      protocolNumber: ATrustIpProtocol.tcp,
      sourceAddress: ip.sourceAddress,
      sourcePort: tcp.sourcePort,
      destinationAddress: ip.destinationAddress,
      destinationPort: tcp.destinationPort
    )
  case ATrustIpProtocol.udp:
    guard payload.count >= 8 else { return nil }
    return ATrustPacketMeta(
      atype: 4,
      protocolNumber: ATrustIpProtocol.udp,
      sourceAddress: ip.sourceAddress,
      sourcePort: Int(payload[0]) << 8 | Int(payload[1]),
      destinationAddress: ip.destinationAddress,
      destinationPort: Int(payload[2]) << 8 | Int(payload[3])
    )
  default:
    return nil
  }
}

/// IPv4/TCP packet assembly with full checksums.
///
/// Tunnel interfaces differ in whether they verify checksums, so every packet
/// is computed completely instead of relying on offload.
public enum ATrustPacketCodec {
  /// Builds one IPv4/TCP packet. [mss] adds the MSS option, which is what a
  /// SYN-ACK needs to clamp the peer.
  public static func buildTcp(
    sourceAddress: String,
    destinationAddress: String,
    sourcePort: Int,
    destinationPort: Int,
    sequenceNumber: Int,
    acknowledgmentNumber: Int,
    flags: UInt8,
    window: Int,
    payload: [UInt8] = [],
    mss: Int? = nil,
    identification: Int = 0,
    timeToLive: Int = 64
  ) throws -> Data {
    guard
      let source = SangforAddressBytes.ipv4(sourceAddress),
      let destination = SangforAddressBytes.ipv4(destinationAddress)
    else {
      throw SangforProtocolError.invalidLength(
        "endpoints \(sourceAddress) -> \(destinationAddress)"
      )
    }
    let optionLength = mss == nil ? 0 : 4
    let tcpLength = 20 + optionLength + payload.count
    var packet = [UInt8](repeating: 0, count: 20 + tcpLength)

    packet[0] = 0x45
    packet[2] = UInt8(packet.count >> 8)
    packet[3] = UInt8(packet.count & 0xff)
    packet[4] = UInt8(identification >> 8)
    packet[5] = UInt8(identification & 0xff)
    packet[8] = UInt8(timeToLive)
    packet[9] = UInt8(ATrustIpProtocol.tcp)
    for index in 0..<4 {
      packet[12 + index] = source[index]
      packet[16 + index] = destination[index]
    }
    let ipChecksum = ipv4HeaderChecksum(packet)
    packet[10] = UInt8(ipChecksum >> 8)
    packet[11] = UInt8(ipChecksum & 0xff)

    let tcp = 20
    packet[tcp] = UInt8(sourcePort >> 8)
    packet[tcp + 1] = UInt8(sourcePort & 0xff)
    packet[tcp + 2] = UInt8(destinationPort >> 8)
    packet[tcp + 3] = UInt8(destinationPort & 0xff)
    packet[tcp + 4] = UInt8(truncatingIfNeeded: UInt32(sequenceNumber) >> 24)
    packet[tcp + 5] = UInt8(truncatingIfNeeded: UInt32(sequenceNumber) >> 16)
    packet[tcp + 6] = UInt8(truncatingIfNeeded: UInt32(sequenceNumber) >> 8)
    packet[tcp + 7] = UInt8(truncatingIfNeeded: UInt32(sequenceNumber))
    packet[tcp + 8] = UInt8(truncatingIfNeeded: UInt32(acknowledgmentNumber) >> 24)
    packet[tcp + 9] = UInt8(truncatingIfNeeded: UInt32(acknowledgmentNumber) >> 16)
    packet[tcp + 10] = UInt8(truncatingIfNeeded: UInt32(acknowledgmentNumber) >> 8)
    packet[tcp + 11] = UInt8(truncatingIfNeeded: UInt32(acknowledgmentNumber))
    packet[tcp + 12] = UInt8(((20 + optionLength) / 4) << 4)
    packet[tcp + 13] = flags
    packet[tcp + 14] = UInt8(window >> 8)
    packet[tcp + 15] = UInt8(window & 0xff)
    if let mss {
      packet[tcp + 20] = 2
      packet[tcp + 21] = 4
      packet[tcp + 22] = UInt8(mss >> 8)
      packet[tcp + 23] = UInt8(mss & 0xff)
    }
    if !payload.isEmpty {
      packet.replaceSubrange(
        (tcp + 20 + optionLength)..<(tcp + 20 + optionLength + payload.count),
        with: payload
      )
    }
    let tcpChecksumValue = tcpChecksum(packet, headerLength: 20)
    packet[tcp + 16] = UInt8(tcpChecksumValue >> 8)
    packet[tcp + 17] = UInt8(tcpChecksumValue & 0xff)
    return Data(packet)
  }

  /// The ones'-complement checksum of an IPv4 header (checksum field zero).
  public static func ipv4HeaderChecksum(_ packet: [UInt8], headerLength: Int = 20)
    -> Int
  {
    var sum = 0
    var index = 0
    while index + 1 < headerLength {
      if index != 10 {
        sum += Int(packet[index]) << 8 | Int(packet[index + 1])
      }
      index += 2
    }
    return fold(sum)
  }

  /// The TCP checksum over the pseudo-header, TCP header, and payload.
  public static func tcpChecksum(_ packet: [UInt8], headerLength: Int = 20) -> Int
  {
    let totalLength = Int(packet[2]) << 8 | Int(packet[3])
    let tcpLength = totalLength - headerLength
    var sum = 0
    var index = 12
    while index < 20 {
      sum += Int(packet[index]) << 8 | Int(packet[index + 1])
      index += 2
    }
    sum += Int(packet[9])
    sum += tcpLength
    var offset = 0
    while offset + 1 < tcpLength {
      sum += Int(packet[headerLength + offset]) << 8
        | Int(packet[headerLength + offset + 1])
      offset += 2
    }
    if tcpLength % 2 == 1 {
      sum += Int(packet[headerLength + tcpLength - 1]) << 8
    }
    return fold(sum)
  }

  private static func fold(_ sum: Int) -> Int {
    var value = sum
    while value >> 16 != 0 {
      value = (value & 0xffff) + (value >> 16)
    }
    return (~value) & 0xffff
  }

  /// Splits a concatenated inbound raw-IP stream into complete packets and
  /// returns them with the unconsumed tail.
  public static func splitIncomingIPPackets(_ stream: [UInt8]) throws
    -> (packets: [Data], remaining: [UInt8])
  {
    var packets: [Data] = []
    var offset = 0
    while offset < stream.count {
      let remaining = stream.count - offset
      let version = stream[offset] >> 4
      let packetLength: Int
      if version == 4 {
        guard remaining >= 4 else {
          return (packets, Array(stream[offset...]))
        }
        let headerLength = Int(stream[offset] & 0x0f) * 4
        packetLength = Int(stream[offset + 2]) << 8 | Int(stream[offset + 3])
        guard headerLength >= 20, packetLength >= headerLength else {
          throw SangforProtocolError.invalidLength("IPv4 packet")
        }
      } else if version == 6 {
        guard remaining >= 6 else {
          return (packets, Array(stream[offset...]))
        }
        packetLength =
          40 + (Int(stream[offset + 4]) << 8 | Int(stream[offset + 5]))
      } else {
        throw SangforProtocolError.unexpectedVersion(stream[offset])
      }
      guard remaining >= packetLength else {
        return (packets, Array(stream[offset...]))
      }
      packets.append(Data(stream[offset..<(offset + packetLength)]))
      offset += packetLength
    }
    return (packets, [])
  }
}

/// Adds [value] in TCP sequence space (32-bit wraparound).
public func tcpSequenceAdd(_ base: Int, _ value: Int) -> Int {
  Int(truncatingIfNeeded: UInt32(truncatingIfNeeded: base) &+ UInt32(truncatingIfNeeded: value))
}

/// The signed distance from [from] to [to] in TCP sequence space.
public func tcpSequenceDifference(_ from: Int, _ to: Int) -> Int {
  let difference = Int(
    UInt32(truncatingIfNeeded: to) &- UInt32(truncatingIfNeeded: from)
  )
  return difference >= 0x8000_0000 ? difference - 0x1_0000_0000 : difference
}
