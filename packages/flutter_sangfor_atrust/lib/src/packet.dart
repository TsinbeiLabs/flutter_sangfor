import 'dart:typed_data';

/// IP version 4.
const int ipv4Version = 4;

/// IP version 6.
const int ipv6Version = 6;

/// IP protocol number for TCP (RFC 793).
const int tcpProtocol = 6;

/// IP protocol number for UDP (RFC 768).
const int udpProtocol = 17;

/// IP protocol number for ICMP (RFC 792).
const int icmpProtocol = 1;

/// IP protocol number for ICMPv6 (RFC 4436).
const int icmp6Protocol = 58;

/// Minimum IPv4 header length in bytes (RFC 791).
const int ipv4HeaderMinLength = 20;

/// Minimum TCP header length in bytes (RFC 793).
const int tcpHeaderMinLength = 20;

/// Minimum UDP header length in bytes (RFC 768).
const int udpHeaderMinLength = 8;

/// TCP SYN flag (RFC 793).
const int tcpSynFlag = 0x02;

/// TCP ACK flag (RFC 793).
const int tcpAckFlag = 0x10;

/// TCP FIN flag (RFC 793).
const int tcpFinFlag = 0x01;

/// TCP RST flag (RFC 793).
const int tcpRstFlag = 0x04;

/// A parsed IPv4 packet header view (RFC 791). Fields are read directly from
/// the underlying buffer; no copy is made.
class ATrustIPv4Packet {
  /// Wraps an IPv4 packet buffer.
  ATrustIPv4Packet(this.data);

  /// The raw packet bytes.
  final Uint8List data;

  /// True when the buffer is at least a minimum IPv4 header of version 4.
  bool get valid =>
      data.length >= ipv4HeaderMinLength && (data[0] >> 4) == ipv4Version;

  /// The 4-bit IP version field.
  int get version => data[0] >> 4;

  /// The header length in bytes derived from the IHL field.
  int get headerLength => (data[0] & 0x0f) * 4;

  /// The total-packet length field.
  int get totalLength =>
      ByteData.sublistView(data, 2, 4).getUint16(0, Endian.big);

  /// The protocol field identifying the payload protocol.
  int get protocol => data[9];

  /// The source address in dotted-quad notation.
  String get sourceIP => '${data[12]}.${data[13]}.${data[14]}.${data[15]}';

  /// The destination address in dotted-quad notation.
  String get destinationIP => '${data[16]}.${data[17]}.${data[18]}.${data[19]}';

  /// The payload following the IP header.
  Uint8List get payload => Uint8List.sublistView(data, headerLength);
}

/// A parsed TCP segment header view (RFC 793).
class ATrustTCPPacket {
  /// Wraps a TCP segment buffer (starting at the TCP header).
  ATrustTCPPacket(this.data);

  /// The raw segment bytes.
  final Uint8List data;

  /// True when the buffer is at least a minimum TCP header.
  bool get valid => data.length >= tcpHeaderMinLength;

  /// The flags byte (SYN/ACK/FIN/RST).
  int get flags => data[13];

  /// The source port.
  int get sourcePort =>
      ByteData.sublistView(data, 0, 2).getUint16(0, Endian.big);

  /// The destination port.
  int get destinationPort =>
      ByteData.sublistView(data, 2, 4).getUint16(0, Endian.big);

  /// The sequence number.
  int get sequenceNumber =>
      ByteData.sublistView(data, 4, 8).getUint32(0, Endian.big);

  /// The acknowledgment number.
  int get acknowledgmentNumber =>
      ByteData.sublistView(data, 8, 12).getUint32(0, Endian.big);
}

/// A parsed UDP datagram header view (RFC 768).
class ATrustUDPPacket {
  /// Wraps a UDP datagram buffer (starting at the UDP header).
  ATrustUDPPacket(this.data);

  /// The raw datagram bytes.
  final Uint8List data;

  /// True when the buffer is at least a minimum UDP header.
  bool get valid => data.length >= udpHeaderMinLength;

  /// The source port.
  int get sourcePort =>
      ByteData.sublistView(data, 0, 2).getUint16(0, Endian.big);

  /// The destination port.
  int get destinationPort =>
      ByteData.sublistView(data, 2, 4).getUint16(0, Endian.big);
}

/// Routing/flow metadata extracted from one IP packet.
class ATrustPacketMeta {
  /// Creates metadata for one packet flow.
  const ATrustPacketMeta({
    required this.atype,
    required this.protocol,
    required this.sourceAddress,
    required this.sourcePort,
    required this.destinationAddress,
    required this.destinationPort,
  });

  /// The address type (4 for IPv4, 6 for IPv6).
  final int atype;

  /// The IP protocol number.
  final int protocol;

  /// The source address in text form.
  final String sourceAddress;

  /// The source port (0 for ICMP).
  final int sourcePort;

  /// The destination address in text form.
  final String destinationAddress;

  /// The destination port (0 for ICMP).
  final int destinationPort;

  /// The flow key used by conntrack lookups.
  String get key => '$atype:$protocol:$sourceAddress:$sourcePort-'
      '$destinationAddress:$destinationPort';

  /// The same metadata with source and destination swapped, as seen by the
  /// peer side of the flow.
  ATrustPacketMeta get reversed => ATrustPacketMeta(
        atype: atype,
        protocol: protocol,
        sourceAddress: destinationAddress,
        sourcePort: destinationPort,
        destinationAddress: sourceAddress,
        destinationPort: sourcePort,
      );
}

/// Extracts routing metadata from one IP packet, or null when the packet is
/// empty, malformed, or uses an unsupported protocol.
ATrustPacketMeta? buildPacketMeta(Uint8List packet) {
  if (packet.isEmpty) return null;
  final ip = ATrustIPv4Packet(packet);
  if (!ip.valid) return null;

  switch (ip.protocol) {
    case icmpProtocol:
      return ATrustPacketMeta(
        atype: 4,
        protocol: icmpProtocol,
        sourceAddress: ip.sourceIP,
        sourcePort: 0,
        destinationAddress: ip.destinationIP,
        destinationPort: 0,
      );
    case tcpProtocol:
      final tcp = ATrustTCPPacket(ip.payload);
      if (!tcp.valid) return null;
      return ATrustPacketMeta(
        atype: 4,
        protocol: tcpProtocol,
        sourceAddress: ip.sourceIP,
        sourcePort: tcp.sourcePort,
        destinationAddress: ip.destinationIP,
        destinationPort: tcp.destinationPort,
      );
    case udpProtocol:
      final udp = ATrustUDPPacket(ip.payload);
      if (!udp.valid) return null;
      return ATrustPacketMeta(
        atype: 4,
        protocol: udpProtocol,
        sourceAddress: ip.sourceIP,
        sourcePort: udp.sourcePort,
        destinationAddress: ip.destinationIP,
        destinationPort: udp.destinationPort,
      );
    default:
      return null;
  }
}

/// Splits a concatenated inbound raw-IP byte stream into complete packets.
/// Returns the parsed packets and the unconsumed tail bytes.
(List<Uint8List>, Uint8List) splitIncomingIPPackets(Uint8List stream) {
  final packets = <Uint8List>[];
  var offset = 0;
  while (offset < stream.length) {
    final remaining = stream.length - offset;
    final version = stream[offset] >> 4;
    int packetLen;

    if (version == ipv4Version) {
      if (remaining < 4) {
        return (packets, Uint8List.sublistView(stream, offset));
      }
      final headerLen = (stream[offset] & 0x0f) * 4;
      packetLen = ByteData.sublistView(stream, offset + 2, offset + 4)
          .getUint16(0, Endian.big);
      if (headerLen < 20 || packetLen < headerLen) {
        throw FormatException(
          'invalid IPv4 packet length $packetLen with header length $headerLen',
        );
      }
    } else if (version == ipv6Version) {
      if (remaining < 6) {
        return (packets, Uint8List.sublistView(stream, offset));
      }
      packetLen = 40 +
          ByteData.sublistView(stream, offset + 4, offset + 6)
              .getUint16(0, Endian.big);
    } else {
      throw FormatException('unexpected IP version $version');
    }

    if (remaining < packetLen) {
      return (packets, Uint8List.sublistView(stream, offset));
    }
    packets.add(Uint8List.fromList(stream.sublist(offset, offset + packetLen)));
    offset += packetLen;
  }
  return (packets, Uint8List.sublistView(stream, offset));
}

/// Maps an IP protocol number to its lowercase protocol name.
String protocolName(int protocol) => switch (protocol) {
      tcpProtocol => 'tcp',
      udpProtocol => 'udp',
      icmpProtocol => 'icmp',
      icmp6Protocol => 'icmp6',
      _ => 'ip',
    };

/// Maps an address type to the Ethernet protocol value used by auth requests.
int authIPType(int atype) => switch (atype) {
      6 => 0x86DD,
      _ => 0x0800,
    };
