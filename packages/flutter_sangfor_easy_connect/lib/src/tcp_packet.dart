import 'dart:typed_data';

/// TCP header flag bits (RFC 793).
const int tcpFlagFin = 0x01;
const int tcpFlagSyn = 0x02;
const int tcpFlagRst = 0x04;
const int tcpFlagPsh = 0x08;
const int tcpFlagAck = 0x10;

const int ipProtocolTcp = 6;
const int ipProtocolUdp = 17;

/// One's-complement internet checksum over even-length padded bytes.
int internetChecksum(List<int> bytes) {
  var sum = 0;
  for (var i = 0; i + 1 < bytes.length; i += 2) {
    sum += (bytes[i] << 8) | bytes[i + 1];
  }
  if (bytes.length.isOdd) {
    sum += bytes[bytes.length - 1] << 8;
  }
  while (sum >> 16 != 0) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return (~sum) & 0xffff;
}

Uint8List _pseudoHeader(
  List<int> srcIp,
  List<int> dstIp,
  int protocol,
  int length,
) {
  final header = <int>[
    ...srcIp,
    ...dstIp,
    0,
    protocol,
    (length >> 8) & 0xff,
    length & 0xff,
  ];
  return Uint8List.fromList(header);
}

int tcpChecksum(
  List<int> srcIp,
  List<int> dstIp,
  List<int> segment,
) {
  final pseudo = _pseudoHeader(srcIp, dstIp, ipProtocolTcp, segment.length);
  final combined = <int>[...pseudo, ...segment];
  return internetChecksum(combined);
}

int udpChecksum(
  List<int> srcIp,
  List<int> dstIp,
  List<int> datagram,
) {
  final pseudo = _pseudoHeader(srcIp, dstIp, ipProtocolUdp, datagram.length);
  final combined = <int>[...pseudo, ...datagram];
  return internetChecksum(combined);
}

int ipv4HeaderChecksum(List<int> header) => internetChecksum(header);

/// Builds a complete IPv4 packet (20-byte header, no options).
Uint8List buildIpPacket({
  required List<int> srcIp,
  required List<int> dstIp,
  required int protocol,
  required Uint8List payload,
  int identification = 0,
  int ttl = 64,
}) {
  final totalLength = 20 + payload.length;
  final header = ByteData(20);
  header.setUint8(0, 0x45);
  header.setUint8(1, 0x00);
  header.setUint16(2, totalLength, Endian.big);
  header.setUint16(4, identification & 0xffff, Endian.big);
  header.setUint16(6, 0x4000, Endian.big);
  header.setUint8(8, ttl);
  header.setUint8(9, protocol);
  header.setUint16(10, 0, Endian.big);
  for (var i = 0; i < 4; i++) {
    header.setUint8(12 + i, srcIp[i]);
    header.setUint8(16 + i, dstIp[i]);
  }
  final headerBytes = header.buffer.asUint8List();
  final checksum = ipv4HeaderChecksum(headerBytes);
  header.setUint16(10, checksum, Endian.big);

  final packet = Uint8List(totalLength);
  packet.setRange(0, 20, headerBytes);
  packet.setRange(20, totalLength, payload);
  return packet;
}

class Ipv4Packet {
  const Ipv4Packet({
    required this.protocol,
    required this.srcIp,
    required this.dstIp,
    required this.payload,
  });

  final int protocol;
  final List<int> srcIp;
  final List<int> dstIp;
  final Uint8List payload;
}

Ipv4Packet? parseIpv4Packet(Uint8List packet) {
  if (packet.length < 20) return null;
  final version = packet[0] >> 4;
  if (version != 4) return null;
  final headerLength = (packet[0] & 0x0f) * 4;
  if (headerLength < 20 || packet.length < headerLength) return null;
  final totalLength =
      ByteData.sublistView(packet, 2, 4).getUint16(0, Endian.big);
  if (totalLength < headerLength || totalLength > packet.length) return null;
  return Ipv4Packet(
    protocol: packet[9],
    srcIp: List<int>.from(packet.sublist(12, 16)),
    dstIp: List<int>.from(packet.sublist(16, 20)),
    payload: Uint8List.sublistView(packet, headerLength, totalLength),
  );
}

/// Builds a TCP segment (header + options + payload) with a valid checksum.
Uint8List buildTcpSegment({
  required List<int> srcIp,
  required List<int> dstIp,
  required int srcPort,
  required int dstPort,
  required int seq,
  required int ack,
  required int flags,
  required int window,
  Uint8List? payload,
  List<int> options = const <int>[],
}) {
  final data = payload ?? Uint8List(0);
  final optionsPadding = (4 - options.length % 4) % 4;
  final headerLength = 20 + options.length + optionsPadding;
  final segment = Uint8List(headerLength + data.length);
  final view = ByteData.sublistView(segment);
  view.setUint16(0, srcPort, Endian.big);
  view.setUint16(2, dstPort, Endian.big);
  view.setUint32(4, seq & 0xffffffff, Endian.big);
  view.setUint32(8, ack & 0xffffffff, Endian.big);
  view.setUint8(12, (headerLength ~/ 4) << 4);
  view.setUint8(13, flags);
  view.setUint16(14, window, Endian.big);
  view.setUint16(18, 0, Endian.big);
  segment.setRange(20, 20 + options.length, options);
  segment.setRange(headerLength, segment.length, data);
  final checksum = tcpChecksum(srcIp, dstIp, segment);
  view.setUint16(16, checksum, Endian.big);
  return segment;
}

class TcpSegment {
  const TcpSegment({
    required this.srcPort,
    required this.dstPort,
    required this.seq,
    required this.ack,
    required this.flags,
    required this.window,
    required this.options,
    required this.payload,
    required this.validChecksum,
  });

  final int srcPort;
  final int dstPort;
  final int seq;
  final int ack;
  final int flags;
  final int window;
  final Uint8List options;
  final Uint8List payload;
  final bool validChecksum;

  bool get syn => flags & tcpFlagSyn != 0;
  bool get hasAck => flags & tcpFlagAck != 0;
  bool get fin => flags & tcpFlagFin != 0;
  bool get rst => flags & tcpFlagRst != 0;
}

TcpSegment? parseTcpSegment(
  List<int> srcIp,
  List<int> dstIp,
  Uint8List segment,
) {
  if (segment.length < 20) return null;
  final dataOffset = (segment[12] >> 4) * 4;
  if (dataOffset < 20 || dataOffset > segment.length) return null;
  final view = ByteData.sublistView(segment);
  final parsed = TcpSegment(
    srcPort: view.getUint16(0, Endian.big),
    dstPort: view.getUint16(2, Endian.big),
    seq: view.getUint32(4, Endian.big),
    ack: view.getUint32(8, Endian.big),
    flags: segment[13],
    window: view.getUint16(14, Endian.big),
    options: Uint8List.sublistView(segment, 20, dataOffset),
    payload: Uint8List.sublistView(segment, dataOffset),
    validChecksum: tcpChecksum(srcIp, dstIp, segment) == 0,
  );
  return parsed;
}

/// Builds a UDP datagram. A zero checksum is legal for IPv4 and skips the
/// computation.
Uint8List buildUdpDatagram({
  required List<int> srcIp,
  required List<int> dstIp,
  required int srcPort,
  required int dstPort,
  required Uint8List payload,
  bool computeChecksum = true,
}) {
  final datagram = Uint8List(8 + payload.length);
  final view = ByteData.sublistView(datagram);
  view.setUint16(0, srcPort, Endian.big);
  view.setUint16(2, dstPort, Endian.big);
  view.setUint16(4, datagram.length, Endian.big);
  datagram.setRange(8, datagram.length, payload);
  if (computeChecksum) {
    final checksum = udpChecksum(srcIp, dstIp, datagram);
    view.setUint16(6, checksum == 0 ? 0xffff : checksum, Endian.big);
  }
  return datagram;
}

class UdpDatagram {
  const UdpDatagram({
    required this.srcPort,
    required this.dstPort,
    required this.payload,
  });

  final int srcPort;
  final int dstPort;
  final Uint8List payload;
}

UdpDatagram? parseUdpDatagram(Uint8List datagram) {
  if (datagram.length < 8) return null;
  final view = ByteData.sublistView(datagram);
  final length = view.getUint16(4, Endian.big);
  if (length < 8 || length > datagram.length) return null;
  return UdpDatagram(
    srcPort: view.getUint16(0, Endian.big),
    dstPort: view.getUint16(2, Endian.big),
    payload: Uint8List.sublistView(datagram, 8, length),
  );
}

/// The MSS option bytes for a SYN segment.
List<int> mssOption(int mss) => [0x02, 0x04, (mss >> 8) & 0xff, mss & 0xff];

/// Reads the MSS advertised in a segment's options, if any.
int? parseMssOption(Uint8List options) {
  var offset = 0;
  while (offset < options.length) {
    final kind = options[offset];
    if (kind == 0) return null;
    if (kind == 1) {
      offset += 1;
      continue;
    }
    if (offset + 1 >= options.length) return null;
    final length = options[offset + 1];
    if (length < 2) return null;
    if (kind == 2 && length == 4 && offset + 3 < options.length) {
      return (options[offset + 2] << 8) | options[offset + 3];
    }
    offset += length;
  }
  return null;
}
