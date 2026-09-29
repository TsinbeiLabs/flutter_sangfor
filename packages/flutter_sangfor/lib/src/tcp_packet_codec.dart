import 'dart:typed_data';

/// IP protocol number for TCP (RFC 793).
const int tcpProtocolNumber = 6;

/// Minimum IPv4 header length in bytes.
const int ipv4HeaderLength = 20;

/// Minimum TCP header length in bytes.
const int tcpHeaderLength = 20;

const int tcpFlagFin = 0x01;
const int tcpFlagSyn = 0x02;
const int tcpFlagRst = 0x04;
const int tcpFlagPsh = 0x08;
const int tcpFlagAck = 0x10;

/// TCP option kind for the maximum segment size (RFC 6691).
const int tcpOptionMss = 2;

/// A parsed IPv4/TCP packet. The view borrows the underlying buffer; the
/// payload is a sublist view, so callers must not mutate it.
class SangforTcpSegment {
  SangforTcpSegment._(this.packet, this.headerLength, this._tcpOffset);

  /// Parses [packet] as an IPv4 datagram carrying TCP, or returns null when
  /// the buffer is too short, is not IPv4, or is not TCP.
  static SangforTcpSegment? parse(Uint8List packet) {
    if (packet.length < ipv4HeaderLength) return null;
    if (packet[0] >> 4 != 4) return null;
    final ipHeaderLength = (packet[0] & 0x0f) * 4;
    if (ipHeaderLength < ipv4HeaderLength || packet.length < ipHeaderLength) {
      return null;
    }
    if (packet[9] != tcpProtocolNumber) return null;
    final tcpOffset = ipHeaderLength;
    if (packet.length < tcpOffset + tcpHeaderLength) return null;
    final dataOffset = (packet[tcpOffset + 12] >> 4) * 4;
    if (dataOffset < tcpHeaderLength) return null;
    if (packet.length < tcpOffset + dataOffset) return null;
    final totalLength = _uint16(packet, 2);
    if (totalLength < ipHeaderLength || totalLength > packet.length) {
      return null;
    }
    return SangforTcpSegment._(packet, ipHeaderLength, tcpOffset);
  }

  /// The whole IP packet.
  final Uint8List packet;

  /// Length of the IP header, including options.
  final int headerLength;

  final int _tcpOffset;

  int get _dataOffset => (packet[_tcpOffset + 12] >> 4) * 4;

  /// Total length of the TCP header plus payload.
  int get tcpLength => _uint16(packet, 2) - headerLength;

  String get sourceAddress => _address(packet, 12);

  String get destinationAddress => _address(packet, 16);

  int get sourcePort => _uint16(packet, _tcpOffset);

  int get destinationPort => _uint16(packet, _tcpOffset + 2);

  int get sequenceNumber => _uint32(packet, _tcpOffset + 4);

  int get acknowledgmentNumber => _uint32(packet, _tcpOffset + 8);

  int get flags => packet[_tcpOffset + 13];

  bool get isSyn => flags & tcpFlagSyn != 0;

  bool get isAck => flags & tcpFlagAck != 0;

  bool get isFin => flags & tcpFlagFin != 0;

  bool get isRst => flags & tcpFlagRst != 0;

  /// The receive window the sender advertises, without scaling.
  int get window => _uint16(packet, _tcpOffset + 14);

  /// The MSS option the sender offered, or 0 when it did not send one.
  int get maximumSegmentSize {
    final end = _tcpOffset + _dataOffset;
    var index = _tcpOffset + tcpHeaderLength;
    while (index < end) {
      final kind = packet[index];
      if (kind == 0) break;
      if (kind == 1) {
        index++;
        continue;
      }
      if (index + 1 >= end) break;
      final length = packet[index + 1];
      if (length < 2 || index + length > end) break;
      if (kind == tcpOptionMss && length == 4) {
        return _uint16(packet, index + 2);
      }
      index += length;
    }
    return 0;
  }

  /// The TCP payload, empty for bare control segments.
  Uint8List get payload => Uint8List.sublistView(
        packet,
        _tcpOffset + _dataOffset,
        headerLength + tcpLength,
      );

  /// The identity of this segment's flow, from the client's point of view.
  String get flowKey =>
      '$sourceAddress:$sourcePort-$destinationAddress:$destinationPort';

  /// The same flow with the direction reversed.
  String get reversedFlowKey =>
      '$destinationAddress:$destinationPort-$sourceAddress:$sourcePort';

  static int _uint16(Uint8List data, int offset) =>
      (data[offset] << 8) | data[offset + 1];

  static int _uint32(Uint8List data, int offset) =>
      (data[offset] << 24) |
      (data[offset + 1] << 16) |
      (data[offset + 2] << 8) |
      data[offset + 3];
}

String _address(Uint8List data, int offset) =>
    '${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}';

List<int> parseIPv4Address(String address) {
  final parts = address.split('.');
  if (parts.length != 4) return const <int>[];
  final bytes = <int>[];
  for (final part in parts) {
    final value = int.tryParse(part);
    if (value == null || value < 0 || value > 255) return const <int>[];
    bytes.add(value);
  }
  return bytes;
}

/// Builds IPv4/TCP packets for the userspace data plane, checksums included.
///
/// Tunnel adapters differ in whether they verify checksums, so every packet is
/// fully computed instead of relying on offload.
class SangforTcpPacketBuilder {
  const SangforTcpPacketBuilder();

  static final Uint8List _emptyPayload = Uint8List(0);

  /// Assembles one IPv4/TCP packet. [mss] adds an MSS option to the TCP
  /// header, which is what a SYN-ACK needs to clamp the peer's segments.
  Uint8List build({
    required String sourceAddress,
    required String destinationAddress,
    required int sourcePort,
    required int destinationPort,
    required int sequenceNumber,
    required int acknowledgmentNumber,
    required int flags,
    required int window,
    Uint8List? payload,
    int? mss,
    int identification = 0,
    int timeToLive = 64,
  }) {
    final source = parseIPv4Address(sourceAddress);
    final destination = parseIPv4Address(destinationAddress);
    if (source.length != 4 || destination.length != 4) {
      throw ArgumentError.value(
        '$sourceAddress -> $destinationAddress',
        'endpoints',
        'both endpoints must be dotted-quad IPv4 addresses',
      );
    }
    final optionLength = mss == null ? 0 : 4;
    final body = payload ?? _emptyPayload;
    final tcpLength = tcpHeaderLength + optionLength + body.length;
    final packet = Uint8List(ipv4HeaderLength + tcpLength);
    final data = ByteData.sublistView(packet);

    // IPv4 header: version/IHL, DSCP, total length, identification, flags,
    // TTL, protocol, checksum, addresses.
    packet[0] = 0x45;
    data.setUint16(2, packet.length, Endian.big);
    data.setUint16(4, identification & 0xffff, Endian.big);
    packet[8] = timeToLive;
    packet[9] = tcpProtocolNumber;
    for (var index = 0; index < 4; index++) {
      packet[12 + index] = source[index];
      packet[16 + index] = destination[index];
    }
    data.setUint16(10, ipv4HeaderChecksum(packet), Endian.big);

    // TCP header.
    final tcp = ipv4HeaderLength;
    data.setUint16(tcp, sourcePort & 0xffff, Endian.big);
    data.setUint16(tcp + 2, destinationPort & 0xffff, Endian.big);
    data.setUint32(tcp + 4, sequenceNumber & 0xffffffff, Endian.big);
    data.setUint32(tcp + 8, acknowledgmentNumber & 0xffffffff, Endian.big);
    packet[tcp + 12] = ((tcpHeaderLength + optionLength) ~/ 4) << 4;
    packet[tcp + 13] = flags & 0xff;
    data.setUint16(tcp + 14, window & 0xffff, Endian.big);
    if (mss != null) {
      packet[tcp + tcpHeaderLength] = tcpOptionMss;
      packet[tcp + tcpHeaderLength + 1] = 4;
      data.setUint16(tcp + tcpHeaderLength + 2, mss & 0xffff, Endian.big);
    }
    if (body.isNotEmpty) {
      packet.setRange(
        tcp + tcpHeaderLength + optionLength,
        packet.length,
        body,
      );
    }
    data.setUint16(
      tcp + 16,
      tcpChecksum(packet, headerLength: ipv4HeaderLength),
      Endian.big,
    );
    return packet;
  }
}

/// The ones'-complement checksum of an IPv4 header. [packet]'s checksum field
/// must be zero; only the first [headerLength] bytes are covered.
int ipv4HeaderChecksum(
  Uint8List packet, {
  int headerLength = ipv4HeaderLength,
}) {
  var sum = 0;
  for (var index = 0; index + 1 < headerLength; index += 2) {
    if (index == 10) continue;
    sum += (packet[index] << 8) | packet[index + 1];
  }
  return complement(sum);
}

/// The TCP checksum over the pseudo-header, the TCP header, and the payload.
/// The checksum field inside the header must be zero.
int tcpChecksum(Uint8List packet, {int headerLength = ipv4HeaderLength}) {
  final tcpOffset = headerLength;
  final totalLength = (packet[2] << 8) | packet[3];
  final tcpLength = totalLength - headerLength;
  var sum = 0;
  // Pseudo-header: source, destination, zero, protocol, TCP length.
  for (var index = 12; index < 20; index += 2) {
    sum += (packet[index] << 8) | packet[index + 1];
  }
  sum += packet[9];
  sum += tcpLength;
  for (var index = 0; index + 1 < tcpLength; index += 2) {
    sum += (packet[tcpOffset + index] << 8) | packet[tcpOffset + index + 1];
  }
  if (tcpLength.isOdd) {
    sum += packet[tcpOffset + tcpLength - 1] << 8;
  }
  return complement(sum);
}

/// Folds a 32-bit accumulation into an inverted 16-bit checksum.
int complement(int sum) {
  var value = sum;
  while (value >> 16 != 0) {
    value = (value & 0xffff) + (value >> 16);
  }
  return (~value) & 0xffff;
}

/// Adds [a] and [b] in TCP sequence space (32-bit wraparound).
int tcpSequenceAdd(int a, int b) => (a + b) & 0xffffffff;

/// The distance from [from] to [to] in TCP sequence space, as a signed value:
/// positive when [to] is ahead.
int tcpSequenceDifference(int from, int to) {
  final difference = (to - from) & 0xffffffff;
  return difference >= 0x80000000 ? difference - 0x100000000 : difference;
}
