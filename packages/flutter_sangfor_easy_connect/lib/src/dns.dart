import 'dart:typed_data';

/// Builds one recursive A query for [host].
Uint8List buildDnsQuery(int id, String host) {
  final labels = host.split('.');
  final builder = BytesBuilder();
  final header = ByteData(12);
  header.setUint16(0, id & 0xffff, Endian.big);
  header.setUint16(2, 0x0100, Endian.big);
  header.setUint16(4, 1, Endian.big);
  builder.add(header.buffer.asUint8List());
  for (final label in labels) {
    final bytes = label.codeUnits;
    if (bytes.isEmpty || bytes.length > 63) {
      throw const FormatException('invalid DNS label');
    }
    builder.addByte(bytes.length);
    builder.add(bytes);
  }
  builder.addByte(0);
  final tail = ByteData(4);
  tail.setUint16(0, 1, Endian.big);
  tail.setUint16(2, 1, Endian.big);
  builder.add(tail.buffer.asUint8List());
  return builder.toBytes();
}

/// Returns the first IPv4 address in the answer section, or null when the
/// name has no A record. Throws [FormatException] on malformed replies.
List<int>? parseDnsAResponse(Uint8List reply, int expectedId) {
  if (reply.length < 12) {
    throw const FormatException('short DNS reply');
  }
  final view = ByteData.sublistView(reply);
  if (view.getUint16(0, Endian.big) != (expectedId & 0xffff)) {
    throw const FormatException('DNS reply id mismatch');
  }
  final flags = view.getUint16(2, Endian.big);
  if ((flags & 0x8000) == 0) {
    throw const FormatException('DNS reply is not a response');
  }
  final rcode = flags & 0x0f;
  if (rcode != 0) {
    throw FormatException('DNS reply rcode $rcode');
  }
  final questionCount = view.getUint16(4, Endian.big);
  final answerCount = view.getUint16(6, Endian.big);
  var offset = 12;
  for (var i = 0; i < questionCount; i++) {
    offset = _skipName(reply, offset);
    offset += 4;
  }
  List<int>? address;
  for (var i = 0; i < answerCount; i++) {
    offset = _skipName(reply, offset);
    if (offset + 10 > reply.length) {
      throw const FormatException('truncated DNS answer');
    }
    final type = view.getUint16(offset, Endian.big);
    offset += 8; // type, class, ttl
    final rdLength = view.getUint16(offset, Endian.big);
    offset += 2;
    if (offset + rdLength > reply.length) {
      throw const FormatException('truncated DNS rdata');
    }
    if (type == 1 && rdLength == 4) {
      address ??= List<int>.from(reply.sublist(offset, offset + 4));
    }
    offset += rdLength;
  }
  return address;
}

int _skipName(Uint8List reply, int offset) {
  while (true) {
    if (offset >= reply.length) {
      throw const FormatException('truncated DNS name');
    }
    final length = reply[offset];
    if (length == 0) return offset + 1;
    if ((length & 0xc0) == 0xc0) return offset + 2;
    offset += 1 + length;
  }
}

/// Parses a dotted IPv4 address, or null when [text] is not one.
List<int>? parseIPv4Address(String text) {
  final parts = text.split('.');
  if (parts.length != 4) return null;
  final bytes = <int>[];
  for (final part in parts) {
    if (part.isEmpty || part.length > 3) return null;
    final value = int.tryParse(part);
    if (value == null || value < 0 || value > 255) return null;
    bytes.add(value);
  }
  return bytes;
}
