import 'dart:typed_data';

/// Minimal DER reader sufficient to walk X.509 certificate structures.
class DerReader {
  DerReader(this.data, [this.offset = 0]);

  final Uint8List data;
  int offset;

  bool get hasMore => offset < data.length;

  int peekTag() {
    if (offset >= data.length) {
      throw const FormatException('no DER element to peek');
    }
    return data[offset];
  }

  /// Reads one TLV element and returns (tag, content bytes).
  (int, Uint8List) readElement() {
    if (offset + 2 > data.length) {
      throw const FormatException('truncated DER element');
    }
    final tag = data[offset];
    var length = data[offset + 1];
    var headerLength = 2;
    if (length & 0x80 != 0) {
      final lengthBytes = length & 0x7f;
      if (lengthBytes == 0 || lengthBytes > 4) {
        throw const FormatException('unsupported DER length');
      }
      if (offset + 2 + lengthBytes > data.length) {
        throw const FormatException('truncated DER length');
      }
      length = 0;
      for (var index = 0; index < lengthBytes; index++) {
        length = (length << 8) | data[offset + 2 + index];
      }
      headerLength = 2 + lengthBytes;
    }
    if (offset + headerLength + length > data.length) {
      throw const FormatException('DER element exceeds buffer');
    }
    final content = Uint8List.sublistView(
      data,
      offset + headerLength,
      offset + headerLength + length,
    );
    offset += headerLength + length;
    return (tag, content);
  }

  /// Reads one element and returns a reader over its content.
  DerReader readConstructed() {
    final (_, content) = readElement();
    return DerReader(content);
  }
}

/// The RSA public key extracted from an X.509 certificate.
class TlsRsaPublicKey {
  const TlsRsaPublicKey({required this.modulus, required this.exponent});

  final BigInt modulus;
  final BigInt exponent;
}

BigInt _readInteger(Uint8List content) {
  if (content.isEmpty) return BigInt.zero;
  if (content[0] & 0x80 == 0) {
    var value = BigInt.zero;
    for (final byte in content) {
      value = (value << 8) | BigInt.from(byte);
    }
    return value;
  }
  if (content.length == 1) {
    return BigInt.from(content[0] - 256);
  }
  throw const FormatException('negative RSA integer not expected');
}

/// Extracts the RSA SubjectPublicKeyInfo from a DER certificate, walking the
/// RFC 5280 layout deterministically: tbsCertificate -> [version], serial,
/// signature, issuer, validity, subject, subjectPublicKeyInfo.
TlsRsaPublicKey parseRsaPublicKey(Uint8List certificateDer) {
  final certificate = DerReader(certificateDer).readConstructed();
  final tbs = certificate.readConstructed();
  if (tbs.hasMore && tbs.peekTag() == 0xa0) {
    tbs.readElement(); // [0] EXPLICIT version
  }
  tbs.readElement(); // serialNumber INTEGER
  tbs.readConstructed(); // signature AlgorithmIdentifier
  tbs.readConstructed(); // issuer Name
  tbs.readConstructed(); // validity Validity
  tbs.readConstructed(); // subject Name
  final spki = tbs.readConstructed(); // subjectPublicKeyInfo
  spki.readConstructed(); // algorithm AlgorithmIdentifier
  final (bitTag, bitContent) =
      spki.readElement(); // subjectPublicKey BIT STRING
  if (bitTag != 0x03) {
    throw const FormatException('subjectPublicKey is not a BIT STRING');
  }
  if (bitContent.isEmpty || bitContent[0] != 0) {
    throw const FormatException('unexpected subjectPublicKey padding');
  }
  final rsa = DerReader(
    Uint8List.sublistView(bitContent, 1),
  ).readConstructed();
  final (modulusTag, modulusContent) = rsa.readElement();
  final (exponentTag, exponentContent) = rsa.readElement();
  if (modulusTag != 0x02 || exponentTag != 0x02) {
    throw const FormatException('unexpected RSA public key structure');
  }
  return TlsRsaPublicKey(
    modulus: _readInteger(modulusContent),
    exponent: _readInteger(exponentContent),
  );
}
