import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// Cipher suites supported by the minimal TLS client.
enum TlsCipher {
  rsaRc4128Sha(0x0005, 20, 16, 0),
  rsaAes128CbcSha(0x002f, 20, 16, 16);

  const TlsCipher(this.id, this.macKeyLength, this.encKeyLength, this.ivLength);

  final int id;
  final int macKeyLength;
  final int encKeyLength;
  final int ivLength;

  static TlsCipher fromId(int id) => values.firstWhere(
        (cipher) => cipher.id == id,
        orElse: () => throw TlsRecordException('unsupported cipher 0x'
            '${id.toRadixString(16).padLeft(4, '0')}'),
      );
}

class TlsRecordException implements Exception {
  const TlsRecordException(this.message);

  final String message;

  @override
  String toString() => 'TlsRecordException: $message';
}

/// Record-layer protection for one direction of a TLS connection.
/// Implements the MAC-then-encrypt construction with SHA-1 HMAC and either
/// RC4 (stream) or AES-128-CBC (explicit per-record IV) per RFC 5246.
class TlsRecordCrypto {
  TlsRecordCrypto({
    required this.cipher,
    required Uint8List macKey,
    required Uint8List encKey,
    Random? random,
  })  : _macKey = Uint8List.fromList(macKey),
        _encKey = Uint8List.fromList(encKey),
        _random = random ?? Random.secure() {
    if (macKey.length != cipher.macKeyLength ||
        encKey.length != cipher.encKeyLength) {
      throw TlsRecordException('key material length mismatch');
    }
    switch (cipher) {
      case TlsCipher.rsaRc4128Sha:
        _encryptor = RC4Engine()..init(true, KeyParameter(_encKey));
        _decryptor = RC4Engine()..init(false, KeyParameter(_encKey));
      case TlsCipher.rsaAes128CbcSha:
        _encryptor = null;
        _decryptor = null;
    }
  }

  final TlsCipher cipher;
  final Uint8List _macKey;
  final Uint8List _encKey;
  final Random _random;
  RC4Engine? _encryptor;
  RC4Engine? _decryptor;
  int _sequence = 0;

  /// Protects one record payload and returns the on-wire ciphertext.
  Uint8List seal(int contentType, int version, Uint8List fragment) {
    final mac = _mac(contentType, version, fragment);
    final plaintext = Uint8List.fromList(<int>[...fragment, ...mac]);
    Uint8List payload;
    switch (cipher) {
      case TlsCipher.rsaRc4128Sha:
        final out = Uint8List(plaintext.length);
        _encryptor!.processBytes(plaintext, 0, plaintext.length, out, 0);
        payload = out;
      case TlsCipher.rsaAes128CbcSha:
        const blockSize = 16;
        // padding such that (content + mac + padding + padding_length) is a
        // multiple of the block size (RFC 5246 section 6.2.3.2).
        final paddingLength =
            (blockSize - ((plaintext.length + 1) % blockSize)) % blockSize;
        final padded = Uint8List(plaintext.length + paddingLength + 1);
        padded.setRange(0, plaintext.length, plaintext);
        for (var index = 0; index <= paddingLength; index++) {
          padded[plaintext.length + index] = paddingLength;
        }
        final iv = Uint8List.fromList(
          List<int>.generate(blockSize, (_) => _random.nextInt(256)),
        );
        final cbc = CBCBlockCipher(AESEngine())
          ..init(true, ParametersWithIV(KeyParameter(_encKey), iv));
        final encrypted = Uint8List(padded.length);
        var offset = 0;
        while (offset < padded.length) {
          offset += cbc.processBlock(padded, offset, encrypted, offset);
        }
        payload = Uint8List.fromList(<int>[...iv, ...encrypted]);
    }
    _sequence++;
    return payload;
  }

  /// Unprotects one record ciphertext and returns the plaintext fragment.
  Uint8List open(int contentType, int version, Uint8List payload) {
    Uint8List plaintext;
    switch (cipher) {
      case TlsCipher.rsaRc4128Sha:
        final out = Uint8List(payload.length);
        _decryptor!.processBytes(payload, 0, payload.length, out, 0);
        plaintext = out;
      case TlsCipher.rsaAes128CbcSha:
        if (payload.length < 16 || payload.length % 16 != 0) {
          throw const TlsRecordException('invalid CBC record length');
        }
        final iv = Uint8List.sublistView(payload, 0, 16);
        final body = Uint8List.sublistView(payload, 16);
        final cbc = CBCBlockCipher(AESEngine())
          ..init(false, ParametersWithIV(KeyParameter(_encKey), iv));
        final decrypted = Uint8List(body.length);
        var offset = 0;
        while (offset < body.length) {
          offset += cbc.processBlock(body, offset, decrypted, offset);
        }
        if (decrypted.isEmpty) {
          throw const TlsRecordException('empty CBC plaintext');
        }
        final paddingLength = decrypted[decrypted.length - 1];
        if (paddingLength + 1 > decrypted.length) {
          throw const TlsRecordException('invalid CBC padding');
        }
        for (var index = decrypted.length - paddingLength - 1;
            index < decrypted.length;
            index++) {
          if (decrypted[index] != paddingLength) {
            throw const TlsRecordException('invalid CBC padding bytes');
          }
        }
        plaintext = Uint8List.sublistView(
          decrypted,
          0,
          decrypted.length - paddingLength - 1,
        );
    }
    if (plaintext.length < cipher.macKeyLength) {
      throw const TlsRecordException('record too short for MAC');
    }
    final fragment = Uint8List.sublistView(
      plaintext,
      0,
      plaintext.length - cipher.macKeyLength,
    );
    final mac = Uint8List.sublistView(
      plaintext,
      plaintext.length - cipher.macKeyLength,
    );
    final expected = _mac(contentType, version, fragment);
    for (var index = 0; index < mac.length; index++) {
      if (mac[index] != expected[index]) {
        throw const TlsRecordException('bad record MAC');
      }
    }
    _sequence++;
    return fragment;
  }

  Uint8List _mac(int contentType, int version, Uint8List fragment) {
    final header = Uint8List(13);
    final data = ByteData.sublistView(header);
    data.setUint64(0, _sequence, Endian.big);
    header[8] = contentType;
    header[9] = (version >> 8) & 0xff;
    header[10] = version & 0xff;
    data.setUint16(11, fragment.length, Endian.big);
    final hmac = HMac(SHA1Digest(), 64)..init(KeyParameter(_macKey));
    hmac.update(header, 0, header.length);
    hmac.update(fragment, 0, fragment.length);
    final out = Uint8List(hmac.macSize);
    hmac.doFinal(out, 0);
    return out;
  }
}
