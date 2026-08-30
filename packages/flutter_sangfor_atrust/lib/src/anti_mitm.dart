import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';

class ATrustAntiMitmData {
  const ATrustAntiMitmData({
    required this.enable,
    required this.devicePublicKeyModulus,
    required this.devicePublicKeyExponent,
    required this.challenge,
    required this.encryptedChallenge,
    required this.mitmSignature,
    this.rsaCertificate,
    this.sm2EncryptionCertificate,
    this.ticket,
    this.antiMitmRequest = false,
  });

  factory ATrustAntiMitmData.fromMap(Map<String, Object?> map) =>
      ATrustAntiMitmData(
        enable: _int(map['enable']),
        devicePublicKeyModulus: _string(map['devicePubKeyMod']),
        devicePublicKeyExponent: _string(map['devicePubKeyExp']),
        challenge: _string(map['challenge']),
        encryptedChallenge: _string(map['encryptedChallenge']),
        mitmSignature: _string(map['mitmSig']),
        rsaCertificate: _string(map['rsaCert']),
        sm2EncryptionCertificate: _string(map['sm2encCert']),
        ticket: _string(map['ticket']),
        antiMitmRequest: map['antiMITMRequest'] as bool? ?? false,
      );

  final int enable;
  final String devicePublicKeyModulus;
  final String devicePublicKeyExponent;
  final String challenge;
  final String encryptedChallenge;
  final String mitmSignature;
  final String? rsaCertificate;
  final String? sm2EncryptionCertificate;
  final String? ticket;
  final bool antiMitmRequest;

  void verifyChallenge() {
    _requireEnabled();
    final material = sha256.convert(utf8.encode(
      '$devicePublicKeyModulus$devicePublicKeyExponent'
      'OrHWuJz7gku5awmVb5w1sKTmfeCWHmzokBxmn0sn0faIcv1G10PdrbbRGKBrrZ3m',
    )).bytes;
    final cipher = CBCBlockCipher(AESEngine())
      ..init(
        true,
        ParametersWithIV(
          KeyParameter(Uint8List.fromList(material.sublist(0, 16))),
          Uint8List.fromList(material.sublist(16, 32)),
        ),
      );
    final padded = Uint8List.fromList(_pkcs7(utf8.encode(challenge), 16));
    final encrypted = Uint8List(padded.length);
    for (var offset = 0; offset < padded.length; offset += 16) {
      cipher.processBlock(padded, offset, encrypted, offset);
    }
    final actual = _upperHex(encrypted);
    if (actual != encryptedChallenge.toUpperCase()) {
      throw const FormatException('aTrust anti-MITM challenge mismatch');
    }
  }

  void verifyResponseSignature(Map<String, Object?> rawResponse) {
    _requireEnabled();
    if (mitmSignature.isEmpty) {
      throw const FormatException('aTrust anti-MITM signature is missing');
    }
    final first = sha256.convert(utf8.encode(
      '$devicePublicKeyModulus$devicePublicKeyExponent'
      '3uW5IEy8KwDaOMK8uw1TmNr50U3aK1Qdu8b6vopXxGstzan3AJXxVNR6piuKi5Nq',
    )).bytes;
    final second = sha256.convert(utf8.encode(
      _upperHex(first) + challenge,
    )).bytes;
    final key = <int>[
      for (var index = 0; index < 32; index++) first[index] ^ second[index],
    ];
    final fields = <String, String>{};
    _collect(rawResponse, fields);
    final origin = fields.keys.toList()..sort();
    final message = origin.map((key) => '$key:${fields[key]}').join('&');
    final expected = _upperHex(Hmac(sha256, key)
        .convert(utf8.encode(message))
        .bytes);
    if (expected != mitmSignature.toUpperCase()) {
      throw const FormatException('aTrust anti-MITM response signature mismatch');
    }
  }

  void verifyCertificateIdentity(Iterable<List<int>> peerCertificates) {
    _requireEnabled();
    final encodedCertificates = <String>[
      if (rsaCertificate != null && rsaCertificate!.isNotEmpty)
        rsaCertificate!,
      if (sm2EncryptionCertificate != null &&
          sm2EncryptionCertificate!.isNotEmpty)
        sm2EncryptionCertificate!,
    ];
    if (encodedCertificates.isEmpty) {
      throw const FormatException(
        'aTrust anti-MITM certificate identities are missing',
      );
    }
    final expected = encodedCertificates
        .map(_certificateDigestFromBase64)
        .toSet();
    for (final certificate in peerCertificates) {
      final actual = _certificateDigest(certificate);
      if (expected.contains(actual)) return;
    }
    throw const FormatException('aTrust anti-MITM certificate mismatch');
  }

  void _requireEnabled() {
    if (enable != 1) throw StateError('anti-MITM is not enabled');
    if (devicePublicKeyModulus.isEmpty ||
        devicePublicKeyExponent.isEmpty ||
        challenge.isEmpty) {
      throw const FormatException('incomplete aTrust anti-MITM data');
    }
  }
}

void _collect(Object? value, Map<String, String> fields) {
  if (value is Map) {
    for (final entry in value.entries) {
      final key = entry.key.toString();
      if (key == 'mitmSig') continue;
      final child = entry.value;
      if (child is Map || child is List) {
        _collect(child, fields);
      } else {
        fields[key] = _scalar(child);
      }
    }
  } else if (value is List) {
    for (final child in value) {
      _collect(child, fields);
    }
  }
}

String _scalar(Object? value) => switch (value) {
      null => 'null',
      bool value => value.toString(),
      num value => value.toString(),
      _ => value.toString(),
    };

List<int> _pkcs7(List<int> value, int blockSize) {
  final count = blockSize - value.length % blockSize;
  return <int>[...value, ...List<int>.filled(count, count)];
}

String _upperHex(Iterable<int> bytes) =>
    bytes.map((value) => value.toRadixString(16).padLeft(2, '0')).join().toUpperCase();

String _certificateDigest(List<int> der) => _certificateDigestFromBase64(
      base64Encode(der),
    );

String _certificateDigestFromBase64(String encoded) => _upperHex(
      sha256.convert(utf8.encode('$encoded@~*&!()-')).bytes,
    );

String _string(Object? value) => value is String ? value : '';

int _int(Object? value) => value is int ? value : int.tryParse('$value') ?? 0;
