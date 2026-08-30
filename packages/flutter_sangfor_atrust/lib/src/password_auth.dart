import 'dart:convert';
import 'dart:math';

import 'package:http/http.dart' as http;

import 'api.dart';

/// Result of the primary aTrust password exchange.
class ATrustPasswordAuthResult {
  const ATrustPasswordAuthResult({
    required this.ticket,
    required this.graphCheckCodeRequired,
  });

  final String ticket;
  final bool graphCheckCodeRequired;
}

/// Performs the primary password exchange after auth discovery.
class ATrustPasswordAuthenticator {
  ATrustPasswordAuthenticator({http.Client? client})
      : _client = client ?? http.Client();

  final http.Client _client;

  Future<ATrustPasswordAuthResult> authenticate({
    required Uri server,
    required String username,
    required String password,
    required String loginDomain,
    required ATrustAuthConfig config,
    required String deviceId,
    String? graphCheckCode,
  }) async {
    final publicKey = _PublicKey.fromConfig(config);
    final plaintext =
        utf8.encode('${password}_${config.antiReplayRandom ?? ''}');
    final encrypted = _encryptPkcs1Chunks(publicKey, plaintext);
    final payload = <String, Object?>{
      'username': '$username@$loginDomain',
      'password': _hex(encrypted),
      'rememberPwd': '0',
      if (graphCheckCode != null) 'graphCheckCode': graphCheckCode,
    };
    final uri = server.replace(
      path: '/passport/v1/auth/psw',
      queryParameters: const <String, String>{
        'clientType': 'SDPClient',
        'platform': 'Flutter',
        'lang': 'en-US',
      },
      fragment: '',
    );
    final response = await _client.post(
      uri,
      headers: <String, String>{
        'content-type': 'application/json;charset=utf-8',
        'accept': 'application/json',
        'user-agent': 'flutter_sangfor',
        if (config.csrfToken != null) 'x-csrf-token': config.csrfToken!,
        'x-sdp-env': base64Encode(utf8.encode(jsonEncode(<String, String>{
          'deviceId': deviceId,
        }))),
        'x-sdp-rid': base64Encode(utf8.encode(server.authority)),
        'x-sdp-traceid': _traceId(),
      },
      body: jsonEncode(payload),
    );
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw ATrustApiException(
        'password endpoint returned HTTP ${response.statusCode}',
        statusCode: response.statusCode,
      );
    }
    final decoded = jsonDecode(response.body);
    if (decoded is! Map) {
      throw const ATrustApiException('password response is not a JSON object');
    }
    final root = Map<String, Object?>.from(decoded);
    final code = _asInt(root['code']);
    final data = _asMap(root['data']);
    final captchaRequired = _asInt(data['graphCheckCodeEnable']) == 1;
    if (code != 0 && !captchaRequired) {
      throw ATrustApiException(
        _asString(root['message']) ?? 'password authentication failed',
      );
    }
    final ticket = _asString(data['ticket']) ?? '';
    if (!captchaRequired && ticket.isEmpty) {
      throw const ATrustApiException(
        'password authentication succeeded without a ticket',
      );
    }
    return ATrustPasswordAuthResult(
      ticket: ticket,
      graphCheckCodeRequired: captchaRequired,
    );
  }
}

class _PublicKey {
  const _PublicKey(this.modulus, this.exponent);

  factory _PublicKey.fromConfig(ATrustAuthConfig config) {
    final modulusText = config.publicKey;
    final exponentText = config.publicKeyExponent;
    if (modulusText == null || modulusText.isEmpty) {
      throw const ATrustApiException('aTrust RSA public key is missing');
    }
    final modulus = BigInt.tryParse(modulusText, radix: 16);
    final exponent = int.tryParse(exponentText ?? '');
    if (modulus == null || modulus <= BigInt.zero) {
      throw const ATrustApiException('aTrust RSA public key is invalid');
    }
    if (exponent == null || exponent <= 0) {
      throw const ATrustApiException(
          'aTrust RSA public key exponent is invalid');
    }
    return _PublicKey(modulus, BigInt.from(exponent));
  }

  final BigInt modulus;
  final BigInt exponent;

  int get size => (modulus.bitLength + 7) ~/ 8;
}

List<int> _encryptPkcs1Chunks(_PublicKey key, List<int> plaintext) {
  final chunkSize = key.size - 11;
  if (chunkSize <= 0) {
    throw const ATrustApiException('aTrust RSA public key is too small');
  }
  final output = <int>[];
  for (var offset = 0; offset < plaintext.length; offset += chunkSize) {
    final end = min(offset + chunkSize, plaintext.length);
    final chunk = plaintext.sublist(offset, end);
    final paddingLength = key.size - chunk.length - 3;
    final padding = <int>[];
    final random = Random.secure();
    while (padding.length < paddingLength) {
      final value = random.nextInt(256);
      if (value != 0) padding.add(value);
    }
    final encoded = <int>[0, 2, ...padding, 0, ...chunk];
    final message = _bytesToBigInt(encoded);
    final encrypted = message.modPow(key.exponent, key.modulus);
    output.addAll(_bigIntToBytes(encrypted, key.size));
  }
  return output;
}

BigInt _bytesToBigInt(List<int> bytes) {
  var value = BigInt.zero;
  for (final byte in bytes) {
    value = (value << 8) | BigInt.from(byte);
  }
  return value;
}

List<int> _bigIntToBytes(BigInt value, int size) {
  final bytes = List<int>.filled(size, 0);
  for (var index = size - 1; index >= 0 && value > BigInt.zero; index--) {
    bytes[index] = (value & BigInt.from(255)).toInt();
    value >>= 8;
  }
  if (value != BigInt.zero) {
    throw const ATrustApiException('aTrust RSA result exceeds key size');
  }
  return bytes;
}

String _hex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

String _traceId() => List<String>.generate(
      8,
      (_) => Random.secure().nextInt(16).toRadixString(16),
    ).join();

Map<String, Object?> _asMap(Object? value) =>
    value is Map ? Map<String, Object?>.from(value) : <String, Object?>{};

String? _asString(Object? value) => value is String ? value : null;

int _asInt(Object? value) => value is int ? value : int.tryParse('$value') ?? 0;
