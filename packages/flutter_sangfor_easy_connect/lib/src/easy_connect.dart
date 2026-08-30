import 'dart:convert';
import 'dart:math';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:http/http.dart' as http;

import 'data_plane.dart';

typedef EasyConnectCodeProvider = Future<String> Function();

class EasyConnectLoginOptions {
  const EasyConnectLoginOptions({
    required this.server,
    required this.username,
    required this.password,
    this.smsCodeProvider,
    this.totpCodeProvider,
  });

  final Uri server;
  final String username;
  final String password;
  final EasyConnectCodeProvider? smsCodeProvider;
  final EasyConnectCodeProvider? totpCodeProvider;
}

class EasyConnectSession {
  const EasyConnectSession({required this.twfId});

  final String twfId;
}

class EasyConnectApiException implements Exception {
  const EasyConnectApiException(this.message, {this.statusCode});

  final String message;
  final int? statusCode;

  @override
  String toString() => statusCode == null
      ? 'EasyConnectApiException: $message'
      : 'EasyConnectApiException($statusCode): $message';
}

class EasyConnectLoginSession {
  EasyConnectLoginSession({http.Client? client}) : _client = client ?? http.Client();

  final http.Client _client;
  String? _twfId;

  Future<EasyConnectSession> login(EasyConnectLoginOptions options) async {
    _requireHttps(options.server);
    final auth = await _getAuth(options.server);
    _twfId = auth.twfId;
    var authResponse = await _postForm(
      options.server,
      '/por/login_psw.csp',
      <String, String>{
        'svpn_rand_code': '',
        'mitm': '',
        'svpn_req_randcode': auth.csrfCode,
        'svpn_name': options.username,
        'svpn_password': _encryptPassword(
          '${options.password}_${auth.csrfCode}',
          auth.modulus,
          auth.exponent,
        ),
      },
      query: const <String, String>{
        'anti_replay': '1',
        'encrypt': '1',
        'type': 'cs',
      },
    );
    if (_contains(authResponse, '<NextService>auth/sms</NextService>')) {
      final provider = options.smsCodeProvider;
      if (provider == null) {
        throw const SangforException(
          SangforErrorCode.mfaRequired,
          'EasyConnect SMS code is required',
        );
      }
      await _postForm(options.server, '/por/login_sms.csp', const <String, String>{});
      authResponse = await _postForm(
        options.server,
        '/por/login_sms1.csp',
        <String, String>{'svpn_inputsms': await provider()},
      );
    } else if (_contains(authResponse, '<NextService>auth/token</NextService>')) {
      final provider = options.totpCodeProvider;
      if (provider == null) {
        throw const SangforException(
          SangforErrorCode.mfaRequired,
          'EasyConnect TOTP code is required',
        );
      }
      authResponse = await _postForm(
        options.server,
        '/por/login_token.csp',
        <String, String>{'svpn_inputtoken': await provider()},
      );
    }
    if (!_contains(authResponse, '<Result>1</Result>') &&
        !_contains(authResponse, 'Auth sms suc') &&
        !_contains(authResponse, 'Totp auth succ')) {
      throw const EasyConnectApiException('EasyConnect password authentication failed');
    }
    return EasyConnectSession(twfId: _twfId!);
  }

  String? get twfId => _twfId;

  Future<EasyConnectConfig> fetchConfig(Uri server) async {
    _requireAuthenticated();
    final body = await _request(
      server,
      '/por/conf.csp',
      method: 'GET',
    );
    return EasyConnectConfig.parse(body);
  }

  Future<EasyConnectResourceList> fetchResourceList(Uri server) async {
    _requireAuthenticated();
    final body = await _request(
      server,
      '/por/rclist.csp',
      method: 'GET',
    );
    return EasyConnectResourceList.parse(body);
  }

  void _requireAuthenticated() {
    if (_twfId == null) {
      throw const EasyConnectApiException(
        'EasyConnect session is not authenticated',
      );
    }
  }

  Future<_AuthResponse> _getAuth(Uri server) async {
    final response = await _request(server, '/por/login_auth.csp', method: 'GET',
        query: const <String, String>{'apiversion': '1'});
    final twfId = _tag(response, 'TwfID');
    final modulus = _tag(response, 'RSA_ENCRYPT_KEY');
    if (twfId.isEmpty || modulus.isEmpty) {
      throw const EasyConnectApiException('EasyConnect auth response is incomplete');
    }
    return _AuthResponse(
      twfId: twfId,
      modulus: modulus,
      exponent: int.tryParse(_tag(response, 'RSA_ENCRYPT_EXP')) ?? 65537,
      csrfCode: _tag(response, 'CSRF_RAND_CODE'),
    );
  }

  Future<String> _postForm(
    Uri server,
    String path,
    Map<String, String> fields, {
    Map<String, String> query = const <String, String>{},
  }) async =>
      _request(server, path, method: 'POST', query: query, fields: fields);

  Future<String> _request(
    Uri server,
    String path, {
    required String method,
    Map<String, String> query = const <String, String>{},
    Map<String, String> fields = const <String, String>{},
  }) async {
    final uri = server.replace(path: path, queryParameters: query);
    final request = http.Request(method, uri)
      ..headers['accept'] = '*/*'
      ..headers['user-agent'] = 'EasyConnect_windows';
    if (_twfId != null) request.headers['cookie'] = 'TWFID=$_twfId';
    if (method == 'POST') {
      request.headers['content-type'] = 'application/x-www-form-urlencoded';
      request.bodyFields = fields;
    }
    final response = await _client.send(request);
    final body = await response.stream.bytesToString();
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw EasyConnectApiException(
        'EasyConnect endpoint returned HTTP ${response.statusCode}',
        statusCode: response.statusCode,
      );
    }
    return body;
  }
}

class _AuthResponse {
  const _AuthResponse({
    required this.twfId,
    required this.modulus,
    required this.exponent,
    required this.csrfCode,
  });

  final String twfId;
  final String modulus;
  final int exponent;
  final String csrfCode;
}

String _tag(String body, String name) =>
    RegExp('<$name>([^<]*)</$name>').firstMatch(body)?.group(1) ?? '';

bool _contains(String body, String value) => body.contains(value);

void _requireHttps(Uri server) {
  if (server.scheme != 'https' || server.host.isEmpty) {
    throw const SangforException(
      SangforErrorCode.invalidOptions,
      'EasyConnect server must use HTTPS',
    );
  }
}

String _encryptPassword(String password, String modulusText, int exponent) {
  final modulus = BigInt.tryParse(modulusText, radix: 16);
  if (modulus == null || modulus <= BigInt.zero || exponent <= 0) {
    throw const EasyConnectApiException('EasyConnect RSA key is invalid');
  }
  final size = (modulus.bitLength + 7) ~/ 8;
  final plaintext = utf8.encode(password);
  final chunkSize = size - 11;
  if (chunkSize <= 0) throw const EasyConnectApiException('EasyConnect RSA key is too small');
  final output = <int>[];
  for (var offset = 0; offset < plaintext.length; offset += chunkSize) {
    final chunk = plaintext.sublist(offset, min(offset + chunkSize, plaintext.length));
    final padding = <int>[];
    final random = Random.secure();
    while (padding.length < size - chunk.length - 3) {
      final value = random.nextInt(256);
      if (value != 0) padding.add(value);
    }
    final encoded = <int>[0, 2, ...padding, 0, ...chunk];
    var message = BigInt.zero;
    for (final byte in encoded) {
      message = (message << 8) | BigInt.from(byte);
    }
    var encrypted = message.modPow(BigInt.from(exponent), modulus);
    final bytes = List<int>.filled(size, 0);
    for (var index = size - 1; index >= 0 && encrypted > BigInt.zero; index--) {
      bytes[index] = (encrypted & BigInt.from(255)).toInt();
      encrypted >>= 8;
    }
    output.addAll(bytes);
  }
  return output.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
}
