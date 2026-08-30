import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:http/http.dart' as http;

import 'anti_mitm.dart';

/// Authentication method advertised by an aTrust server.
class ATrustAuthInfo {
  const ATrustAuthInfo({
    required this.authType,
    required this.loginDomain,
    this.authName,
    this.loginUrl,
  });

  factory ATrustAuthInfo.fromMap(Map<String, Object?> map) => ATrustAuthInfo(
        authType: map['authType'] as String? ?? '',
        loginDomain: map['loginDomain'] as String? ?? '',
        authName: map['authName'] as String?,
        loginUrl: map['loginUrl'] as String?,
      );

  final String authType;
  final String loginDomain;
  final String? authName;
  final String? loginUrl;
}

/// Normalized response from the aTrust auth configuration endpoint.
class ATrustAuthConfig {
  const ATrustAuthConfig({
    required this.isLoggedIn,
    required this.authMethods,
    this.csrfToken,
    this.publicKey,
    this.publicKeyExponent,
    this.antiReplayRandom,
    this.antiMitm,
  });

  final bool isLoggedIn;
  final List<ATrustAuthInfo> authMethods;
  final String? csrfToken;
  final String? publicKey;
  final String? publicKeyExponent;
  final String? antiReplayRandom;
  final ATrustAntiMitmData? antiMitm;
}

class ATrustApiException implements Exception {
  const ATrustApiException(this.message, {this.statusCode});

  final String message;
  final int? statusCode;

  @override
  String toString() => statusCode == null
      ? 'ATrustApiException: $message'
      : 'ATrustApiException($statusCode): $message';
}

/// HTTPS discovery client. It deliberately uses the platform trust store.
class ATrustApiClient {
  ATrustApiClient({
    http.Client? client,
    this.enforceAntiMitm = true,
  }) : _client = client ?? http.Client();

  final http.Client _client;
  final bool enforceAntiMitm;

  Future<ATrustAuthConfig> fetchAuthConfig(Uri server) async {
    final response = await _get(server, '/passport/v1/public/authConfig', {
      'needTicket': '1',
    });
    final envelope = _envelope(response, 'auth config');
    final data = _map(envelope['data']);
    final security = _map(data['security']);
    final methods = (_list(data['authServerInfoList']))
        .map((item) => ATrustAuthInfo.fromMap(_map(item)))
        .where((item) => item.authType.isNotEmpty)
        .toList(growable: false);
    final antiMitm = data['antiMITMAttackData'] is Map
        ? ATrustAntiMitmData.fromMap(
            Map<String, Object?>.from(data['antiMITMAttackData'] as Map),
          )
        : null;
    if (enforceAntiMitm && antiMitm?.enable == 1) {
      antiMitm!.verifyChallenge();
      antiMitm.verifyResponseSignature(envelope);
    }
    return ATrustAuthConfig(
      isLoggedIn: _int(data['isLogin']) == 1,
      authMethods: methods,
      csrfToken: _string(data['csrfToken']) ?? _string(security['csrfToken']),
      publicKey: _string(data['pubKey']),
      publicKeyExponent: _string(data['pubKeyExp']),
      antiReplayRandom: _string(data['antiReplayRand']),
      antiMitm: antiMitm,
    );
  }

  Future<Map<String, Object?>> fetchManifest(Uri server) async {
    final response = await _get(server, '/public/manifest', const {});
    return _data(response);
  }

  Future<Map<String, Object?>> fetchClientResource({
    required Uri server,
    required String csrfToken,
  }) async {
    final uri = server.replace(
      path: '/controller/v1/user/clientResource',
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
        'x-csrf-token': csrfToken,
        'x-sdp-rid': _rid(server),
        'x-sdp-traceid': _traceId(),
      },
      body: jsonEncode(<String, Object?>{
        'resourceType': <String, Object?>{
          'sdpPolicy': <String, Object?>{},
          'appList': <String, Object?>{},
          'favoriteAppList': <String, Object?>{},
          'featureCenter': <String, Object?>{},
          'uemSpace': <String, Object?>{
            'params': <String, String>{'action': 'login'},
          },
        },
      }),
    );
    return _envelope(response, 'client resource');
  }

  /// Connects to the server and verifies the peer certificate digest against
  /// the anti-MITM identities advertised by the auth configuration. The
  /// connection pins the certificate instead of relying on the platform
  /// trust store, mirroring the aTrust anti-MITM design.
  Future<void> verifyServerCertificate(
    Uri server,
    ATrustAntiMitmData antiMitm,
  ) async {
    final context = SecurityContext(withTrustedRoots: false);
    final socket = await SecureSocket.connect(
      server.host,
      server.port == 0 ? 443 : server.port,
      context: context,
      onBadCertificate: (certificate) {
        try {
          antiMitm.verifyCertificateIdentity([certificate.der]);
          return true;
        } on Object {
          return false;
        }
      },
      timeout: const Duration(seconds: 10),
    );
    await socket.close();
  }

  Future<http.Response> _get(
    Uri server,
    String path,
    Map<String, String> extraQuery,
  ) async {
    final uri = server.replace(
      path: path,
      queryParameters: <String, String>{
        'clientType': 'SDPClient',
        'platform': 'Flutter',
        'lang': 'en-US',
        ...extraQuery,
      },
      fragment: '',
    );
    final response = await _client.get(
      uri,
      headers: <String, String>{
        'accept': 'application/json',
        'user-agent': 'flutter_sangfor',
        'x-sdp-rid': _rid(server),
        'x-sdp-traceid': _traceId(),
      },
    );
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw ATrustApiException(
        'aTrust endpoint returned HTTP ${response.statusCode}',
        statusCode: response.statusCode,
      );
    }
    return response;
  }

  Map<String, Object?> _data(http.Response response) {
    return _map(_envelope(response, 'aTrust request')['data']);
  }

  Map<String, Object?> _envelope(http.Response response, String operation) {
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw ATrustApiException(
        '$operation endpoint returned HTTP ${response.statusCode}',
        statusCode: response.statusCode,
      );
    }
    final decoded = jsonDecode(response.body);
    if (decoded is! Map) {
      throw ATrustApiException('$operation response is not a JSON object');
    }
    final root = Map<String, Object?>.from(decoded);
    final code = _int(root['code']);
    if (code != 0) {
      throw ATrustApiException(
        _string(root['message']) ?? 'aTrust request failed',
      );
    }
    return root;
  }

  String _traceId() {
    final random = Random.secure();
    return List<String>.generate(
      8,
      (_) => random.nextInt(16).toRadixString(16),
    ).join();
  }

  static Map<String, Object?> _map(Object? value) =>
      value is Map ? Map<String, Object?>.from(value) : <String, Object?>{};

  static List<Object?> _list(Object? value) =>
      value is List ? value : const <Object?>[];

  static String? _string(Object? value) => value is String ? value : null;

  static int _int(Object? value) =>
      value is int ? value : int.tryParse('$value') ?? 0;
}

String _rid(Uri server) => base64Encode(utf8.encode(server.authority));
