import 'dart:convert';
import 'dart:math';

import 'package:http/http.dart' as http;

import 'api.dart';
import 'auth_flow.dart';

/// Performs server-directed secondary authentication for an existing ticket.
class ATrustSecondaryAuthenticator {
  ATrustSecondaryAuthenticator({
    required this.server,
    required this.csrfToken,
    http.Client? client,
  }) : _client = client ?? http.Client();

  final Uri server;
  final String csrfToken;
  final http.Client _client;

  Future<ATrustAuthStep> authCheck() async {
    final response = await _client.get(
      _uri('/passport/v1/auth/authCheck'),
      headers: _headers(),
    );
    return _step(response, 'authCheck');
  }

  Future<void> sendSms(ATrustAuthStep step) async {
    if (step.service != ATrustAuthService.sms) {
      throw ArgumentError.value(step, 'step', 'must be an SMS step');
    }
    final query = <String, String>{'action': 'sendsms'};
    if (step.smsMode == ATrustSmsMode.withAuthId) {
      query.addAll(<String, String>{
        'isPrevEffect': '0',
        'taskId': '',
        'authId': step.authId!,
      });
    }
    final response = await _client.get(
      _uri('/passport/v1/auth/sms', query),
      headers: _headers(),
    );
    _ensureSuccess(response, 'send SMS');
  }

  Future<ATrustAuthStep> verifyCustomSms({
    required String code,
    bool skipSecondaryAuth = false,
  }) async {
    if (code.trim().isEmpty) {
      throw ArgumentError.value(code, 'code', 'must not be empty');
    }
    final headers = _headers()
      ..['content-type'] = 'application/json;charset=utf-8';
    final sendResponse = await _client.post(
      _uri('/passport/v1/auth/customSms', const <String, String>{
        'action': 'sendcustomsms',
      }),
      headers: headers,
      body: jsonEncode(<String, String>{'isPrevEffect': '0', 'taskId': ''}),
    );
    _ensureSuccess(sendResponse, 'send custom SMS');
    final response = await _client.post(
      _uri('/passport/v1/auth/customSms', const <String, String>{
        'action': 'checkcustomcode',
      }),
      headers: headers,
      body: jsonEncode(<String, Object?>{
        'isPrevEffect': false,
        'customCode': code,
        'skipSecondaryAuth': skipSecondaryAuth ? '1' : '0',
        'taskId': '',
      }),
    );
    return _step(response, 'verify custom SMS');
  }

  Future<ATrustAuthStep> verifySms({
    required ATrustAuthStep step,
    required String code,
    bool skipSecondaryAuth = false,
  }) async {
    if (step.service != ATrustAuthService.sms) {
      throw ArgumentError.value(step, 'step', 'must be an SMS step');
    }
    if (code.trim().isEmpty) {
      throw ArgumentError.value(code, 'code', 'must not be empty');
    }
    final query = <String, String>{'action': 'checkcode'};
    final headers = _headers();
    late http.Response response;
    if (step.smsMode == ATrustSmsMode.withAuthId) {
      headers['content-type'] = 'application/json;charset=utf-8';
      response = await _client.post(
        _uri('/passport/v1/auth/sms', query),
        headers: headers,
        body: jsonEncode(<String, Object?>{
          'isPrevEffect': false,
          'code': code,
          'skipSecondaryAuth': skipSecondaryAuth ? '1' : '0',
          'taskId': '',
          'authId': step.authId,
        }),
      );
    } else {
      headers['content-type'] = 'application/x-www-form-urlencoded';
      response = await _client.post(
        _uri('/passport/v1/auth/sms', query),
        headers: headers,
        body: <String, String>{
          'code': code,
          'skipSecondaryAuth': skipSecondaryAuth ? '1' : '0',
        },
      );
    }
    return _step(response, 'verify SMS');
  }

  Future<ATrustAuthStep> verifyTotp({
    required String code,
    String? username,
    bool skipSecondaryAuth = false,
  }) =>
      _verifyToken(
        path: '/passport/v1/auth/token',
        operation: 'verify TOTP',
        payload: <String, Object?>{
          'action': 'auth',
          'totpToken': code,
          'isPrevEffect': false,
          'skipSecondaryAuth': skipSecondaryAuth ? 1 : 0,
          if (username != null && username.isNotEmpty) 'username': username,
        },
      );

  Future<ATrustAuthStep> verifyRadius({
    required String code,
    required ATrustAuthStep step,
    String? username,
    bool skipSecondaryAuth = false,
  }) {
    final path = step.service == ATrustAuthService.challenge
        ? '/passport/v1/auth/challenge'
        : '/passport/v1/auth/token';
    return _verifyToken(
      path: path,
      operation: 'verify ${step.service.name}',
      payload: <String, Object?>{
        'radiusToken': code,
        'skipSecondaryAuth': skipSecondaryAuth ? 1 : 0,
        if (username != null && username.isNotEmpty) 'username': username,
      },
    );
  }

  Future<ATrustAuthStep> accessCheck() async {
    final response = await _client.get(
      _uri('/passport/v1/auth/accessCheck'),
      headers: _headers(),
    );
    return _step(response, 'access check');
  }

  Future<ATrustAuthStep> continueEnhanced(ATrustAuthStep step) async {
    const supported = <ATrustAuthService>{
      ATrustAuthService.preEnhancedAuth,
      ATrustAuthService.enhancedConfirm,
      ATrustAuthService.enhancedDone,
    };
    if (!supported.contains(step.service) || step.rawService == null) {
      throw ArgumentError.value(step, 'step', 'must be an enhanced auth step');
    }
    final response = await _client.get(
      _uri('/passport/v1/${step.rawService}', <String, String>{
        if (step.authId != null && step.authId!.isNotEmpty)
          'authId': step.authId!,
      }),
      headers: _headers(),
    );
    return _step(response, step.rawService!);
  }

  Future<ATrustAuthStep> bindCurrentDevice({
    required ATrustAuthStep step,
    required String deviceId,
  }) async {
    if (step.service != ATrustAuthService.bindAuthDevice) {
      throw ArgumentError.value(step, 'step', 'must be a device binding step');
    }
    if (deviceId.trim().isEmpty) {
      throw ArgumentError.value(deviceId, 'deviceId', 'must not be empty');
    }
    final headers = _headers()
      ..['content-type'] = 'application/json;charset=utf-8';
    final response = await _client.post(
      _uri('/passport/v1/auth/bindAuthDevice', <String, String>{
        if (step.authId != null && step.authId!.isNotEmpty)
          'authId': step.authId!,
      }),
      headers: headers,
      body: jsonEncode(<String, String>{
        'deviceId': deviceId,
        if (step.authId != null && step.authId!.isNotEmpty)
          'authId': step.authId!,
      }),
    );
    return _step(response, 'bind current device');
  }

  Future<ATrustAuthStep> _verifyToken({
    required String path,
    required String operation,
    required Map<String, Object?> payload,
  }) async {
    final code = payload['totpToken'] ?? payload['radiusToken'];
    if (code is! String || code.trim().isEmpty) {
      throw ArgumentError.value(code, 'code', 'must not be empty');
    }
    final headers = _headers()
      ..['content-type'] = 'application/json;charset=utf-8';
    final response = await _client.post(
      _uri(path),
      headers: headers,
      body: jsonEncode(payload),
    );
    return _step(response, operation);
  }

  Uri _uri(String path, [Map<String, String> query = const {}]) =>
      server.replace(
        path: path,
        queryParameters: <String, String>{
          'clientType': 'SDPClient',
          'platform': 'Flutter',
          'lang': 'en-US',
          ...query,
        },
        fragment: '',
      );

  Map<String, String> _headers() => <String, String>{
        'accept': 'application/json',
        'user-agent': 'flutter_sangfor',
        'x-csrf-token': csrfToken,
        'x-sdp-rid': _rid(server),
        'x-sdp-traceid': _traceId(),
      };

  ATrustAuthStep _step(http.Response response, String operation) {
    _ensureSuccess(response, operation);
    final decoded = jsonDecode(response.body);
    if (decoded is! Map) {
      throw ATrustApiException('$operation response is not a JSON object');
    }
    final root = Map<String, Object?>.from(decoded);
    final code = root['code'];
    if (code != 0 && code != '0') {
      throw ATrustApiException(
        root['message'] as String? ?? '$operation failed',
      );
    }
    final data = root['data'];
    return ATrustAuthStep.fromMap(
      data is Map ? Map<String, Object?>.from(data) : const {},
    );
  }

  void _ensureSuccess(http.Response response, String operation) {
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw ATrustApiException(
        '$operation endpoint returned HTTP ${response.statusCode}',
        statusCode: response.statusCode,
      );
    }
  }
}

String _traceId() => List<String>.generate(
      8,
      (_) => Random.secure().nextInt(16).toRadixString(16),
    ).join();

String _rid(Uri server) => base64Encode(utf8.encode(server.authority));
