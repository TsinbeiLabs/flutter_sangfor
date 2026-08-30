import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

import 'api.dart';

class ATrustCookie {
  const ATrustCookie({
    required this.name,
    required this.value,
    required this.domain,
    this.path = '/',
    this.secure = false,
    this.hostOnly = true,
    this.expires,
    this.maxAge,
  });

  final String name;
  final String value;
  final String domain;
  final String path;
  final bool secure;
  final bool hostOnly;
  final DateTime? expires;
  final int? maxAge;

  Map<String, Object?> toMap() => <String, Object?>{
        'name': name,
        'value': value,
        'domain': domain,
        'path': path,
        'secure': secure,
        'hostOnly': hostOnly,
        if (expires != null) 'expires': expires!.toUtc().toIso8601String(),
        if (maxAge != null) 'maxAge': maxAge,
      };

  factory ATrustCookie.fromMap(Map<String, Object?> map) => ATrustCookie(
        name: map['name'] as String? ?? '',
        value: map['value'] as String? ?? '',
        domain: map['domain'] as String? ?? '',
        path: map['path'] as String? ?? '/',
        secure: map['secure'] as bool? ?? false,
        hostOnly: map['hostOnly'] as bool? ?? true,
        expires: DateTime.tryParse(map['expires'] as String? ?? ''),
        maxAge: map['maxAge'] is int ? map['maxAge'] as int : null,
      );
}

/// Minimal cookie-aware HTTP client shared by all aTrust protocol stages.
class ATrustSessionClient extends http.BaseClient {
  ATrustSessionClient({http.Client? inner}) : _inner = inner ?? http.Client();

  factory ATrustSessionClient.withCookies(
    Iterable<ATrustCookie> cookies, {
    http.Client? inner,
  }) {
    final client = ATrustSessionClient(inner: inner);
    client.restoreCookies(cookies);
    return client;
  }

  final http.Client _inner;
  final Map<String, ATrustCookie> _cookies = <String, ATrustCookie>{};

  List<ATrustCookie> get cookies => List.unmodifiable(_cookies.values);

  String? get sid => _cookies['sid']?.value;

  void restoreCookies(Iterable<ATrustCookie> cookies) {
    for (final cookie in cookies) {
      if (cookie.name.isEmpty || cookie.domain.isEmpty) continue;
      if (cookie.expires != null &&
          !cookie.expires!.toUtc().isAfter(DateTime.now().toUtc())) {
        continue;
      }
      _cookies[cookie.name] = cookie;
    }
  }

  @override
  void close() => _inner.close();

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final applicable = _cookies.values.where((cookie) {
      final domainMatches = request.url.host == cookie.domain ||
          (!cookie.hostOnly && request.url.host.endsWith('.${cookie.domain}'));
      final expired = cookie.expires != null &&
          !cookie.expires!.toUtc().isAfter(DateTime.now().toUtc());
      return domainMatches &&
          !expired &&
          request.url.path.startsWith(cookie.path) &&
          (!cookie.secure || request.url.scheme == 'https');
    });
    if (applicable.isNotEmpty) {
      request.headers['cookie'] = applicable
          .map((cookie) => '${cookie.name}=${cookie.value}')
          .join('; ');
    }
    final response = await _inner.send(request);
    _storeCookies(request.url, response.headers);
    return response;
  }

  void _storeCookies(Uri uri, Map<String, String> headers) {
    final header = headers['set-cookie'];
    if (header == null || header.isEmpty) return;
    for (final value in _splitSetCookie(header)) {
      final segments = value.split(';');
      final separator = segments.first.indexOf('=');
      if (separator <= 0) continue;
      final name = segments.first.substring(0, separator).trim();
      final cookieValue = segments.first.substring(separator + 1).trim();
      var domain = uri.host;
      var path = '/';
      var secure = false;
      var hostOnly = true;
      DateTime? expires;
      int? maxAge;
      final receivedAt = DateTime.now().toUtc();
      for (final attribute in segments.skip(1)) {
        final part = attribute.trim();
        final lower = part.toLowerCase();
        if (lower == 'secure') secure = true;
        if (lower.startsWith('domain=')) {
          domain = part.substring(7).trim().replaceFirst(RegExp(r'^\.'), '');
          hostOnly = false;
        }
        if (lower.startsWith('path=')) path = part.substring(5).trim();
        if (lower.startsWith('expires=')) {
          try {
            expires = HttpDate.parse(part.substring(8).trim()).toUtc();
          } on FormatException {
            expires = null;
          }
        }
        if (lower.startsWith('max-age=')) {
          maxAge = int.tryParse(part.substring(8).trim());
        }
      }
      final validDomain = uri.host == domain || uri.host.endsWith('.$domain');
      if (!validDomain) continue;
      final maxAgeExpired = maxAge != null && maxAge <= 0;
      final expiresAt =
          maxAge == null ? expires : receivedAt.add(Duration(seconds: maxAge));
      if (cookieValue.isEmpty ||
          maxAgeExpired ||
          (expiresAt != null && !expiresAt.isAfter(DateTime.now().toUtc()))) {
        _cookies.remove(name);
      } else {
        _cookies[name] = ATrustCookie(
          name: name,
          value: cookieValue,
          domain: domain,
          path: path,
          secure: secure,
          hostOnly: hostOnly,
          expires: expiresAt,
          maxAge: maxAge,
        );
      }
    }
  }

  List<String> _splitSetCookie(String value) => value.split(
        RegExp(r',(?=\s*[^;,=\s]+=[^;,]*)'),
      );
}

class ATrustOnlineInfo {
  const ATrustOnlineInfo({required this.username});

  final String username;
}

/// Post-login session operations that require the authenticated cookie jar.
class ATrustSessionApi {
  ATrustSessionApi({
    required this.server,
    required this.csrfToken,
    required http.Client client,
  }) : _client = client;

  final Uri server;
  final String csrfToken;
  final http.Client _client;

  Future<void> reportEnvironment({
    required String ticket,
    required String deviceId,
  }) async {
    final response = await _client.post(
      _uri('/controller/v1/public/reportEnv'),
      headers: _headers(),
      body: jsonEncode(<String, Object?>{
        'ticket': ticket,
        'deviceId': deviceId,
        'env': <String, Object?>{
          'endpoint': <String, Object?>{
            'device_id': deviceId,
            'device': <String, String>{'type': 'browser'},
          },
        },
      }),
    );
    _data(response, 'report environment');
  }

  Future<ATrustOnlineInfo> fetchOnlineInfo() async {
    final response = await _client.get(
      _uri('/passport/v1/user/onlineInfo'),
      headers: _headers(includeContentType: false),
    );
    final data = _data(response, 'online info');
    final username = data['username'];
    if (username is! String || username.isEmpty) {
      throw const ATrustApiException('online info username is missing');
    }
    return ATrustOnlineInfo(username: username);
  }

  Uri _uri(String path) => server.replace(
        path: path,
        queryParameters: const <String, String>{
          'clientType': 'SDPClient',
          'platform': 'Flutter',
          'lang': 'en-US',
        },
        fragment: '',
      );

  Map<String, String> _headers({bool includeContentType = true}) =>
      <String, String>{
        'accept': 'application/json',
        'user-agent': 'flutter_sangfor',
        'x-csrf-token': csrfToken,
        'x-sdp-rid': base64Encode(utf8.encode(server.authority)),
        if (includeContentType)
          'content-type': 'application/json;charset=utf-8',
      };

  Map<String, Object?> _data(http.Response response, String operation) {
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
    if (root['code'] != 0 && root['code'] != '0') {
      throw ATrustApiException(
        root['message'] as String? ?? '$operation failed',
      );
    }
    final data = root['data'];
    return data is Map ? Map<String, Object?>.from(data) : <String, Object?>{};
  }
}
