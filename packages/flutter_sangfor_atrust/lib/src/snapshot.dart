import 'session.dart';

/// Serializable authenticated state. Passwords and challenge codes are excluded.
class ATrustSessionSnapshot {
  const ATrustSessionSnapshot({
    required this.server,
    required this.username,
    required this.deviceId,
    required this.csrfToken,
    required this.cookies,
  });

  factory ATrustSessionSnapshot.fromMap(Map<String, Object?> map) =>
      ATrustSessionSnapshot(
        server: Uri.parse(map['server'] as String? ?? ''),
        username: map['username'] as String? ?? '',
        deviceId: map['deviceId'] as String? ?? '',
        csrfToken: map['csrfToken'] as String? ?? '',
        cookies: (map['cookies'] as List<Object?>? ?? const <Object?>[])
            .whereType<Map>()
            .map((value) => ATrustCookie.fromMap(
                  Map<String, Object?>.from(value),
                ))
            .toList(growable: false),
      );

  final Uri server;
  final String username;
  final String deviceId;
  final String csrfToken;
  final List<ATrustCookie> cookies;

  String? get sid => cookies
      .where((cookie) => cookie.name == 'sid')
      .map((cookie) => cookie.value)
      .firstOrNull;

  Map<String, Object?> toMap() => <String, Object?>{
        'server': server.toString(),
        'username': username,
        'deviceId': deviceId,
        'csrfToken': csrfToken,
        'cookies': cookies.map((cookie) => cookie.toMap()).toList(),
      };
}

extension<T> on Iterable<T> {
  T? get firstOrNull {
    final iterator = this.iterator;
    return iterator.moveNext() ? iterator.current : null;
  }
}
