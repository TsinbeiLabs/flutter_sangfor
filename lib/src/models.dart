/// Authentication mechanisms exposed by aTrust deployments.
enum SangforAuthType {
  password('auth/psw'),
  cas('auth/cas'),
  sms('auth/smsCheckCode');

  const SangforAuthType(this.value);

  final String value;
}

/// Lifecycle state of the connection.
enum SangforConnectionState {
  disconnected,
  connecting,
  connected,
  disconnecting,
  error;

  static SangforConnectionState fromValue(String? value) =>
      SangforConnectionState.values.firstWhere(
        (state) => state.name == value,
        orElse: () => SangforConnectionState.disconnected,
      );
}

/// Result returned after a successful connection setup.
class SangforSession {
  const SangforSession({
    required this.state,
    this.virtualAddress,
    this.dnsServers = const <String>[],
  });

  factory SangforSession.fromMap(Map<String, Object?> map) => SangforSession(
        state: SangforConnectionState.fromValue(map['state'] as String?),
        virtualAddress: map['virtualAddress'] as String?,
        dnsServers: (map['dnsServers'] as List<Object?>? ?? const <Object?>[])
            .whereType<String>()
            .toList(growable: false),
      );

  final SangforConnectionState state;
  final String? virtualAddress;
  final List<String> dnsServers;
}
