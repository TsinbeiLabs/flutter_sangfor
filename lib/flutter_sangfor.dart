import 'flutter_sangfor_platform_interface.dart';
import 'src/models.dart';

export 'src/models.dart';

/// Controls an aTrust-compatible VPN session.
class FlutterSangfor {
  const FlutterSangfor();

  /// Connects to an aTrust-compatible server.
  Future<SangforSession> connect({
    required Uri server,
    required String username,
    required String password,
    String? loginDomain,
    SangforAuthType authType = SangforAuthType.password,
  }) =>
      FlutterSangforPlatform.instance.connect(
        server: server,
        username: username,
        password: password,
        loginDomain: loginDomain,
        authType: authType,
      );

  /// Disconnects the active session.
  Future<void> disconnect() => FlutterSangforPlatform.instance.disconnect();

  /// Returns the current session state.
  Future<SangforConnectionState> getState() =>
      FlutterSangforPlatform.instance.getState();
}
