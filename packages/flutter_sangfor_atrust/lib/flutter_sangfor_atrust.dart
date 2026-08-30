/// aTrust protocol core: login, L3 tunnel, TCP tunnel, and anti-MITM
/// verification for the `flutter_sangfor` package family.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter_sangfor/flutter_sangfor.dart';

export 'src/api.dart';
export 'src/password_auth.dart';
export 'src/auth_flow.dart';
export 'src/resource.dart';
export 'src/secondary_auth.dart';
export 'src/session.dart';
export 'src/login_session.dart';
export 'src/snapshot.dart';
export 'src/tunnel.dart';
export 'src/anti_mitm.dart';
export 'src/packet.dart';
export 'src/conntrack.dart';
export 'src/tcp_tunnel.dart';
export 'src/node_selection.dart';
export 'src/l3_connection.dart';
export 'src/atrust_tunnel.dart';
export 'src/tcp_tunnel_client.dart';

import 'src/atrust_tunnel.dart';
import 'src/login_session.dart';
import 'src/l3_connection.dart';
import 'src/node_selection.dart';
import 'src/tcp_tunnel_client.dart';
import 'src/snapshot.dart';

/// Authentication methods specific to aTrust deployments.
enum ATrustAuthMethod { password, cas, sms }

extension on ATrustAuthMethod {
  SangforAuthType get coreType => switch (this) {
        ATrustAuthMethod.password => SangforAuthType.password,
        ATrustAuthMethod.cas => SangforAuthType.cas,
        ATrustAuthMethod.sms => SangforAuthType.sms,
      };
}

/// aTrust connector using the platform implementation supplied by the root package.
class ATrustConnector implements SangforConnector {
  ATrustConnector({
    SangforConnector? delegate,
    ATrustLoginSession? loginSession,
    this.authMethod = ATrustAuthMethod.password,
    this.smsCodeProvider,
    this.totpCodeProvider,
    this.radiusCodeProvider,
    this.customSmsCodeProvider,
    this.socketFactory,
    this.nodeDialer,
    this.tlsPolicy,
    this.startTunnel = true,
  })  : _delegate = delegate ??
            SangforPlatformConnector(product: SangforProduct.atrust),
        _loginSession = loginSession;

  final SangforConnector _delegate;
  final ATrustLoginSession? _loginSession;
  final ATrustSmsCodeProvider? smsCodeProvider;
  final ATrustCodeProvider? totpCodeProvider;
  final ATrustCodeProvider? radiusCodeProvider;
  final ATrustCodeProvider? customSmsCodeProvider;
  final ATrustAuthMethod authMethod;
  final ATrustTunnelSocketFactory? socketFactory;
  final ATrustNodeDialer? nodeDialer;
  final ATrustTunnelTlsPolicy? tlsPolicy;
  final bool startTunnel;

  ATrustTunnel? _tunnel;

  /// The active L3 tunnel, available after a successful tunneled connect.
  ATrustTunnel? get tunnel => _tunnel;

  /// Dials one TCP connection through the aTrust TCP tunnel. The gateway
  /// resolves [host], so domains pass through directly.
  Future<SangforTcpStream> dialTcp(
    String host,
    int port, {
    String? resolvedIp,
    bool zeroRtt = false,
  }) async {
    final tunnel = _tunnel;
    if (tunnel == null) {
      throw const SangforException(
        SangforErrorCode.invalidOptions,
        'dialTcp requires a tunnel; connect with startTunnel enabled first',
      );
    }
    final connection = await tunnel.dialTcp(
      host,
      port,
      resolvedIp: resolvedIp,
      zeroRtt: zeroRtt,
    );
    return ATrustTcpTunnelStream(connection);
  }

  @override
  SangforProduct get product => SangforProduct.atrust;

  @override
  Future<SangforSession> connect(SangforConnectOptions options) async {
    final loginSession = _loginSession;
    if (loginSession == null) {
      return _delegate.connect(
        SangforConnectOptions(
          server: options.server,
          username: options.username,
          password: options.password,
          loginDomain: options.loginDomain,
          deviceId: options.deviceId,
          authType: authMethod.coreType,
          timeout: options.timeout,
          cancellationToken: options.cancellationToken,
        ),
      );
    }
    if (options.dryRun) {
      return const SangforSession(
        state: SangforConnectionState.authenticated,
        dryRun: true,
      );
    }
    if (options.loginDomain == null || options.loginDomain!.isEmpty) {
      throw const SangforException(
        SangforErrorCode.invalidOptions,
        'aTrust loginDomain is required for the Dart protocol connector',
      );
    }
    if (authMethod != ATrustAuthMethod.password) {
      throw const SangforException(
        SangforErrorCode.unsupported,
        'The Dart aTrust connector currently supports password authentication',
      );
    }
    if (options.deviceId == null || options.deviceId!.isEmpty) {
      throw const SangforException(
        SangforErrorCode.invalidOptions,
        'aTrust deviceId is required for the Dart protocol connector',
      );
    }
    final operation = loginSession.login(
      ATrustLoginOptions(
        server: options.server,
        username: options.username,
        password: options.password,
        loginDomain: options.loginDomain!,
        deviceId: options.deviceId!,
        smsCodeProvider: smsCodeProvider,
        totpCodeProvider: totpCodeProvider,
        radiusCodeProvider: radiusCodeProvider,
        customSmsCodeProvider: customSmsCodeProvider,
      ),
    );
    ATrustAuthenticatedSession authenticated;
    try {
      authenticated =
          await (options.cancellationToken?.race(operation) ?? operation)
              .timeout(options.timeout);
    } on TimeoutException catch (error, stackTrace) {
      throw SangforException(
        SangforErrorCode.timeout,
        'aTrust authentication timed out',
        cause: error,
        stackTrace: stackTrace,
      );
    }
    if (!startTunnel) {
      return SangforSession(
        state: SangforConnectionState.authenticated,
        dnsServers: authenticated.resource.dnsServers,
      );
    }
    final tunnel = ATrustTunnel(
      resource: authenticated.resource,
      info: ATrustL3ClientInfo(
        sid: authenticated.sid,
        deviceId: options.deviceId!,
        connectionId: buildATrustConnectionId(options.deviceId!),
        username: authenticated.username,
      ),
      signKey: generateATrustSignKey(),
      socketFactory: socketFactory ?? atrustDefaultSocketFactory(tlsPolicy),
      nodeDialer: nodeDialer,
    );
    String? virtualAddress;
    try {
      virtualAddress = await tunnel.start();
    } on Object catch (error, stackTrace) {
      await tunnel.close();
      throw SangforException(
        SangforErrorCode.tunnelFailed,
        'aTrust tunnel establishment failed: $error',
        cause: error,
        stackTrace: stackTrace,
      );
    }
    _tunnel = tunnel;
    return SangforSession(
      state: SangforConnectionState.connected,
      virtualAddress: virtualAddress,
      dnsServers: authenticated.resource.dnsServers,
    );
  }

  @override
  Future<void> disconnect() async {
    final tunnel = _tunnel;
    _tunnel = null;
    if (tunnel != null) {
      await tunnel.close();
    }
    if (_loginSession == null) {
      return _delegate.disconnect();
    }
  }

  /// Builds the connection id used by the L3 tunnel: uppercase MD5 of the
  /// device id followed by the current unix microsecond timestamp.
  static String buildATrustConnectionId(String deviceId) {
    final digest =
        crypto.md5.convert(utf8.encode(deviceId)).toString().toUpperCase();
    return '$digest-${DateTime.now().microsecondsSinceEpoch}';
  }

  /// Generates the client-side tunnel signing key (32 random bytes as 64
  /// uppercase hex characters), mirroring the upstream client.
  static Uint8List generateATrustSignKey() {
    final random = Random.secure();
    final bytes = Uint8List(32);
    for (var index = 0; index < bytes.length; index++) {
      bytes[index] = random.nextInt(256);
    }
    return bytes;
  }

  Future<SangforSession> resume(ATrustSessionSnapshot snapshot) async {
    final loginSession = _loginSession;
    if (loginSession == null) {
      throw const SangforException(
        SangforErrorCode.unsupported,
        'Session resume requires the Dart aTrust protocol connector',
      );
    }
    await loginSession.resume(snapshot);
    return const SangforSession(state: SangforConnectionState.authenticated);
  }

  @override
  Future<SangforConnectionState> getState() => _delegate.getState();

  @override
  Future<SangforPlatformCapabilities> getCapabilities() =>
      _delegate.getCapabilities();
}
