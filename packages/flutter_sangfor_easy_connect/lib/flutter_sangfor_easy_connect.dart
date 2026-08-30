import 'dart:typed_data';

import 'package:flutter_sangfor/flutter_sangfor.dart';

export 'src/easy_connect.dart';
export 'src/data_plane.dart';
export 'src/dns.dart';
export 'src/easy_connect_tunnel.dart';
export 'src/tcp_packet.dart';
export 'src/tcp_proxy.dart';
export 'src/tls/tls_client.dart';
export 'src/tls/tls_prf.dart';
export 'src/tls/tls_record.dart';
export 'src/tls/tls_x509.dart';

import 'src/data_plane.dart';
import 'src/dns.dart';
import 'src/easy_connect.dart';
import 'src/easy_connect_tunnel.dart';
import 'src/tcp_proxy.dart';
import 'src/tls/tls_client.dart';

/// Easy Connect connector. Protocol-specific transport is added here without
/// coupling the root package to Easy Connect implementation details.
class EasyConnectConnector implements SangforConnector {
  EasyConnectConnector({
    SangforConnector? delegate,
    EasyConnectLoginSession? loginSession,
    this.smsCodeProvider,
    this.totpCodeProvider,
    this.certificateValidator,
    this.allowUnverifiedCertificates = false,
    this.startTunnel = true,
    this.connectionFactory,
  })  : _delegate = delegate ??
            SangforPlatformConnector(product: SangforProduct.easyConnect),
        _loginSession = loginSession;

  final SangforConnector _delegate;
  final EasyConnectLoginSession? _loginSession;
  final EasyConnectCodeProvider? smsCodeProvider;
  final EasyConnectCodeProvider? totpCodeProvider;
  final bool Function(Uint8List certificateDer)? certificateValidator;
  final bool allowUnverifiedCertificates;
  final bool startTunnel;
  final EasyConnectTlsConnectionFactory? connectionFactory;

  EasyConnectTunnel? _tunnel;
  EasyConnectTcpProxy? _tcpProxy;

  /// The active L3 tunnel, available after a successful tunneled connect.
  EasyConnectTunnel? get tunnel => _tunnel;

  /// The active userspace TCP/UDP proxy over the tunnel.
  EasyConnectTcpProxy? get tcpProxy => _tcpProxy;

  /// Dials one TCP connection through the VPN. [host] may be a domain,
  /// which is resolved via the VPN DNS servers.
  Future<SangforTcpStream> dialTcp(
    String host,
    int port, {
    Duration timeout = const Duration(seconds: 12),
  }) async {
    final proxy = _tcpProxy;
    if (proxy == null) {
      throw const SangforException(
        SangforErrorCode.invalidOptions,
        'dialTcp requires a tunnel; connect with startTunnel enabled first',
      );
    }
    return proxy.dialTcp(host, port, timeout: timeout);
  }

  @override
  SangforProduct get product => SangforProduct.easyConnect;

  @override
  Future<SangforSession> connect(SangforConnectOptions options) async {
    final loginSession = _loginSession;
    if (loginSession == null) return _delegate.connect(options);
    if (options.dryRun) {
      return const SangforSession(
        state: SangforConnectionState.authenticated,
        dryRun: true,
      );
    }
    final authenticated = await loginSession.login(
      EasyConnectLoginOptions(
        server: options.server,
        username: options.username,
        password: options.password,
        smsCodeProvider: smsCodeProvider,
        totpCodeProvider: totpCodeProvider,
      ),
    );
    EasyConnectConfig? config;
    try {
      config = await loginSession.fetchConfig(options.server);
    } on EasyConnectApiException {
      // Servers without /por/conf.csp support still provide a session.
    }
    final dnsServers = config?.dnsServers ?? const <String>[];
    if (!startTunnel) {
      return SangforSession(
        state: SangforConnectionState.authenticated,
        dnsServers: dnsServers,
      );
    }
    if (certificateValidator == null &&
        !allowUnverifiedCertificates &&
        connectionFactory == null) {
      throw const SangforException(
        SangforErrorCode.invalidOptions,
        'EasyConnect data channels require a certificate validator or an '
        'explicit allowUnverifiedCertificates opt-in',
      );
    }
    final factory = connectionFactory ??
        (TlsClientHelloSpec hello) => EasyConnectTlsClient(
              certificateValidator: certificateValidator,
              allowUnverifiedCertificates: allowUnverifiedCertificates,
            ).connect(
              options.server.host,
              options.server.port == 0 ? 443 : options.server.port,
              hello: hello,
            );
    final tunnel = EasyConnectTunnel(
      server: options.server,
      twfId: authenticated.twfId,
      connectionFactory: factory,
    );
    String? virtualAddress;
    try {
      virtualAddress = await tunnel.start();
    } on Object catch (error, stackTrace) {
      await tunnel.close();
      throw SangforException(
        SangforErrorCode.tunnelFailed,
        'EasyConnect tunnel establishment failed: $error',
        cause: error,
        stackTrace: stackTrace,
      );
    }
    _tunnel = tunnel;
    final clientIp = parseIPv4Address(virtualAddress ?? '');
    if (clientIp != null) {
      final tunnelDnsServers = <String>{
        ...?config?.dnsServers,
        ...?config?.backupDnsServers,
      }.toList(growable: false);
      final proxy = EasyConnectTcpProxy(
        tunnel: tunnel,
        sourceIp: clientIp,
        dnsServers: tunnelDnsServers,
      );
      proxy.start();
      _tcpProxy = proxy;
    }
    return SangforSession(
      state: SangforConnectionState.connected,
      virtualAddress: virtualAddress,
      dnsServers: dnsServers,
    );
  }

  @override
  Future<void> disconnect() async {
    final proxy = _tcpProxy;
    _tcpProxy = null;
    await proxy?.close();
    final tunnel = _tunnel;
    _tunnel = null;
    if (tunnel != null) {
      await tunnel.close();
    }
    if (_loginSession == null) {
      return _delegate.disconnect();
    }
  }

  @override
  Future<SangforConnectionState> getState() => _delegate.getState();

  @override
  Future<SangforPlatformCapabilities> getCapabilities() =>
      _delegate.getCapabilities();
}
