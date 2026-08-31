import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'anti_mitm.dart';
import 'l3_connection.dart';
import 'node_selection.dart';
import 'packet.dart';
import 'resource.dart';
import 'tcp_tunnel.dart';
import 'tcp_tunnel_client.dart';
import 'tunnel.dart';

/// Builds a TLS tunnel channel to a node address.
typedef ATrustTunnelSocketFactory = Future<ATrustTunnelChannel> Function(
  String host,
  int port,
);

/// TLS trust policy for tunnel connections. aTrust tunnel nodes commonly
/// present self-signed certificates, so certificates rejected by the
/// platform trust store are accepted unless anti-MITM identity digests are
/// available for pinning.
class ATrustTunnelTlsPolicy {
  const ATrustTunnelTlsPolicy({this.securityContext, this.antiMitm});

  final SecurityContext? securityContext;
  final ATrustAntiMitmData? antiMitm;
}

/// Creates the default socket factory used by production tunnels.
ATrustTunnelSocketFactory atrustDefaultSocketFactory([
  ATrustTunnelTlsPolicy? policy,
]) {
  final tlsPolicy = policy ?? const ATrustTunnelTlsPolicy();
  return (String host, int port) async {
    final antiMitm = tlsPolicy.antiMitm;
    final socket = await SecureSocket.connect(
      host,
      port,
      context: tlsPolicy.securityContext,
      timeout: const Duration(seconds: 10),
      onBadCertificate: (certificate) =>
          antiMitm?.acceptsCertificate(certificate.der) ?? true,
    );
    return ATrustSecureSocketChannel.fromSocket(socket);
  };
}

/// Manages the L3 tunnels of an authenticated aTrust session: best-node
/// wiring, the client virtual IP, per-node-group connections with reconnect,
/// a merged incoming packet stream, and TCP-tunnel dialing.
class ATrustTunnel {
  ATrustTunnel({
    required this.resource,
    required ATrustL3ClientInfo info,
    required Uint8List signKey,
    ATrustTunnelSocketFactory? socketFactory,
    ATrustTunnelTlsPolicy? tlsPolicy,
    ATrustNodeDialer? nodeDialer,
    Map<String, String>? bestNodes,
    this.reconnectInterval = const Duration(seconds: 5),
    this.onVip,
    this.onError,
  })  : _info = info,
        _signKey = Uint8List.fromList(signKey),
        _socketFactory = socketFactory ?? atrustDefaultSocketFactory(tlsPolicy),
        _nodeDialer = nodeDialer ?? atrustTcpProbeDialer,
        _bestNodes =
            bestNodes != null ? Map<String, String>.of(bestNodes) : null;

  final ATrustResource resource;
  final ATrustL3ClientInfo _info;
  final Uint8List _signKey;
  final ATrustTunnelSocketFactory _socketFactory;
  final ATrustNodeDialer _nodeDialer;
  final Duration reconnectInterval;
  final void Function(List<String> addresses)? onVip;
  final void Function(Object error)? onError;

  final StreamController<Uint8List> _incoming =
      StreamController<Uint8List>.broadcast();
  final Map<String, ATrustL3TunnelConnection> _connections =
      <String, ATrustL3TunnelConnection>{};
  final Map<String, Future<ATrustL3TunnelConnection>> _connecting =
      <String, Future<ATrustL3TunnelConnection>>{};
  final Map<String, Timer> _reconnectTimers = <String, Timer>{};
  Map<String, String>? _bestNodes;
  String? _virtualAddress;
  bool _closed = false;

  Stream<Uint8List> get incoming => _incoming.stream;
  String? get virtualAddress => _virtualAddress;
  bool get isClosed => _closed;
  Map<String, String> get bestNodes => _bestNodes == null
      ? const <String, String>{}
      : Map<String, String>.of(_bestNodes!);

  /// Probes nodes, acquires the client virtual IP, and opens the tunnel to
  /// the major node group.
  Future<String?> start() async {
    if (_closed) throw StateError('tunnel is closed');
    _bestNodes ??= await ATrustNodeSelector().select(
      resource.nodeGroups,
      dialer: _nodeDialer,
    );
    final address = await _queryVirtualAddress();
    _virtualAddress = address;
    await _getConnection(resource.majorNodeGroup);
    return address;
  }

  /// Routes one IP packet to the node group that owns the destination.
  /// Returns false when no L3 route matches the packet.
  Future<bool> sendPacket(Uint8List packet) async {
    if (_closed) return false;
    final meta = buildPacketMeta(packet);
    if (meta == null) return false;
    final route = matchL3Route(
      resource.routes,
      meta.destinationAddress,
      protocolName(meta.protocol),
      meta.destinationPort,
    );
    if (route == null) return false;
    final connection = await _getConnection(route.nodeGroupId);
    await connection.sendPacket(
      packet,
      appId: route.appId,
      nodeGroupId: route.nodeGroupId,
    );
    return true;
  }

  /// Dials a single TCP connection through the SOCKS5-like tunnel.
  ///
  /// [includeL3Preferred] also accepts resources that prefer the L3 tunnel;
  /// callers without an L3 data plane (in-app HTTP proxying) need this to
  /// reach hosts the server marks as L3-preferred.
  Future<ATrustTcpTunnelConn> dialTcp(
    String host,
    int port, {
    String? resolvedIp,
    bool zeroRtt = false,
    bool includeL3Preferred = false,
  }) async {
    final route = matchTcpRoute(
      resource.routes,
      host,
      port,
      includeL3Preferred: includeL3Preferred,
    );
    if (route == null) {
      throw StateException('no TCP tunnel resource for $host:$port');
    }
    final address = _nodeAddressFor(route.nodeGroupId) ??
        _nodeAddressFor(resource.majorNodeGroup);
    if (address == null) {
      throw StateException('no available node for group ${route.nodeGroupId}');
    }
    final (nodeHost, nodePort) = _splitAddress(address);
    final channel = await _socketFactory(nodeHost, nodePort);
    var destAddr = '$host:$port';
    String? destIp;
    if (resolvedIp != null && !route.addrPretend) {
      destIp = resolvedIp;
    }
    final request = ATrustTcpTunnelAuthRequest(
      sid: _info.sid,
      appId: route.appId,
      url: 'tcp://$destAddr',
      deviceId: _info.deviceId,
      connectionId: _info.connectionId,
      procHash: _info.processHash,
      userName: _info.username,
      lang: _info.lang,
      destAddr: destAddr,
      destIp: destIp,
      process: ATrustTcpTunnelProcess(
        name: _info.processName,
        path: _info.processPath,
        platform: atrustPlatformName(),
      ),
    );
    return ATrustTcpTunnelClient.connect(
      channel: channel,
      request: request,
      signKey: _signKey,
      host: host,
      port: port,
      zeroRtt: zeroRtt,
    );
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    for (final timer in _reconnectTimers.values) {
      timer.cancel();
    }
    _reconnectTimers.clear();
    final connections = List<ATrustL3TunnelConnection>.of(_connections.values);
    _connections.clear();
    _connecting.clear();
    for (final connection in connections) {
      await connection.close();
    }
    if (!_incoming.isClosed) {
      await _incoming.close();
    }
  }

  Future<ATrustL3TunnelConnection> _getConnection(String nodeGroupId) {
    if (_closed) throw StateError('tunnel is closed');
    final existing = _connections[nodeGroupId];
    if (existing != null && !existing.isClosed) {
      return Future<ATrustL3TunnelConnection>.value(existing);
    }
    final pending = _connecting[nodeGroupId];
    if (pending != null) return pending;
    final future = _connect(nodeGroupId);
    _connecting[nodeGroupId] = future;
    return future;
  }

  Future<ATrustL3TunnelConnection> _connect(String nodeGroupId) async {
    try {
      final address = _nodeAddressFor(nodeGroupId) ??
          _nodeAddressFor(resource.majorNodeGroup);
      if (address == null) {
        throw StateException(
          'no available node for group $nodeGroupId',
        );
      }
      final (host, port) = _splitAddress(address);
      final channel = await _socketFactory(host, port);
      final connection = ATrustL3TunnelConnection(
        channel: channel,
        info: _info,
        signKey: _signKey,
        onVip: onVip,
        onError: (error) {
          onError?.call(error);
          _scheduleReconnect(nodeGroupId);
        },
      );
      connection.incoming.listen((packet) {
        if (!_incoming.isClosed) {
          _incoming.add(packet);
        }
      });
      try {
        await connection.start();
      } on Object {
        await connection.close();
        rethrow;
      }
      _connections[nodeGroupId] = connection;
      return connection;
    } on Object {
      _scheduleReconnect(nodeGroupId);
      rethrow;
    } finally {
      _connecting.remove(nodeGroupId);
    }
  }

  void _scheduleReconnect(String nodeGroupId) {
    if (_closed) return;
    _connections.remove(nodeGroupId);
    _reconnectTimers[nodeGroupId]?.cancel();
    _reconnectTimers[nodeGroupId] = Timer(reconnectInterval, () {
      _reconnectTimers.remove(nodeGroupId);
      if (_closed) return;
      unawaited(() async {
        try {
          await _getConnection(nodeGroupId);
        } on Object catch (error) {
          onError?.call(error);
        }
      }());
    });
  }

  String? _nodeAddressFor(String nodeGroupId) {
    final nodes = _bestNodes;
    if (nodes == null) return null;
    return nodes[nodeGroupId] ?? nodes[resource.majorNodeGroup];
  }

  Future<String?> _queryVirtualAddress() async {
    var address = _nodeAddressFor(resource.majorNodeGroup);
    if (address == null && _bestNodes != null && _bestNodes!.isNotEmpty) {
      address = _bestNodes!.values.first;
    }
    if (address == null) {
      throw StateException('no reachable node for the IP request');
    }
    final (host, port) = _splitAddress(address);
    final channel = await _socketFactory(host, port);
    try {
      await channel.send(ATrustL3Protocol.authTunnelRequest(_info.sid));
      final parser = ATrustL3HandshakeParser();
      await for (final chunk in channel.incoming) {
        final parsed = parser.add(chunk);
        if (parsed != null) {
          final addresses = parsed.$1.virtualIP?.addresses ?? const <String>[];
          for (final candidate in addresses) {
            if (candidate.contains('.') && !candidate.contains(':')) {
              return candidate;
            }
          }
          return addresses.isEmpty ? null : addresses.first;
        }
      }
      throw StateException('node closed before the IP response');
    } finally {
      await channel.close();
    }
  }

  (String, int) _splitAddress(String address) {
    if (address.startsWith('[')) {
      final close = address.indexOf(']');
      final host = address.substring(1, close);
      final rest = address.substring(close + 1);
      final port = rest.isEmpty ? 441 : int.parse(rest.substring(1));
      return (host, port);
    }
    final colon = address.lastIndexOf(':');
    if (colon < 0) return (address, 441);
    return (
      address.substring(0, colon),
      int.parse(address.substring(colon + 1)),
    );
  }
}
