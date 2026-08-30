import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_sangfor/flutter_sangfor.dart' show SangforTcpStream;

import 'dns.dart';
import 'easy_connect_tunnel.dart';
import 'tcp_packet.dart';

/// Synthesizes TCP and UDP flows over the raw-IP Easy Connect tunnel, so
/// connection-oriented users (for example the SOCKS5 frontend) can dial
/// through the VPN without a system TUN device.
class EasyConnectTcpProxy {
  EasyConnectTcpProxy({
    required EasyConnectPacketTransport tunnel,
    required List<int> sourceIp,
    this.mss = 1300,
    List<String> dnsServers = const <String>[],
    this.dnsTimeout = const Duration(seconds: 4),
    this.initialRto = const Duration(seconds: 1),
  })  : assert(mss > 0 && mss <= 1460),
        _tunnel = tunnel,
        _sourceIp = sourceIp,
        _dnsServerIps = dnsServers
            .map(parseIPv4Address)
            .whereType<List<int>>()
            .toList(growable: false);

  static const int _portRangeStart = 32768;
  static const int _portRangeEnd = 60999;

  final EasyConnectPacketTransport _tunnel;
  final int mss;
  final Duration dnsTimeout;
  final Duration initialRto;
  final List<List<int>> _dnsServerIps;

  final Map<String, EasyConnectTcpConnection> _connections =
      <String, EasyConnectTcpConnection>{};
  final Map<String, EasyConnectUdpFlow> _udpFlows = <String, EasyConnectUdpFlow>{};
  final Random _random = Random();
  StreamSubscription<Uint8List>? _subscription;
  final List<int> _sourceIp;
  int _nextPort = _portRangeStart;
  bool _closed = false;

  List<int> get sourceIp => _sourceIp;

  /// Starts demultiplexing tunnel traffic.
  void start() {
    if (_closed) throw StateError('proxy is closed');
    _subscription = _tunnel.incoming.listen(
      _handlePacket,
      onError: (Object _) {},
      onDone: () => close(),
    );
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _subscription?.cancel();
    final connections = List<EasyConnectTcpConnection>.of(_connections.values);
    _connections.clear();
    final flows = List<EasyConnectUdpFlow>.of(_udpFlows.values);
    _udpFlows.clear();
    for (final connection in connections) {
      await connection._teardown();
    }
    for (final flow in flows) {
      await flow.close();
    }
  }

  /// Dials one TCP connection through the tunnel. [host] may be a domain,
  /// which is resolved via the VPN DNS servers.
  Future<EasyConnectTcpConnection> dialTcp(
    String host,
    int port, {
    Duration timeout = const Duration(seconds: 12),
  }) async {
    if (_closed) throw StateError('proxy is closed');
    if (port <= 0 || port > 65535) {
      throw RangeError.value(port, 'port');
    }
    final remoteIp = await resolveHost(host);
    final localPort = _allocatePort();
    final connection = EasyConnectTcpConnection._(
      this,
      remoteIp,
      port,
      localPort,
    );
    _connections[connection._key] = connection;
    connection._sendSyn();
    try {
      await connection._ready.future.timeout(timeout);
    } on Object {
      await connection.close();
      rethrow;
    }
    return connection;
  }

  /// Opens one UDP flow to [remoteIp]:[remotePort].
  EasyConnectUdpFlow dialUdp(
    List<int> remoteIp,
    int remotePort, {
    int? localPort,
  }) {
    if (_closed) throw StateError('proxy is closed');
    final port = localPort ?? _allocatePort();
    final flow = EasyConnectUdpFlow._(this, remoteIp, remotePort, port);
    _udpFlows[flow._key] = flow;
    return flow;
  }

  /// Resolves [host] to an IPv4 address. IP literals pass through; domains
  /// use the VPN DNS servers when configured and the system resolver
  /// otherwise.
  Future<List<int>> resolveHost(String host) async {
    final literal = parseIPv4Address(host);
    if (literal != null) return literal;
    if (_dnsServerIps.isEmpty) {
      final addresses = await InternetAddress.lookup(host);
      for (final address in addresses) {
        final parsed = parseIPv4Address(address.address);
        if (parsed != null) return parsed;
      }
      throw EasyConnectDnsException('no IPv4 address for $host');
    }
    final resolver = EasyConnectTunnelDnsResolver(this, _dnsServerIps);
    return resolver.resolve(host, timeout: dnsTimeout);
  }

  int _allocatePort() {
    while (true) {
      final port = _nextPort;
      _nextPort++;
      if (_nextPort > _portRangeEnd) _nextPort = _portRangeStart;
      final used = _connections.values.any(
            (connection) => connection.localPort == port,
          ) ||
          _udpFlows.values.any((flow) => flow.localPort == port);
      if (!used) return port;
    }
  }

  int _nextDnsId() => _random.nextInt(0x10000);

  int _nextIss() => _random.nextInt(1 << 32);

  void _handlePacket(Uint8List packet) {
    if (_closed) return;
    final ip = parseIpv4Packet(packet);
    if (ip == null) return;
    if (ip.protocol == ipProtocolTcp) {
      final segment = parseTcpSegment(ip.srcIp, ip.dstIp, ip.payload);
      if (segment == null || !segment.validChecksum) return;
      final connection =
          _connections['${ip.srcIp.join('.')}:${segment.srcPort}:${segment.dstPort}'];
      connection?._handleSegment(segment);
    } else if (ip.protocol == ipProtocolUdp) {
      final datagram = parseUdpDatagram(ip.payload);
      if (datagram == null) return;
      final flow = _udpFlows[
          '${ip.srcIp.join('.')}:${datagram.srcPort}:${datagram.dstPort}'];
      flow?._deliver(datagram.payload);
    }
  }

  void _send(Uint8List packet) {
    if (_closed) return;
    unawaited(
      _tunnel.sendPacket(packet).catchError((Object _) {
        return false;
      }),
    );
  }

  void _removeConnection(EasyConnectTcpConnection connection) {
    _connections.remove(connection._key);
  }

  void _removeFlow(EasyConnectUdpFlow flow) {
    _udpFlows.remove(flow._key);
  }
}

class EasyConnectDnsException implements Exception {
  const EasyConnectDnsException(this.message);

  final String message;

  @override
  String toString() => 'EasyConnectDnsException: $message';
}

enum _TcpState { synSent, established, finSent, closed }

class _OutSegment {
  const _OutSegment({
    required this.seq,
    required this.flags,
    required this.bytes,
    this.options = const <int>[],
  });

  final int seq;
  final int flags;
  final Uint8List bytes;
  final List<int> options;
}

/// One TCP connection synthesized over the L3 tunnel (client role).
class EasyConnectTcpConnection extends SangforTcpStream {
  EasyConnectTcpConnection._(
    this._proxy,
    this.remoteIp,
    this.remotePort,
    this.localPort,
  )   : _key = '${remoteIp.join('.')}:$remotePort:$localPort',
        _iss = _proxy._nextIss();

  static const int _advertisedWindow = 0xffff;
  static const Duration _maxRto = Duration(seconds: 8);
  static const int _sendBufferLimit = 1 << 20;
  static const int _maxRetransmits = 10;
  static const Duration _lingerTimeout = Duration(seconds: 10);

  final EasyConnectTcpProxy _proxy;
  final List<int> remoteIp;
  final int remotePort;
  final int localPort;
  final String _key;
  final int _iss;

  final StreamController<Uint8List> _incoming = StreamController<Uint8List>();
  final Completer<void> _ready = Completer<void>();
  final List<int> _pending = <int>[];
  final List<_OutSegment> _unacked = <_OutSegment>[];
  final Map<int, Uint8List> _outOfOrder = <int, Uint8List>{};
  final List<Completer<void>> _drainWaiters = <Completer<void>>[];

  _TcpState _state = _TcpState.synSent;
  int _sndUna = 0;
  int _sndNxt = 0;
  int _rcvNxt = 0;
  int _peerWindow = _advertisedWindow;
  int _peerMss = 0;
  late Duration _rto;
  int _retransmits = 0;
  Timer? _timer;
  Timer? _lingerTimer;
  bool _finRequested = false;
  bool _finReceived = false;
  bool _tornDown = false;

  @override
  Stream<Uint8List> get incoming => _incoming.stream;

  @override
  bool get isClosed => _tornDown;

  int get _mss {
    final effective = _peerMss == 0 ? _proxy.mss : _peerMss;
    return effective < _proxy.mss ? effective : _proxy.mss;
  }

  Duration get _initialRto => _proxy.initialRto;

  int _inFlight() => (_sndNxt - _sndUna) & 0xffffffff;

  void _sendSyn() {
    _rto = _initialRto;
    _sndUna = _iss;
    _sndNxt = (_iss + 1) & 0xffffffff;
    _sendSegment(
      seq: _iss,
      flags: tcpFlagSyn,
      payload: Uint8List(0),
      options: mssOption(_proxy.mss),
    );
    _unacked.add(
      _OutSegment(
        seq: _iss,
        flags: tcpFlagSyn,
        bytes: Uint8List(0),
        options: mssOption(_proxy.mss),
      ),
    );
    _restartTimer();
  }

  @override
  Future<void> send(Uint8List data) async {
    if (_tornDown || _state == _TcpState.closed) {
      throw StateError('connection is closed');
    }
    _pending.addAll(data);
    _flush();
    while (!_tornDown &&
        _pending.length + _inFlight() > _sendBufferLimit) {
      final waiter = Completer<void>();
      _drainWaiters.add(waiter);
      await waiter.future;
    }
  }

  @override
  Future<void> closeWrite() async {
    if (_tornDown || _finRequested) return;
    _finRequested = true;
    _flush();
    _notifyDrained();
  }

  @override
  Future<void> close() async {
    if (_tornDown) return;
    if (_state == _TcpState.synSent) {
      _sendSegment(
        seq: _sndNxt,
        flags: tcpFlagRst | tcpFlagAck,
        payload: Uint8List(0),
      );
      await _teardown();
      return;
    }
    _finRequested = true;
    _flush();
    if (!_incoming.isClosed) {
      unawaited(_incoming.close());
    }
    _lingerTimer ??= Timer(_lingerTimeout, () => unawaited(_teardown()));
  }

  void _handleSegment(TcpSegment segment) {
    if (_tornDown) return;
    if (segment.rst) {
      _teardownError(
        EasyConnectTcpResetException('connection reset by $remoteIp'),
      );
      return;
    }
    if (segment.syn && !segment.hasAck) {
      // Simultaneous open is not supported.
      _sendSegment(
        seq: _sndNxt,
        flags: tcpFlagRst | tcpFlagAck,
        payload: Uint8List(0),
      );
      return;
    }
    if (_state == _TcpState.synSent) {
      if (!segment.syn || !segment.hasAck || segment.ack != _sndNxt) {
        return;
      }
      _rcvNxt = (segment.seq + 1) & 0xffffffff;
      _sndUna = segment.ack;
      _peerWindow = segment.window;
      _peerMss = parseMssOption(segment.options) ?? 0;
      _state = _TcpState.established;
      _retransmits = 0;
      _rto = _initialRto;
      _unacked.clear();
      _restartTimer();
      _sendSegment(
        seq: _sndNxt,
        flags: tcpFlagAck,
        payload: Uint8List(0),
      );
      if (!_ready.isCompleted) _ready.complete();
      _flush();
      return;
    }
    if (segment.hasAck) {
      _peerWindow = segment.window;
      final ack = segment.ack;
      final progress = (ack - _sndUna) & 0xffffffff;
      if (progress > 0 && progress <= _inFlight()) {
        _sndUna = ack;
        _dropAcked(ack);
        _retransmits = 0;
        _rto = _initialRto;
        _notifyDrained();
        _flush();
      }
    }
    if (segment.payload.isNotEmpty) {
      if (segment.seq == _rcvNxt) {
        _deliver(segment.payload);
        _rcvNxt = (_rcvNxt + segment.payload.length) & 0xffffffff;
        Uint8List? buffered = _outOfOrder.remove(_rcvNxt);
        while (buffered != null) {
          _deliver(buffered);
          _rcvNxt = (_rcvNxt + buffered.length) & 0xffffffff;
          buffered = _outOfOrder.remove(_rcvNxt);
        }
      } else if (((segment.seq - _rcvNxt) & 0xffffffff) > 0) {
        _outOfOrder.putIfAbsent(segment.seq, () => segment.payload);
      }
      _sendSegment(
        seq: _sndNxt,
        flags: tcpFlagAck,
        payload: Uint8List(0),
      );
    }
    if (segment.fin && !_finReceived) {
      _finReceived = true;
      final finSeq = (segment.seq + segment.payload.length) & 0xffffffff;
      _rcvNxt = (finSeq + 1) & 0xffffffff;
      _sendSegment(
        seq: _sndNxt,
        flags: tcpFlagAck,
        payload: Uint8List(0),
      );
      if (!_incoming.isClosed) {
        unawaited(_incoming.close());
      }
    }
    if (_state == _TcpState.finSent &&
        _sndUna == _sndNxt &&
        (_finReceived || _incoming.isClosed)) {
      _lingerTimer?.cancel();
      unawaited(_teardown());
    }
  }

  /// Sends queued data, respecting the peer window, then the FIN if
  /// requested and all data has been acknowledged.
  void _flush() {
    if (_tornDown || _state == _TcpState.closed) return;
    if (_state == _TcpState.established) {
      while (true) {
        final usable = _peerWindow - _inFlight();
        if (usable <= 0 || _pending.isEmpty) break;
        final take = _pending.length < _mss
            ? _pending.length
            : _mss;
        final chunkSize = take < usable ? take : usable;
        if (chunkSize <= 0) break;
        final chunk = Uint8List.fromList(_pending.sublist(0, chunkSize));
        _pending.removeRange(0, chunkSize);
        _sendSegment(
          seq: _sndNxt,
          flags: tcpFlagAck | tcpFlagPsh,
          payload: chunk,
        );
        _unacked.add(
          _OutSegment(seq: _sndNxt, flags: tcpFlagAck, bytes: chunk),
        );
        _sndNxt = (_sndNxt + chunk.length) & 0xffffffff;
      }
      if (_finRequested && _pending.isEmpty && _sndUna == _sndNxt) {
        _state = _TcpState.finSent;
        _sendSegment(
          seq: _sndNxt,
          flags: tcpFlagAck | tcpFlagFin,
          payload: Uint8List(0),
        );
        _unacked.add(
          _OutSegment(seq: _sndNxt, flags: tcpFlagFin, bytes: Uint8List(0)),
        );
        _sndNxt = (_sndNxt + 1) & 0xffffffff;
      }
    }
    _restartTimer();
  }

  void _dropAcked(int upTo) {
    _unacked.removeWhere(
      (segment) => ((upTo - segment.seq) & 0xffffffff) >= segment.bytes.length,
    );
  }

  void _restartTimer() {
    if (_tornDown) return;
    final windowBlocked = _unacked.isEmpty &&
        _pending.isNotEmpty &&
        _state == _TcpState.established &&
        _peerWindow - _inFlight() <= 0;
    if (_unacked.isEmpty && !windowBlocked) {
      _timer?.cancel();
      _timer = null;
      return;
    }
    _timer ??= Timer(_rto, _onRetransmit);
  }

  void _onRetransmit() {
    if (_tornDown) return;
    if (_unacked.isEmpty) {
      // Zero-window probe: retry the flush while data is pending so a
      // reopened window is picked up.
      if (_pending.isNotEmpty) {
        _timer = Timer(_rto, _onRetransmit);
        _flush();
      }
      return;
    }
    _retransmits++;
    if (_retransmits > _maxRetransmits) {
      _teardownError(
        StateError('TCP retransmit limit exceeded for $_key'),
      );
      return;
    }
    for (final segment in List<_OutSegment>.of(_unacked)) {
      _sendSegment(
        seq: segment.seq,
        flags: segment.flags,
        payload: segment.bytes,
        options: segment.options,
      );
    }
    _rto = _rto * 2;
    if (_rto > _maxRto) _rto = _maxRto;
    _timer = Timer(_rto, _onRetransmit);
  }

  void _sendSegment({
    required int seq,
    required int flags,
    required Uint8List payload,
    List<int> options = const <int>[],
  }) {
    final segment = buildTcpSegment(
      srcIp: _proxy.sourceIp,
      dstIp: remoteIp,
      srcPort: localPort,
      dstPort: remotePort,
      seq: seq,
      ack: flags & tcpFlagSyn != 0 && flags & tcpFlagAck == 0 ? 0 : _rcvNxt,
      flags: flags,
      window: _advertisedWindow,
      payload: payload,
      options: options,
    );
    final packet = buildIpPacket(
      srcIp: _proxy.sourceIp,
      dstIp: remoteIp,
      protocol: ipProtocolTcp,
      payload: segment,
    );
    _proxy._send(packet);
  }

  void _deliver(Uint8List payload) {
    if (!_incoming.isClosed && payload.isNotEmpty) {
      _incoming.add(payload);
    }
  }

  void _notifyDrained() {
    if (_drainWaiters.isEmpty) return;
    if (_pending.length + _inFlight() <= _sendBufferLimit) {
      final waiters = List<Completer<void>>.of(_drainWaiters);
      _drainWaiters.clear();
      for (final waiter in waiters) {
        if (!waiter.isCompleted) waiter.complete();
      }
    }
  }

  Future<void> _teardown() async {
    if (_tornDown) return;
    _tornDown = true;
    _timer?.cancel();
    _timer = null;
    _lingerTimer?.cancel();
    _lingerTimer = null;
    if (!_ready.isCompleted) {
      _ready.completeError(
        StateError('connection closed before handshake completed'),
      );
    }
    if (!_incoming.isClosed) {
      unawaited(_incoming.close());
    }
    for (final waiter in _drainWaiters) {
      if (!waiter.isCompleted) waiter.complete();
    }
    _drainWaiters.clear();
    _proxy._removeConnection(this);
  }

  void _teardownError(Object error) {
    if (!_incoming.isClosed) {
      _incoming.addError(error);
    }
    unawaited(_teardown());
  }
}

/// One UDP flow over the L3 tunnel.
class EasyConnectUdpFlow {
  EasyConnectUdpFlow._(
    this._proxy,
    this.remoteIp,
    this.remotePort,
    this.localPort,
  ) : _key = '${remoteIp.join('.')}:$remotePort:$localPort';

  final EasyConnectTcpProxy _proxy;
  final List<int> remoteIp;
  final int remotePort;
  final int localPort;
  final String _key;

  // Single-subscription (buffered) so bytes arriving before the consumer
  // attaches are not dropped.
  final StreamController<Uint8List> _incoming = StreamController<Uint8List>();
  bool _closed = false;

  Stream<Uint8List> get incoming => _incoming.stream;

  bool get isClosed => _closed;

  Future<void> send(Uint8List payload) async {
    if (_closed) throw StateError('UDP flow is closed');
    final datagram = buildUdpDatagram(
      srcIp: _proxy.sourceIp,
      dstIp: remoteIp,
      srcPort: localPort,
      dstPort: remotePort,
      payload: payload,
    );
    final packet = buildIpPacket(
      srcIp: _proxy.sourceIp,
      dstIp: remoteIp,
      protocol: ipProtocolUdp,
      payload: datagram,
    );
    await _proxy._tunnel.sendPacket(packet);
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    _proxy._removeFlow(this);
    if (!_incoming.isClosed) {
      unawaited(_incoming.close());
    }
  }

  void _deliver(Uint8List payload) {
    if (!_closed && !_incoming.isClosed && payload.isNotEmpty) {
      _incoming.add(payload);
    }
  }
}

/// Resolves hostnames by sending A queries to the VPN DNS servers over the
/// tunnel's UDP data plane.
class EasyConnectTunnelDnsResolver {
  EasyConnectTunnelDnsResolver(this._proxy, this._servers);

  final EasyConnectTcpProxy _proxy;
  final List<List<int>> _servers;

  Future<List<int>> resolve(
    String host, {
    Duration timeout = const Duration(seconds: 4),
  }) async {
    Object? lastError;
    for (final server in _servers) {
      for (var attempt = 0; attempt < 2; attempt++) {
        final flow = _proxy.dialUdp(server, 53);
        StreamSubscription<Uint8List>? subscription;
        try {
          final replyCompleter = Completer<Uint8List>();
          subscription = flow.incoming.listen(
            (payload) {
              if (!replyCompleter.isCompleted) replyCompleter.complete(payload);
            },
            onError: (Object error) {
              if (!replyCompleter.isCompleted) {
                replyCompleter.completeError(error);
              }
            },
          );
          final id = _proxy._nextDnsId();
          final query = buildDnsQuery(id, host);
          await flow.send(query);
          final reply = await replyCompleter.future.timeout(timeout);
          final address = parseDnsAResponse(reply, id);
          if (address != null) return address;
          lastError = EasyConnectDnsException('no A record for $host');
        } on Object catch (error) {
          lastError = error;
        } finally {
          await subscription?.cancel();
          unawaited(flow.close());
        }
      }
    }
    throw EasyConnectDnsException(
      'failed to resolve $host: $lastError',
    );
  }
}

class EasyConnectTcpResetException implements Exception {
  const EasyConnectTcpResetException(this.message);

  final String message;

  @override
  String toString() => 'EasyConnectTcpResetException: $message';
}

