import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'packet.dart';
import 'tcp_tunnel.dart';
import 'tunnel.dart';

/// Incremental decoder that turns socket chunks into L3 frames.
class ATrustL3FrameStreamDecoder {
  final List<int> _buffer = <int>[];

  List<ATrustL3Frame> add(List<int> chunk) {
    _buffer.addAll(chunk);
    final frames = <ATrustL3Frame>[];
    while (true) {
      final frame = _decodeOne();
      if (frame == null) break;
      frames.add(frame);
    }
    return frames;
  }

  void reset() => _buffer.clear();

  ATrustL3Frame? _decodeOne() {
    if (_buffer.length < 2) return null;
    if (_buffer[0] != ATrustL3Protocol.version) {
      throw FormatException(
        'unexpected L3 tunnel version 0x${_buffer[0].toRadixString(16)}',
      );
    }
    final command = _buffer[1];
    final hasStatus = command == ATrustL3Command.authResponse.value ||
        command == ATrustL3Command.secondVipResponse.value;
    final headerLength = hasStatus ? 5 : 4;
    if (_buffer.length < headerLength) return null;
    final lengthOffset = hasStatus ? 3 : 2;
    final payloadLength = ByteData.sublistView(
      Uint8List.fromList(_buffer),
      lengthOffset,
      lengthOffset + 2,
    ).getUint16(0, Endian.big);
    final total = headerLength + payloadLength;
    if (_buffer.length < total) return null;
    final bytes = Uint8List.fromList(_buffer.sublist(0, total));
    _buffer.removeRange(0, total);
    return ATrustL3Protocol.decodeFrame(bytes);
  }
}

/// Parses the initial tunnel-auth handshake byte sequence incrementally.
class ATrustL3HandshakeParser {
  final List<int> _buffer = <int>[];
  int _phase = 0;
  int _authLength = 0;
  int _vipLength = 0;

  /// Feeds a chunk. Returns the parsed result together with the unconsumed
  /// leftover bytes, or null when more data is required.
  (ATrustL3TunnelAuthResult, Uint8List)? add(List<int> chunk) {
    _buffer.addAll(chunk);
    while (true) {
      switch (_phase) {
        case 0:
          if (_buffer.length < 2) return null;
          if (_buffer[0] != ATrustL3Protocol.version || _buffer[1] != 0xD0) {
            throw FormatException(
              'unexpected L3 tunnel auth method response: '
              '0x${_buffer[0].toRadixString(16)} 0x${_buffer[1].toRadixString(16)}',
            );
          }
          _buffer.removeRange(0, 2);
          _phase = 1;
        case 1:
          if (_buffer.length < 4) return null;
          if (_buffer[0] != 0x53) {
            throw FormatException(
              'unexpected L3 tunnel auth response version: '
              '0x${_buffer[0].toRadixString(16)}',
            );
          }
          final status = _buffer[1];
          _authLength = ByteData.sublistView(
            Uint8List.fromList(_buffer.sublist(0, 4)),
            2,
            4,
          ).getUint16(0, Endian.big);
          _buffer.removeRange(0, 4);
          if (status != 0) {
            throw FormatException('L3 tunnel auth status $status');
          }
          _phase = 2;
        case 2:
          if (_buffer.length < _authLength) return null;
          final authPayload = Uint8List.fromList(
            _buffer.sublist(0, _authLength),
          );
          _buffer.removeRange(0, _authLength);
          String? deviceId;
          if (_authLength > 0) {
            final decoded = jsonDecode(utf8.decode(authPayload));
            if (decoded is Map) {
              final map = Map<String, Object?>.from(decoded);
              final code = map['code'] is int
                  ? map['code'] as int
                  : int.tryParse('${map['code'] ?? 0}') ?? 0;
              if (code != 0) {
                throw FormatException(
                  'L3 tunnel auth failed: code $code: ${map['message'] ?? ""}',
                );
              }
              final data = map['data'] is Map
                  ? Map<String, Object?>.from(map['data'] as Map)
                  : <String, Object?>{};
              deviceId = data['deviceId']?.toString();
            }
          }
          _deviceId = deviceId;
          _phase = 3;
        case 3:
          if (_buffer.length < 4) return null;
          final header = Uint8List.fromList(_buffer.sublist(0, 4));
          _vipLength = ATrustL3Protocol.parseInitialVIPHeader(header);
          _buffer.removeRange(0, 4);
          _phase = 4;
        case 4:
          if (_buffer.length < _vipLength) return null;
          final vipData = Uint8List.fromList(
            _buffer.sublist(0, _vipLength),
          );
          _buffer.removeRange(0, _vipLength);
          final vip = ATrustL3Protocol.parseVirtualIPData(vipData);
          final result = ATrustL3TunnelAuthResult(
            authStatus: 0,
            deviceId: _deviceId,
            virtualIP: vip,
            consumed: 0,
          );
          return (result, Uint8List.fromList(_buffer));
      }
    }
  }

  String? _deviceId;
}

/// Client identity used by the L3 tunnel protocol.
class ATrustL3ClientInfo {
  const ATrustL3ClientInfo({
    required this.sid,
    required this.deviceId,
    required this.connectionId,
    required this.username,
    this.processName = 'flutter_sangfor',
    this.processPath = '/usr/bin/flutter_sangfor',
    this.lang = 'en-US',
  });

  final String sid;
  final String deviceId;
  final String connectionId;
  final String username;
  final String processName;
  final String processPath;
  final String lang;

  Map<String, Object?> defaultEnv() {
    final fingerprint = ATrustTcpTunnelProcess(
      name: processName,
      path: processPath,
      platform: atrustPlatformName(),
    ).fingerprint;
    return <String, Object?>{
      'application': <String, Object?>{
        'runtime': <String, Object?>{
          'process': <String, Object?>{
            'name': processName,
            'digital_signature': 'TrustAppClosed',
            'platform': atrustPlatformName(),
            'fingerprint': fingerprint,
            'description': 'TrustAppClosed',
            'path': processPath,
            'version': 'TrustAppClosed',
            'security_env': 'normal',
          },
          'process_trusted': 'TRUSTED',
        },
      },
    };
  }

  String get processHash => ATrustTcpTunnelProcess(
        name: processName,
        path: processPath,
        platform: atrustPlatformName(),
      ).fingerprint;
}

String atrustPlatformName() => switch (Platform.operatingSystem) {
      'macos' => 'macOS',
      'windows' => 'Windows',
      'android' => 'Android',
      'ios' => 'iOS',
      'linux' => 'Linux',
      _ => 'Unknown',
    };

/// Drives one aTrust L3 tunnel TLS connection end to end: the initial
/// authTunnel handshake, the read loop, per-flow authentication with deadlines
/// and retries, heartbeats with miss detection, and VIP updates.
class ATrustL3TunnelConnection {
  ATrustL3TunnelConnection({
    required ATrustTunnelChannel channel,
    required ATrustL3ClientInfo info,
    required Uint8List signKey,
    ATrustL3FlowTracker? flowTracker,
    this.heartbeatInterval = const Duration(seconds: 5),
    this.heartbeatMissLimit = 3,
    this.authTimeout = const Duration(seconds: 5),
    this.authScanInterval = const Duration(milliseconds: 250),
    this.authRetryWait = const Duration(seconds: 10),
    this.authMaxAttempts = 3,
    this.authBatchSize = 64,
    this.connectTimeout = const Duration(seconds: 10),
    DateTime Function()? clock,
    this.onVip,
    this.onError,
  })  : _channel = channel,
        _info = info,
        _signKey = Uint8List.fromList(signKey),
        tracker = flowTracker ?? ATrustL3FlowTracker(),
        _clock = clock ?? DateTime.now;

  final ATrustTunnelChannel _channel;
  final ATrustL3ClientInfo _info;
  final Uint8List _signKey;
  final ATrustL3FlowTracker tracker;
  final Duration heartbeatInterval;
  final int heartbeatMissLimit;
  final Duration authTimeout;
  final Duration authScanInterval;
  final Duration authRetryWait;
  final int authMaxAttempts;
  final int authBatchSize;
  final Duration connectTimeout;
  final DateTime Function() _clock;
  final void Function(List<String> addresses)? onVip;
  final void Function(Object error)? onError;

  late final ATrustL3FlowTransport _transport = ATrustL3FlowTransport(
    sid: _info.sid,
    deviceId: _info.deviceId,
    connectionId: _info.connectionId,
    signKey: _signKey,
    lang: _info.lang,
    env: _info.defaultEnv(),
    tracker: tracker,
  );

  final StreamController<Uint8List> _incoming =
      StreamController<Uint8List>.broadcast();
  final ATrustL3FrameStreamDecoder _frameDecoder = ATrustL3FrameStreamDecoder();
  final ATrustL3HandshakeParser _handshakeParser = ATrustL3HandshakeParser();
  final List<int> _dataStream = <int>[];

  StreamSubscription<List<int>>? _subscription;
  Timer? _authTimer;
  Timer? _heartbeatTimer;
  Future<void> _writeChain = Future<void>.value();
  ATrustL3TunnelAuthResult? _handshakeResult;
  bool _closed = false;
  bool _hasWrite = false;
  int _heartbeatMisses = 0;

  bool get isClosed => _closed;
  ATrustL3TunnelAuthResult? get handshakeResult => _handshakeResult;
  Stream<Uint8List> get incoming => _incoming.stream;

  /// Performs the authTunnel handshake and starts the background loops.
  Future<void> start() async {
    if (_closed) throw StateError('connection is closed');
    final completer = Completer<void>();
    var handshakeDone = false;
    _subscription = _channel.incoming.listen(
      (chunk) {
        if (!handshakeDone) {
          (ATrustL3TunnelAuthResult, Uint8List)? parsed;
          try {
            parsed = _handshakeParser.add(chunk);
          } on Object catch (error, stackTrace) {
            _fail(error, stackTrace);
            if (!completer.isCompleted) {
              completer.completeError(error, stackTrace);
            }
            return;
          }
          if (parsed != null) {
            handshakeDone = true;
            _handshakeResult = parsed.$1;
            final addresses = parsed.$1.virtualIP?.addresses ??
                const <String>[];
            if (addresses.isNotEmpty) {
              onVip?.call(addresses);
            }
            if (parsed.$2.isNotEmpty) {
              _handleChannelData(parsed.$2);
            }
            if (!completer.isCompleted) completer.complete();
          }
        } else {
          _handleChannelData(chunk);
        }
      },
      onError: (Object error, StackTrace stackTrace) {
        _fail(error, stackTrace);
        if (!completer.isCompleted) completer.completeError(error);
      },
      onDone: () {
        _fail(StateError('channel closed'), StackTrace.current);
        if (!completer.isCompleted) {
          completer.completeError(StateError('channel closed'));
        }
      },
    );
    try {
      await _write(ATrustL3Protocol.authTunnelRequest(_info.sid));
      await completer.future.timeout(connectTimeout);
    } on Object {
      await close();
      rethrow;
    }
    _authTimer = Timer.periodic(authScanInterval, (_) => _onAuthTick());
    _heartbeatTimer =
        Timer.periodic(heartbeatInterval, (_) => _onHeartbeatTick());
  }

  /// Sends one IP packet through the tunnel, authenticating its flow first.
  Future<void> sendPacket(
    Uint8List packet, {
    required String appId,
    required String nodeGroupId,
  }) async {
    if (_closed) return;
    final meta = buildPacketMeta(packet);
    if (meta == null) return;
    final key = ATrustL3FlowKey(
      protocol: meta.protocol,
      sourceAddress: meta.sourceAddress,
      sourcePort: meta.sourcePort,
      destinationAddress: meta.destinationAddress,
      destinationPort: meta.destinationPort,
    );
    final flow = tracker.getOrCreate(
      key,
      appId: appId,
      nodeGroupId: nodeGroupId,
    );
    tracker.observePacket(key, packet, false);
    if (flow.state == ATrustL3FlowState.authenticated && flow.token != null) {
      await _write(ATrustL3Protocol.dataRequest(flow.token!, packet));
      return;
    }
    if (flow.state != ATrustL3FlowState.pending) return;
    if (!tracker.cachePacket(flow, packet)) return;
    _dispatchPendingAuth();
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    _authTimer?.cancel();
    _heartbeatTimer?.cancel();
    await _subscription?.cancel();
    _subscription = null;
    if (!_incoming.isClosed) {
      await _incoming.close();
    }
    await _channel.close();
  }

  void _handleChannelData(List<int> chunk) {
    List<ATrustL3Frame> frames;
    try {
      frames = _frameDecoder.add(chunk);
    } on Object catch (error, stackTrace) {
      _fail(error, stackTrace);
      return;
    }
    for (final frame in frames) {
      _handleFrame(frame);
    }
  }

  void _handleFrame(ATrustL3Frame frame) {
    try {
      switch (frame.command) {
        case ATrustL3Command.dataResponse:
          _dataStream.addAll(frame.payload);
          final (packets, remaining) = splitIncomingIPPackets(
            Uint8List.fromList(_dataStream),
          );
          _dataStream
            ..clear()
            ..addAll(remaining);
          for (final packet in packets) {
            _refreshIncomingConntrack(packet);
            if (!_incoming.isClosed) {
              _incoming.add(packet);
            }
          }
        case ATrustL3Command.authResponse:
          _handleAuthResponse(frame);
        case ATrustL3Command.secondVipResponse:
          if (frame.status == 0) {
            final vips = ATrustL3Protocol.extractVIPs(frame.payload);
            if (vips.isNotEmpty) onVip?.call(vips);
          }
        case ATrustL3Command.heartbeatResponse:
          _heartbeatMisses = 0;
        default:
          break;
      }
    } on Object catch (error, stackTrace) {
      _fail(error, stackTrace);
    }
  }

  void _refreshIncomingConntrack(Uint8List packet) {
    final meta = buildPacketMeta(packet);
    if (meta == null) return;
    final reversed = meta.reversed;
    final key = ATrustL3FlowKey(
      protocol: reversed.protocol,
      sourceAddress: reversed.sourceAddress,
      sourcePort: reversed.sourcePort,
      destinationAddress: reversed.destinationAddress,
      destinationPort: reversed.destinationPort,
    );
    tracker.observePacket(key, packet, true);
  }

  void _handleAuthResponse(ATrustL3Frame frame) {
    Map<String, Object?> decoded;
    try {
      final value = jsonDecode(utf8.decode(frame.payload));
      if (value is! Map) throw const FormatException('not an object');
      decoded = Map<String, Object?>.from(value);
    } on Object {
      return;
    }
    final data = decoded['data'] is Map
        ? Map<String, Object?>.from(decoded['data'] as Map)
        : <String, Object?>{};
    final conntrackHash = _asInt(data['conntrackHash']);
    var flow =
        conntrackHash != null ? tracker.flowById(conntrackHash) : null;
    flow ??= _findFlowByIp(data['ip']);
    if (flow == null) {
      if (conntrackHash != null) {
        tracker.complete(
          conntrackHash,
          error: StateError('missing conntrack hash'),
        );
      }
      return;
    }
    if (frame.status == 0x84) {
      _retryAuth(flow, Duration.zero);
      return;
    }
    if (frame.status >= 0x85 && frame.status <= 0x87) {
      _retryAuth(flow, authRetryWait);
      return;
    }
    if (frame.status != 0) {
      tracker.complete(
        flow.id,
        error: StateException('auth status ${frame.status}'),
      );
      return;
    }
    final token = data['connectToken']?.toString() ?? '';
    final packets = tracker.complete(flow.id, token: token);
    for (final packet in packets) {
      _write(ATrustL3Protocol.dataRequest(token, packet));
    }
  }

  ATrustL3Flow? _findFlowByIp(Object? rawIp) {
    if (rawIp is! Map) return null;
    final ip = Map<String, Object?>.from(rawIp);
    final srcAddr = ip['srcAddr']?.toString();
    final dstAddr = ip['destAddr']?.toString();
    final srcPort = _asInt(ip['srcPort']);
    final dstPort = _asInt(ip['destPort']);
    final protocol = _asInt(ip['protocol']);
    final atype = _asInt(ip['atype']);
    if (srcAddr == null || dstAddr == null) return null;
    if (atype != null && atype != authIPType(4)) return null;
    for (final flow in tracker.flows) {
      if (flow.key.sourceAddress != srcAddr) continue;
      if (flow.key.destinationAddress != dstAddr) continue;
      if (srcPort != null && flow.key.sourcePort != srcPort) continue;
      if (dstPort != null && flow.key.destinationPort != dstPort) continue;
      if (protocol != null && flow.key.protocol != protocol) continue;
      return flow;
    }
    return null;
  }

  void _retryAuth(ATrustL3Flow flow, Duration delay) {
    if (flow.state != ATrustL3FlowState.pending) return;
    flow.authRequested = false;
    flow.authDeadline = null;
    flow.authRetryAt = _clock().add(delay);
  }

  void _onAuthTick() {
    if (_closed) return;
    _expireAuths();
    _dispatchPendingAuth();
  }

  void _expireAuths() {
    final now = _clock();
    for (final flow in tracker.flows.toList(growable: false)) {
      final deadline = flow.authDeadline;
      if (deadline == null) continue;
      if (now.isBefore(deadline)) continue;
      flow.authTimeouts++;
      if (flow.authTimeouts < authMaxAttempts) {
        flow.authRequested = false;
        flow.authDeadline = null;
        flow.authRetryAt = now;
      } else {
        tracker.complete(
          flow.id,
          error: TimeoutException('flow authentication timed out'),
        );
      }
    }
  }

  void _dispatchPendingAuth() {
    if (_closed) return;
    var dispatched = 0;
    for (final flow in tracker.flows.toList(growable: false)) {
      if (dispatched >= authBatchSize) break;
      if (flow.pendingPackets.isEmpty) continue;
      if (flow.authRequested) continue;
      final retryAt = flow.authRetryAt;
      if (retryAt != null && _clock().isBefore(retryAt)) continue;
      final frame = _transport.authFrameFor(flow);
      flow.authRequested = true;
      flow.authDeadline = _clock().add(authTimeout);
      _write(frame);
      dispatched++;
    }
  }

  void _onHeartbeatTick() {
    if (_closed) return;
    tracker.removeExpired(_clock());
    if (_hasWrite) {
      _hasWrite = false;
      _heartbeatMisses = 0;
      return;
    }
    if (_heartbeatMisses >= heartbeatMissLimit) {
      _fail(
        TimeoutException(
          'L3 tunnel heartbeat timed out after '
          '$_heartbeatMisses missed responses',
        ),
        StackTrace.current,
      );
      return;
    }
    _heartbeatMisses++;
    _write(ATrustL3Protocol.heartbeatRequest(), countsAsActivity: false);
  }

  Future<void> _write(Uint8List frame, {bool countsAsActivity = true}) {
    final task = _writeChain.then((_) {
      if (_closed) throw StateError('connection is closed');
      return _channel.send(frame);
    }).then((_) {
      if (countsAsActivity) {
        _hasWrite = true;
      }
    });
    _writeChain = task.then<void>((_) {}, onError: (Object error) {
      _fail(error, StackTrace.current);
    });
    return task;
  }

  void _fail(Object error, StackTrace stackTrace) {
    if (_closed) return;
    onError?.call(error);
    unawaited(close());
  }
}

int? _asInt(Object? value) {
  if (value is int) return value;
  if (value is num) return value.toInt();
  return int.tryParse('$value');
}

class StateException implements Exception {
  const StateException(this.message);

  final String message;

  @override
  String toString() => 'StateException: $message';
}
