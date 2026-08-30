import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_sangfor/flutter_sangfor.dart';

import 'l3_connection.dart';
import 'tcp_tunnel.dart';
import 'tunnel.dart';

/// Convenience wrapper for dialing single TCP connections through the
/// SOCKS5-like aTrust TCP tunnel.
class ATrustTcpTunnelClient {
  const ATrustTcpTunnelClient();

  static Future<ATrustTcpTunnelConn> connect({
    required ATrustTunnelChannel channel,
    required ATrustTcpTunnelAuthRequest request,
    required Uint8List signKey,
    required String host,
    required int port,
    bool zeroRtt = false,
    Duration timeout = const Duration(seconds: 18),
  }) =>
      ATrustTcpTunnelConn.connect(
        channel: channel,
        request: request,
        signKey: signKey,
        host: host,
        port: port,
        zeroRtt: zeroRtt,
        timeout: timeout,
      );
}

/// A live TCP tunnel connection. In raw mode bytes flow unframed; in reuse
/// mode both directions use the tunnel data frames with EOF signaling.
class ATrustTcpTunnelConn {
  ATrustTcpTunnelConn._(this._channel);

  final ATrustTunnelChannel _channel;
  // Single-subscription (buffered) so bytes arriving before the consumer
  // attaches are not dropped.
  final StreamController<Uint8List> _incoming = StreamController<Uint8List>();
  final Completer<void> _handshakeDone = Completer<void>();
  final List<int> _buffer = <int>[];
  ATrustTcpTunnelServerResponse? _response;
  bool _reuse = false;
  bool _closed = false;
  StreamSubscription<List<int>>? _subscription;

  bool get reuse => _reuse;
  bool get raw => !_reuse;
  Stream<Uint8List> get incoming => _incoming.stream;
  bool get isClosed => _closed;
  ATrustTcpTunnelServerResponse? get serverResponse => _response;

  static Future<ATrustTcpTunnelConn> connect({
    required ATrustTunnelChannel channel,
    required ATrustTcpTunnelAuthRequest request,
    required Uint8List signKey,
    required String host,
    required int port,
    bool zeroRtt = false,
    Duration timeout = const Duration(seconds: 18),
  }) async {
    final conn = ATrustTcpTunnelConn._(channel).._beginListen(zeroRtt: zeroRtt);
    try {
      await channel.send(
        ATrustTcpTunnelProtocol.handshakeMessage(
          request,
          signKey,
          host,
          port,
          zeroRtt: zeroRtt,
        ),
      );
      await conn._handshakeDone.future.timeout(timeout);
    } on Object {
      await conn.close();
      rethrow;
    }
    final response = conn._response!;
    if (response.authCode != 0) {
      await conn.close();
      throw ATrustTcpTunnelException(
        'TCP tunnel authentication failed (code ${response.authCode}): '
        '${response.authMessage}',
      );
    }
    if (response.connectStatus != 0) {
      await conn.close();
      throw ATrustTcpTunnelException(
        ATrustTcpTunnelProtocol.connectStatusMessage(response.connectStatus),
      );
    }
    conn._reuse = zeroRtt && response.reuse;
    return conn;
  }

  void _beginListen({required bool zeroRtt}) {
    _subscription = _channel.incoming.listen(
      (chunk) {
        if (!_handshakeDone.isCompleted) {
          final leftover = _handleHandshakeChunk(chunk);
          if (leftover != null && leftover.isNotEmpty) {
            _handleDataChunk(leftover);
          }
        } else {
          _handleDataChunk(chunk);
        }
      },
      onDone: () {
        if (!_handshakeDone.isCompleted) {
          _handshakeDone.completeError(
            StateException('channel closed during TCP tunnel handshake'),
          );
        }
        if (!_incoming.isClosed) {
          unawaited(_incoming.close());
        }
      },
      onError: (Object error) {
        if (!_handshakeDone.isCompleted) {
          _handshakeDone.completeError(error);
        }
      },
    );
  }

  Uint8List? _handleHandshakeChunk(List<int> chunk) {
    _buffer.addAll(chunk);
    if (_buffer.length < 2) return null;
    if (_buffer[0] != ATrustTcpTunnelProtocol.version || _buffer[1] != 0x81) {
      _handshakeDone.completeError(
        const FormatException('unexpected TCP tunnel server hello'),
      );
      return null;
    }
    if (_buffer.length < 4) return null;
    if (_buffer[2] != 0x53 || _buffer[3] != 0x00) {
      _handshakeDone.completeError(
        const FormatException('unexpected TCP tunnel auth response'),
      );
      return null;
    }
    if (_buffer.length < 6) return null;
    final authLength = (_buffer[4] << 8) | _buffer[5];
    if (_buffer.length < 6 + authLength) return null;
    final authPayload = Uint8List.fromList(_buffer.sublist(6, 6 + authLength));
    var offset = 6 + authLength;
    if (_buffer.length < offset + 4) return null;
    if (_buffer[offset] != ATrustTcpTunnelProtocol.version) {
      _handshakeDone.completeError(
        const FormatException('unexpected TCP tunnel connect reply version'),
      );
      return null;
    }
    final connectStatus = _buffer[offset + 1];
    if (connectStatus != 0) {
      final consumed = offset + 4;
      final leftover = Uint8List.fromList(_buffer.sublist(consumed));
      _buffer.clear();
      _completeHandshake(authPayload, connectStatus, false);
      return leftover;
    }
    var reuse = false;
    var addressLength = 0;
    reuse = _buffer[offset + 2] == 0x01;
    final addressType = _buffer[offset + 3];
    addressLength = switch (addressType) {
      0x01 => 4,
      0x04 => 16,
      _ => -1,
    };
    if (addressLength < 0) {
      _handshakeDone.completeError(
        const FormatException('unexpected bind address type'),
      );
      return null;
    }
    final totalNeeded = offset + 4 + addressLength + 2;
    if (_buffer.length < totalNeeded) return null;
    final leftover = Uint8List.fromList(_buffer.sublist(totalNeeded));
    _buffer.clear();
    _completeHandshake(authPayload, connectStatus, reuse);
    return leftover;
  }

  void _completeHandshake(
    Uint8List authPayload,
    int connectStatus,
    bool reuse,
  ) {
    var authCode = 0;
    var authMessage = '';
    try {
      final value = jsonDecode(utf8.decode(authPayload));
      if (value is Map) {
        final map = Map<String, Object?>.from(value);
        authCode = map['code'] is int
            ? map['code'] as int
            : int.tryParse('${map['code'] ?? 0}') ?? 0;
        authMessage = map['message']?.toString() ?? '';
      }
    } on Object {
      authCode = -1;
      authMessage = 'invalid auth response';
    }
    _response = ATrustTcpTunnelServerResponse(
      authCode: authCode,
      authMessage: authMessage,
      connectStatus: connectStatus,
      reuse: reuse,
      consumed: 0,
    );
    if (!_handshakeDone.isCompleted) {
      _handshakeDone.complete();
    }
  }

  void _handleDataChunk(List<int> chunk) {
    if (_closed) return;
    if (raw) {
      if (chunk.isNotEmpty && !_incoming.isClosed) {
        _incoming.add(Uint8List.fromList(chunk));
      }
      return;
    }
    _buffer.addAll(chunk);
    while (true) {
      if (_buffer.length < 4) return;
      if (_buffer[0] != 0x01) {
        unawaited(close());
        return;
      }
      if (_buffer[1] == 0x01) {
        _buffer.clear();
        if (!_incoming.isClosed) unawaited(_incoming.close());
        return;
      }
      if (_buffer[1] != 0x00) {
        unawaited(close());
        return;
      }
      final length = (_buffer[2] << 8) | _buffer[3];
      if (_buffer.length < 4 + length) return;
      final data = Uint8List.fromList(_buffer.sublist(4, 4 + length));
      _buffer.removeRange(0, 4 + length);
      if (data.isNotEmpty && !_incoming.isClosed) {
        _incoming.add(data);
      }
    }
  }

  Future<void> send(Uint8List data) async {
    if (_closed) throw StateError('TCP tunnel connection is closed');
    if (raw) {
      await _channel.send(data);
      return;
    }
    for (final frame in ATrustTcpTunnelProtocol.dataFrames(data)) {
      await _channel.send(frame);
    }
  }

  /// Half-closes the connection. In reuse mode this sends the tunnel EOF
  /// frame; in raw mode it simply closes the underlying channel.
  Future<void> closeWrite() async {
    if (_closed) return;
    if (reuse) {
      await _channel.send(ATrustTcpTunnelProtocol.eofFrame());
      return;
    }
    await _channel.close();
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _subscription?.cancel();
    _subscription = null;
    if (!_incoming.isClosed) {
      unawaited(_incoming.close());
    }
    await _channel.close();
  }
}

class ATrustTcpTunnelException implements Exception {
  const ATrustTcpTunnelException(this.message);

  final String message;

  @override
  String toString() => 'ATrustTcpTunnelException: $message';
}

/// Adapts an [ATrustTcpTunnelConn] to the product-neutral
/// [SangforTcpStream] interface used by the SOCKS5 frontend.
class ATrustTcpTunnelStream extends SangforTcpStream {
  ATrustTcpTunnelStream(this._connection);

  final ATrustTcpTunnelConn _connection;

  @override
  Stream<Uint8List> get incoming => _connection.incoming;

  @override
  bool get isClosed => _connection.isClosed;

  @override
  Future<void> send(Uint8List data) => _connection.send(data);

  @override
  Future<void> closeWrite() => _connection.closeWrite();

  @override
  Future<void> close() => _connection.close();
}
