import 'dart:async';
import 'dart:typed_data';

import 'data_plane.dart';
import 'tls/tls_client.dart';

/// A logical TLS connection the tunnel can run on. [EasyConnectTlsSocket]
/// implements it; tests provide scripted implementations.
abstract class EasyConnectTlsConnection {
  Stream<Uint8List> get incoming;

  Uint8List get sessionId;

  Uint8List get peerCertificate;

  bool get isClosed;

  Future<void> send(Uint8List data);

  Future<void> close();
}

/// Builds the TLS connections the tunnel needs: a standard-hello token
/// connection plus L3IP-hello command/RX/TX streams.
typedef EasyConnectTlsConnectionFactory = Future<EasyConnectTlsConnection>
    Function(TlsClientHelloSpec hello);

/// The raw-IP transport surface the userspace proxies need. Implemented by
/// [EasyConnectTunnel] and by test doubles.
abstract class EasyConnectPacketTransport {
  Stream<Uint8List> get incoming;

  Future<void> sendPacket(Uint8List packet);
}

/// Splits a raw byte stream into IPv4/IPv6 packets using the IP header
/// length fields, keeping any partial trailing packet buffered.
(List<Uint8List>, Uint8List) splitIpPacketStream(Uint8List stream) {
  final packets = <Uint8List>[];
  var offset = 0;
  while (offset < stream.length) {
    final remaining = stream.length - offset;
    final version = stream[offset] >> 4;
    int packetLength;
    if (version == 4) {
      if (remaining < 4) {
        return (packets, Uint8List.sublistView(stream, offset));
      }
      final headerLength = (stream[offset] & 0x0f) * 4;
      packetLength = ByteData.sublistView(stream, offset + 2, offset + 4)
          .getUint16(0, Endian.big);
      if (headerLength < 20 || packetLength < headerLength) {
        throw FormatException(
          'invalid IPv4 packet length $packetLength with header length '
          '$headerLength',
        );
      }
    } else if (version == 6) {
      if (remaining < 6) {
        return (packets, Uint8List.sublistView(stream, offset));
      }
      packetLength = 40 +
          ByteData.sublistView(stream, offset + 4, offset + 6)
              .getUint16(0, Endian.big);
    } else {
      throw FormatException('unexpected IP version $version');
    }
    if (remaining < packetLength) {
      return (packets, Uint8List.sublistView(stream, offset));
    }
    packets.add(Uint8List.fromList(stream.sublist(offset, offset + packetLength)));
    offset += packetLength;
  }
  return (packets, Uint8List.sublistView(stream, offset));
}

/// Drives the EasyConnect L3 data plane: derives the tunnel token from a
/// TLS session id, acquires the client IP over a long-lived command stream,
/// and establishes the raw-IP RX/TX streams with their keepalives.
class EasyConnectTunnel implements EasyConnectPacketTransport {
  EasyConnectTunnel({
    required this.server,
    required this.twfId,
    required EasyConnectTlsConnectionFactory connectionFactory,
    EasyConnectKeepaliveClient? keepaliveClient,
    this.commandHeartbeatInterval = const Duration(seconds: 30),
    this.txHeartbeatInterval = const Duration(seconds: 12),
    this.onFatal,
  })  : _connectionFactory = connectionFactory,
        _keepalive = keepaliveClient ??
            EasyConnectKeepaliveClient(
              interval: const Duration(seconds: 60),
            );

  final Uri server;
  final String twfId;
  final EasyConnectTlsConnectionFactory _connectionFactory;
  final EasyConnectKeepaliveClient _keepalive;
  final Duration commandHeartbeatInterval;
  final Duration txHeartbeatInterval;
  final void Function(Object error)? onFatal;

  final StreamController<Uint8List> _incoming =
      StreamController<Uint8List>.broadcast();
  final List<int> _rxBuffer = <int>[];

  EasyConnectTlsConnection? _commandConnection;
  EasyConnectTlsConnection? _rxConnection;
  EasyConnectTlsConnection? _txConnection;
  Uint8List? _token;
  List<int> _clientIp = const <int>[];
  List<int> _serverLanIp = const <int>[];
  Timer? _commandHeartbeatTimer;
  Timer? _txHeartbeatTimer;
  StreamSubscription<Uint8List>? _commandSubscription;
  StreamSubscription<Uint8List>? _rxSubscription;
  bool _closed = false;

  @override
  Stream<Uint8List> get incoming => _incoming.stream;
  Uint8List? get token => _token;
  String? get virtualAddress => _clientIp.isEmpty
      ? null
      : _clientIp.join('.');
  bool get isClosed => _closed;

  /// Runs the full bring-up sequence and returns the assigned client IP.
  Future<String?> start() async {
    if (_closed) throw StateError('tunnel is closed');
    // 1. Token connection: standard hello + pipelined conf/rclist requests.
    final tokenConnection = await _connectionFactory(
      TlsClientHelloSpec.standard(),
    );
    try {
      final host = server.host;
      final request =
          'GET /por/conf.csp HTTP/1.1\r\nHost: $host\r\n'
          'Cookie: TWFID=$twfId\r\n\r\n'
          'GET /por/rclist.csp HTTP/1.1\r\nHost: $host\r\n'
          'Cookie: TWFID=$twfId\r\nConnection: close\r\n\r\n';
      // Subscribe before sending so no reply chunk is missed.
      await _sendAndReadFirst(
        tokenConnection,
        Uint8List.fromList(request.codeUnits),
      );
    } finally {
      await tokenConnection.close();
    }
    final token = EasyConnectTunnelProtocol.deriveToken(
      tokenConnection.sessionId,
      twfId,
    );
    _token = token;

    // 2. Query-IP on the long-lived command stream.
    final command = await _connectionFactory(TlsClientHelloSpec.l3Ip());
    _commandConnection = command;
    final queryReply = await _sendAndReadFirst(
      command,
      EasyConnectTunnelProtocol.queryIpMessage(token),
    );
    final (clientIp, serverLanIp) =
        EasyConnectTunnelProtocol.parseQueryIpResponse(queryReply);
    _clientIp = List<int>.from(clientIp);
    _serverLanIp = List<int>.from(serverLanIp);
    _commandSubscription = command.incoming.listen(
      _onCommandData,
      onError: (Object error) => _fatal(error),
      onDone: () => _fatal(StateError('command stream closed')),
    );
    _commandHeartbeatTimer = Timer.periodic(
      commandHeartbeatInterval,
      (_) => _sendCommandHeartbeat(),
    );

    // 3. RX stream: raw IP packets from the server.
    final rx = await _connectionFactory(TlsClientHelloSpec.l3Ip());
    _rxConnection = rx;
    final ipRev = _reversedClientIp();
    final rxReply = await _sendAndReadFirst(
      rx,
      EasyConnectTunnelProtocol.rxStreamMessage(token, ipRev),
    );
    EasyConnectTunnelProtocol.parseStreamResponse(rxReply, 1);
    _rxSubscription = rx.incoming.listen(
      _onRxData,
      onError: (Object error) => _fatal(error),
      onDone: () => _fatal(StateError('RX stream closed')),
    );

    // 4. TX stream: raw IP packets to the server plus ICMP keepalives.
    final tx = await _connectionFactory(TlsClientHelloSpec.l3Ip());
    _txConnection = tx;
    final txReply = await _sendAndReadFirst(
      tx,
      EasyConnectTunnelProtocol.txStreamMessage(token, ipRev),
    );
    EasyConnectTunnelProtocol.parseStreamResponse(txReply, 2);
    _txHeartbeatTimer = Timer.periodic(
      txHeartbeatInterval,
      (_) => _sendTxHeartbeat(),
    );

    // 5. HTTP session keepalive.
    _keepalive.start(
      server,
      twfId,
      onError: (Object error) {
        // Keepalive failures are surfaced by the tunnel but not fatal.
      },
    );
    return virtualAddress;
  }

  /// Sends [message] and resolves with the first reply chunk. The reply
  /// subscription is attached before the send so synchronous responders
  /// cannot race the reader.
  Future<Uint8List> _sendAndReadFirst(
    EasyConnectTlsConnection connection,
    Uint8List message,
  ) async {
    final completer = Completer<Uint8List>();
    final subscription = connection.incoming.listen(
      (chunk) {
        if (!completer.isCompleted) completer.complete(chunk);
      },
      onError: (Object error, StackTrace stackTrace) {
        if (!completer.isCompleted) completer.completeError(error, stackTrace);
      },
      onDone: () {
        if (!completer.isCompleted) {
          completer.completeError(
            StateError('connection closed before reply'),
          );
        }
      },
    );
    try {
      await connection.send(message);
      return await completer.future;
    } finally {
      await subscription.cancel();
    }
  }

  /// Sends one raw IP packet through the TX stream.
  @override
  Future<void> sendPacket(Uint8List packet) async {
    if (_closed) return;
    final tx = _txConnection;
    if (tx == null || tx.isClosed) {
      throw StateError('TX stream is not established');
    }
    await tx.send(packet);
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    _commandHeartbeatTimer?.cancel();
    _txHeartbeatTimer?.cancel();
    await _commandSubscription?.cancel();
    await _rxSubscription?.cancel();
    _keepalive.stop();
    await _commandConnection?.close();
    await _rxConnection?.close();
    await _txConnection?.close();
    if (!_incoming.isClosed) {
      await _incoming.close();
    }
  }

  void _onCommandData(Uint8List chunk) {
    if (_closed) return;
    int code;
    if (EasyConnectTunnelProtocol.isNativeControlFrame(chunk)) {
      code = EasyConnectTunnelProtocol.parseNativeControlFrame(chunk);
    } else if (chunk.length >= 4) {
      code = ByteData.sublistView(chunk).getUint32(0, Endian.little);
    } else {
      return;
    }
    // Fatal controls: shutdown, IpConflict, IpKick.
    if (code == 8 || code == 9 || code == 14) {
      _fatal(StateError('server sent fatal control code $code'));
    }
  }

  void _onRxData(Uint8List chunk) {
    if (_closed) return;
    _rxBuffer.addAll(chunk);
    final (packets, remaining) = splitIpPacketStream(
      Uint8List.fromList(_rxBuffer),
    );
    _rxBuffer
      ..clear()
      ..addAll(remaining);
    for (final packet in packets) {
      if (!_incoming.isClosed) {
        _incoming.add(packet);
      }
    }
  }

  void _sendCommandHeartbeat() {
    final token = _token;
    final command = _commandConnection;
    if (_closed || token == null || command == null) return;
    unawaited(
      command
          .send(EasyConnectTunnelProtocol.commandHeartbeatMessage(token))
          .catchError((Object error) {
        _fatal(error);
      }),
    );
  }

  void _sendTxHeartbeat() {
    final token = _token;
    final tx = _txConnection;
    if (_closed || token == null || tx == null) return;
    unawaited(
      tx
          .send(
            EasyConnectTunnelProtocol.heartbeatPacket(
              _clientIp,
              _serverLanIp,
              token,
            ),
          )
          .catchError((Object error) {
        _fatal(error);
      }),
    );
  }

  List<int> _reversedClientIp() => _clientIp.isEmpty
      ? const <int>[0, 0, 0, 0]
      : <int>[
          _clientIp[3],
          _clientIp[2],
          _clientIp[1],
          _clientIp[0],
        ];

  void _fatal(Object error) {
    if (_closed) return;
    onFatal?.call(error);
    unawaited(close());
  }
}
