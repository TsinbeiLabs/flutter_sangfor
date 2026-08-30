import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_test/flutter_test.dart';

/// Serializes one socket's chunks so tests can await them one by one.
class _ChunkReader {
  _ChunkReader(Stream<List<int>> stream) {
    _subscription = stream.listen(
      (chunk) {
        _queue.add(Uint8List.fromList(chunk));
        _drain();
      },
      onDone: () {
        if (!_done.isCompleted) _done.complete();
      },
      onError: (Object error) {
        if (!_done.isCompleted) _done.completeError(error);
      },
    );
  }

  final _queue = <Uint8List>[];
  final _completers = <Completer<Uint8List>>[];
  final _done = Completer<void>();
  late final StreamSubscription<List<int>> _subscription;

  Future<void> get done => _done.future;

  void _drain() {
    while (_queue.isNotEmpty && _completers.isNotEmpty) {
      _completers.removeAt(0).complete(_queue.removeAt(0));
    }
  }

  Future<Uint8List> next() {
    if (_queue.isNotEmpty) {
      return Future.value(_queue.removeAt(0));
    }
    final completer = Completer<Uint8List>();
    _completers.add(completer);
    return completer.future;
  }

  Future<void> cancel() => _subscription.cancel();
}

void main() {
  test('routes packets between a device and a tunnel', () async {
    final device = _ScriptedDevice();
    final tunnel = _ScriptedTunnel();
    final router = SangforTunnelRouter(
      egressFilter: (packet) => packet.first == 1,
      ingressFilter: (packet) => packet.first == 2,
    );
    router.start(device: device, tunnel: tunnel);

    device.controller.add(Uint8List.fromList([1, 9]));
    device.controller.add(Uint8List.fromList([0, 9]));
    tunnel.controller.add(Uint8List.fromList([2, 7]));
    tunnel.controller.add(Uint8List.fromList([3, 7]));
    await Future<void>.delayed(Duration.zero);

    expect(tunnel.sent, [
      [1, 9],
    ]);
    expect(device.sent, [
      [2, 7],
    ]);
    await router.stop();
  });

  test('SOCKS5 server proxies a connection end to end', () async {
    final echoServer = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final echoChunks = <List<int>>[];
    echoServer.listen((client) {
      client.listen((chunk) {
        echoChunks.add(chunk);
        client.add(chunk);
      });
    });

    final server = SangforSocks5Server(
      dialer: (host, port) async {
        expect(host, '127.0.0.1');
        expect(port, echoServer.port);
        final socket = await Socket.connect(host, port);
        return SocketTcpStream(socket);
      },
    );
    final socksPort = await server.start();

    final client = await Socket.connect(
      InternetAddress.loopbackIPv4,
      socksPort,
    );
    final reader = _ChunkReader(client);
    client.add(
      Uint8List.fromList([0x05, 0x01, 0x00]),
    );
    client.add(
      Uint8List.fromList([
        0x05,
        0x01,
        0x00,
        0x01,
        127,
        0,
        0,
        1,
        (echoServer.port >> 8) & 0xff,
        echoServer.port & 0xff,
      ]),
    );
    final greeting = await reader.next();
    expect(greeting[0], 0x05);
    expect(greeting[1], 0x00);

    final reply = await reader.next();
    expect(reply[0], 0x05);
    expect(reply[1], 0x00);

    const payload = 'hello through socks';
    client.add(utf8.encode(payload));
    final echoed = await reader
        .next()
        .timeout(const Duration(seconds: 5))
        .then((bytes) => utf8.decode(bytes));
    expect(echoed, payload);

    await client.close();
    await server.close();
    await echoServer.close();
  });

  test('SOCKS5 server proxies via domain and pipelines request bytes',
      () async {
    final echoServer = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final dialHosts = <String>[];
    echoServer.listen((client) {
      client.listen((chunk) {
        client.add(chunk);
      });
    });

    final server = SangforSocks5Server(
      dialer: (host, port) async {
        dialHosts.add(host);
        final address = await InternetAddress.lookup(host);
        final socket = await Socket.connect(address.first, port);
        return SocketTcpStream(socket);
      },
    );
    final socksPort = await server.start();

    final client = await Socket.connect(
      InternetAddress.loopbackIPv4,
      socksPort,
    );
    final domain = 'localhost';
    final portBytes = [
      (echoServer.port >> 8) & 0xff,
      echoServer.port & 0xff,
    ];
    // Greeting, request, and payload arrive together in one write.
    final request = <int>[
      ...[0x05, 0x01, 0x00],
      ...[0x05, 0x01, 0x00, 0x03, domain.length, ...domain.codeUnits],
      ...portBytes,
      ...utf8.encode('pipelined'),
    ];
    client.add(Uint8List.fromList(request));
    final reader = _ChunkReader(client);
    await reader.next();
    final reply = await reader.next();
    expect(reply[1], 0x00);

    final echoed = await reader
        .next()
        .timeout(const Duration(seconds: 5))
        .then((bytes) => utf8.decode(bytes));
    expect(echoed, 'pipelined');
    expect(dialHosts, [domain]);

    await client.close();
    await server.close();
    await echoServer.close();
  });

  test('SOCKS5 server replies with an error when the dial fails', () async {
    final server = SangforSocks5Server(
      dialer: (host, port) async => throw const SocketException('no route'),
    );
    final socksPort = await server.start();

    final client = await Socket.connect(
      InternetAddress.loopbackIPv4,
      socksPort,
    );
    client.add(Uint8List.fromList([0x05, 0x01, 0x00]));
    final reader = _ChunkReader(client);
    await reader.next();
    client.add(
      Uint8List.fromList([
        0x05,
        0x01,
        0x00,
        0x01,
        10,
        1,
        2,
        3,
        0x00,
        0x50,
      ]),
    );
    final reply = await reader.next();
    expect(reply[1], 0x01);

    await client.close();
    await server.close();
  });

  test('SOCKS5 server rejects non-no-auth method offers', () async {
    final server = SangforSocks5Server(
      dialer: (host, port) async => throw StateError('never dialed'),
    );
    final socksPort = await server.start();

    final client = await Socket.connect(
      InternetAddress.loopbackIPv4,
      socksPort,
    );
    client.add(Uint8List.fromList([0x05, 0x01, 0x02]));
    final reader = _ChunkReader(client);
    final greeting = await reader.next();
    expect(greeting[0], 0x05);
    expect(greeting[1], 0xff);
    await reader.done.timeout(const Duration(seconds: 5));

    await server.close();
  });

  test('SOCKS5 server rejects non-CONNECT commands', () async {
    final server = SangforSocks5Server(
      dialer: (host, port) async => throw StateError('never dialed'),
    );
    final socksPort = await server.start();

    final client = await Socket.connect(
      InternetAddress.loopbackIPv4,
      socksPort,
    );
    client.add(Uint8List.fromList([0x05, 0x01, 0x00]));
    final reader = _ChunkReader(client);
    await reader.next();
    // BIND.
    client.add(
      Uint8List.fromList([0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
    );
    final reply = await reader.next();
    expect(reply[1], 0x07);

    await client.close();
    await server.close();
  });

  test('router stops when the cancellation token is cancelled', () async {
    final device = _ScriptedDevice();
    final tunnel = _ScriptedTunnel();
    final token = SangforCancellationToken();
    final router = SangforTunnelRouter(cancellationToken: token);
    router.start(device: device, tunnel: tunnel);
    expect(router.isRunning, isTrue);

    token.cancel();
    await Future<void>.delayed(Duration.zero);

    expect(router.isRunning, isFalse);
    // Packets after cancellation are not forwarded.
    device.controller.add(Uint8List.fromList([1, 1]));
    await Future<void>.delayed(Duration.zero);
    expect(tunnel.sent, isEmpty);
  });

  test('SOCKS5 server closes sessions when the token is cancelled', () async {
    final token = SangforCancellationToken();
    final neverCompletes = Completer<SangforTcpStream>();
    final server = SangforSocks5Server(
      dialer: (host, port) => neverCompletes.future,
      cancellationToken: token,
    );
    final socksPort = await server.start();

    final client = await Socket.connect(
      InternetAddress.loopbackIPv4,
      socksPort,
    );
    client.add(Uint8List.fromList([0x05, 0x01, 0x00]));
    final reader = _ChunkReader(client);
    await reader.next();
    client.add(
      Uint8List.fromList([
        0x05,
        0x01,
        0x00,
        0x01,
        127,
        0,
        0,
        1,
        0x00,
        0x50,
      ]),
    );
    // The dial is pending; cancelling must tear the session down.
    token.cancel();
    await reader.done.timeout(const Duration(seconds: 5));
    expect(server.isRunning, isFalse);

    await client.close();
  });
}

class _ScriptedDevice implements SangforPacketDevice {
  final controller = StreamController<Uint8List>.broadcast();
  final sent = <List<int>>[];

  @override
  Stream<Uint8List> get incoming => controller.stream;

  @override
  bool get isClosed => controller.isClosed;

  @override
  Future<void> send(Uint8List packet) async => sent.add(packet);

  @override
  Future<void> close() async => controller.close();
}

class _ScriptedTunnel implements SangforPacketTunnel {
  final controller = StreamController<Uint8List>.broadcast();
  final sent = <List<int>>[];

  @override
  Stream<Uint8List> get incoming => controller.stream;

  @override
  bool get isClosed => controller.isClosed;

  @override
  Future<bool> sendPacket(Uint8List packet) async {
    sent.add(packet);
    return true;
  }

  @override
  Future<void> close() async => controller.close();
}
