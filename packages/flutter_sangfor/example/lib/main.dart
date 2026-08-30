import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_sangfor/flutter_sangfor.dart';

void main() {
  runApp(const ExampleApp());
}

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      title: 'flutter_sangfor example',
      home: Socks5DemoPage(),
    );
  }
}

class Socks5DemoPage extends StatefulWidget {
  const Socks5DemoPage({super.key});

  @override
  State<Socks5DemoPage> createState() => _Socks5DemoPageState();
}

class _Socks5DemoPageState extends State<Socks5DemoPage> {
  SangforSocks5Server? _server;
  int? _port;
  String _log = 'SOCKS5 server is not running.\n';

  Future<void> _start() async {
    if (_server != null) return;
    // Demo dialer: connects directly (no VPN). Replace with
    // `connector.dialTcp` from flutter_sangfor_atrust or
    // flutter_sangfor_easy_connect once connected.
    final server = SangforSocks5Server(
      dialer: (host, port) async {
        final socket = await Socket.connect(host, port);
        return SocketTcpStream(socket);
      },
    );
    final port = await server.start();
    setState(() {
      _server = server;
      _port = port;
      _log += 'SOCKS5 listening on 127.0.0.1:$port\n';
    });
  }

  Future<void> _stop() async {
    final server = _server;
    if (server == null) return;
    await server.close();
    setState(() {
      _server = null;
      _port = null;
      _log += 'SOCKS5 server stopped.\n';
    });
  }

  /// Runs one SOCKS5 CONNECT round trip against a local echo server and
  /// echoes a payload back through the proxy.
  Future<void> _runEchoTest() async {
    final port = _port;
    if (port == null) {
      setState(() => _log += 'Start the SOCKS5 server first.\n');
      return;
    }
    final echo = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    echo.listen((client) {
      client.listen((chunk) => client.add(chunk));
    });
    try {
      final client = await Socket.connect(InternetAddress.loopbackIPv4, port);
      client.add(Uint8List.fromList([0x05, 0x01, 0x00]));
      client.add(Uint8List.fromList([
        0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1,
        (echo.port >> 8) & 0xff, echo.port & 0xff,
      ]));
      final completer = Completer<String>();
      final buffer = BytesBuilder();
      late final StreamSubscription<List<int>> subscription;
      subscription = client.listen(
        (chunk) {
          buffer.add(chunk);
          final bytes = buffer.toBytes();
          if (bytes.length >= 2 && bytes[1] == 0x00) {
            // Greeting consumed; wait for the CONNECT reply (10 bytes).
            if (bytes.length >= 12) {
              final payload = String.fromCharCodes(bytes.sublist(12));
              subscription.cancel();
              if (!completer.isCompleted) completer.complete(payload);
            }
          }
        },
        onDone: () {
          if (!completer.isCompleted) {
            completer.completeError(StateError('connection closed'));
          }
        },
        onError: (Object error) {
          if (!completer.isCompleted) completer.completeError(error);
        },
      );
      const payload = 'hello via socks5';
      client.add(Uint8List.fromList(payload.codeUnits));
      final echoed = await completer.future
          .timeout(const Duration(seconds: 5));
      await client.close();
      setState(() => _log += 'echo round trip: "$echoed"\n');
    } finally {
      await echo.close();
    }
  }

  @override
  void dispose() {
    unawaited(_server?.close());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final running = _server != null;
    return Scaffold(
      appBar: AppBar(title: const Text('flutter_sangfor')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              running
                  ? 'SOCKS5 proxy: 127.0.0.1:$_port'
                  : 'SOCKS5 proxy: stopped',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 12),
            FilledButton(
              onPressed: running ? _stop : _start,
              child: Text(running ? 'Stop SOCKS5' : 'Start SOCKS5'),
            ),
            const SizedBox(height: 8),
            OutlinedButton(
              onPressed: _runEchoTest,
              child: const Text('Run echo test'),
            ),
            const SizedBox(height: 12),
            Expanded(
              child: Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  border: Border.all(color: Colors.black26),
                ),
                child: SingleChildScrollView(
                  child: Text(
                    _log,
                    style: const TextStyle(fontFamily: 'monospace'),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
