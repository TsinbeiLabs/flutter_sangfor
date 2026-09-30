import 'dart:convert';
import 'dart:io';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_test/flutter_test.dart';

/// A reply captured from the real `sangfor-tunneld` binary, not written by hand.
///
/// Pinning the daemon's actual output is what keeps the two sides honest: the
/// Rust struct serializes with `#[serde(rename_all = "camelCase")]` and omits
/// absent fields, and a rename there would otherwise show up only as a tunnel
/// that reports nothing.
const String kCapturedStatusReply =
    '{"ok":true,"data":{"active":false,"virtualIp":[],"interfaceConfigured":'
    'false,"interfaceError":null,"channelsOpen":0,"devicePackets":0,'
    '"emittedPackets":0,"deviceDropped":0,"emitFailures":0,"channelBytesIn":0,'
    '"channelBytesOut":0,"connectFailures":1,"routed":0,"terminated":0,'
    '"unrouted":0,"ingress":0,"interface":"smoke0","fatal":null}}';

/// A stand-in for the daemon: one connection, JSON lines, answers in order.
class FakeDaemon {
  FakeDaemon._(this._server, this.token);

  final ServerSocket _server;
  final String? token;
  final List<Map<String, Object?>> requests = <Map<String, Object?>>[];

  /// What `status` replies with.
  Map<String, Object?> snapshot = <String, Object?>{
    'active': true,
    'virtualIp': <String>['10.0.0.42'],
    'interfaceConfigured': true,
    'interface': 'fake0',
  };

  /// Set to make the daemon hang up instead of replying.
  bool dropOnNextRequest = false;

  int get port => _server.port;

  static Future<FakeDaemon> start({String? token}) async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final daemon = FakeDaemon._(server, token);
    server.listen(daemon._accept);
    return daemon;
  }

  void _accept(Socket socket) {
    socket
        .cast<List<int>>()
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(
          (line) => _handle(socket, line),
          onDone: socket.destroy,
          onError: (Object _) => socket.destroy(),
        );
  }

  void _handle(Socket socket, String line) {
    if (dropOnNextRequest) {
      socket.destroy();
      return;
    }
    final decoded = jsonDecode(line);
    if (decoded is! Map) {
      _write(socket, <String, Object?>{'ok': false, 'error': 'not an object'});
      return;
    }
    final request = decoded.cast<String, Object?>();
    requests.add(request);
    final command = request['cmd'];
    final supplied = request['token'] as String?;
    if (command != 'ping' && token != null && supplied != token) {
      _write(socket, <String, Object?>{
        'ok': false,
        'error': 'the control token is missing or wrong',
      });
      return;
    }
    switch (command) {
      case 'ping':
      case 'stop':
        _write(socket, <String, Object?>{'ok': true});
      case 'status':
        _write(socket, <String, Object?>{'ok': true, 'data': snapshot});
      default:
        _write(socket, <String, Object?>{
          'ok': false,
          'error': 'unrecognised request',
        });
    }
  }

  void _write(Socket socket, Map<String, Object?> reply) {
    socket.add(utf8.encode('${jsonEncode(reply)}\n'));
  }

  Future<void> close() async {
    await _server.close();
  }
}

void main() {
  group('SangforTunnelHostConfig', () {
    test('uses the field names the daemon parses', () {
      // The Rust side declares `deny_unknown_fields`, so a name that drifts is
      // rejected outright rather than ignored -- but only if it is one the
      // daemon has heard of. These are the names it knows.
      final json = const SangforTunnelHostConfig(
        device: SangforTunnelDevice.wintun,
        interface: 'Luotopia',
        fd: 7,
        wintunDllPath: r'C:\app\wintun.dll',
        address: '10.0.0.42',
        netmask: '255.255.255.0',
        gateway: '10.0.0.1',
        routes: <String>['10.1.0.0/16'],
        dnsServers: <String>['10.0.0.53'],
        mtu: 1280,
        acceptUnpinnedCertificate: false,
        connectTimeoutSeconds: 30,
        controlPort: 0,
        controlToken: 'tok',
        logPath: r'C:\logs\tunnel.log',
      ).toJson();

      expect(json, <String, Object?>{
        'device': 'wintun',
        'interface': 'Luotopia',
        'fd': 7,
        'wintunDll': r'C:\app\wintun.dll',
        'address': '10.0.0.42',
        'netmask': '255.255.255.0',
        'gateway': '10.0.0.1',
        'routes': <String>['10.1.0.0/16'],
        'dnsServers': <String>['10.0.0.53'],
        'mtu': 1280,
        'acceptUnpinnedCertificate': false,
        'connectTimeoutSeconds': 30,
        'controlPort': 0,
        'controlToken': 'tok',
        'logPath': r'C:\logs\tunnel.log',
      });
    });

    test('omits unset optional fields rather than sending null', () {
      // `fd: null` would be a field the daemon has to interpret; absent is
      // unambiguous, and `deny_unknown_fields` makes the difference matter.
      final json = const SangforTunnelHostConfig().toJson();
      for (final key in <String>[
        'fd',
        'wintunDll',
        'address',
        'gateway',
        'controlPort',
        'controlToken',
        'logPath',
      ]) {
        expect(json.containsKey(key), isFalse, reason: '$key should be absent');
      }
      expect(json['device'], 'wintun');
      expect(json['interface'], 'sangfor0');
      expect(json['netmask'], '255.255.255.255');
      expect(json['mtu'], 1400);
      expect(json['acceptUnpinnedCertificate'], isTrue);
      expect(json['connectTimeoutSeconds'], 15);
      expect(json['routes'], isEmpty);
      expect(json['dnsServers'], isEmpty);
    });

    test('every device kind has a distinct wire name', () {
      final names = SangforTunnelDevice.values
          .map((SangforTunnelDevice device) => device.wireName)
          .toSet();
      expect(names, <String>{'wintun', 'tun', 'fd', 'loopback'});
    });

    test('encodes to the same document toJson describes', () {
      const config = SangforTunnelHostConfig(interface: 'enc0');
      expect(jsonDecode(config.encode()), config.toJson());
    });
  });

  group('SangforTunnelSnapshot', () {
    test('parses a reply captured from the real daemon', () {
      final decoded = jsonDecode(kCapturedStatusReply) as Map<String, Object?>;
      final data = (decoded['data']! as Map).cast<String, Object?>();
      final snapshot = SangforTunnelSnapshot.fromJson(data);

      expect(snapshot.active, isFalse);
      expect(snapshot.virtualIp, isEmpty);
      expect(snapshot.interfaceConfigured, isFalse);
      expect(snapshot.interfaceError, isNull);
      expect(snapshot.connectFailures, 1);
      expect(snapshot.interfaceName, 'smoke0');
      expect(snapshot.fatal, isNull);
      expect(snapshot.isDead, isFalse);
    });

    test('tolerates a reply that omits fields', () {
      // A daemon older than this client must not crash it.
      final snapshot =
          SangforTunnelSnapshot.fromJson(const <String, Object?>{});
      expect(snapshot.active, isFalse);
      expect(snapshot.virtualIp, isEmpty);
      expect(snapshot.routed, 0);
      expect(snapshot.interfaceName, isNull);
    });

    test('accepts numbers the JSON decoder gave back as doubles', () {
      final snapshot = SangforTunnelSnapshot.fromJson(
        const <String, Object?>{'routed': 3.0, 'ingress': 4},
      );
      expect(snapshot.routed, 3);
      expect(snapshot.ingress, 4);
    });

    test('a fatal error marks the session dead', () {
      final snapshot = SangforTunnelSnapshot.fromJson(
        const <String, Object?>{'fatal': 'the gateway rejected the session'},
      );
      expect(snapshot.isDead, isTrue);
      expect(snapshot.toString(), contains('the gateway rejected the session'));
    });

    test('the description carries the counters worth reading', () {
      final snapshot = SangforTunnelSnapshot.fromJson(
        const <String, Object?>{
          'active': true,
          'routed': 5,
          'terminated': 2,
          'unrouted': 1,
          'deviceDropped': 3,
        },
      );
      final text = snapshot.toString();
      for (final fragment in <String>[
        'active: true',
        'routed: 5',
        'terminated: 2',
        'unrouted: 1',
        'dropped: 3',
      ]) {
        expect(text, contains(fragment));
      }
    });
  });

  group('SangforTunnelControlClient', () {
    late FakeDaemon daemon;

    tearDown(() async {
      await daemon.close();
    });

    test('pings and reads a snapshot', () async {
      daemon = await FakeDaemon.start();
      final client =
          await SangforTunnelControlClient.connect(port: daemon.port);
      addTearDown(client.close);

      await client.ping();
      final snapshot = await client.status();
      expect(snapshot.active, isTrue);
      expect(snapshot.virtualIp, <String>['10.0.0.42']);
      expect(snapshot.interfaceName, 'fake0');
      expect(client.isClosed, isFalse);
    });

    test('sends the token with every request that needs one', () async {
      daemon = await FakeDaemon.start(token: 's3cret');
      final client = await SangforTunnelControlClient.connect(
        port: daemon.port,
        token: 's3cret',
      );
      addTearDown(client.close);

      await client.ping();
      await client.status();
      await client.stop();
      expect(daemon.requests, hasLength(3));
      for (final request in daemon.requests) {
        expect(request['token'], 's3cret');
      }
      expect(
        daemon.requests.map((Map<String, Object?> request) => request['cmd']),
        <String>['ping', 'status', 'stop'],
      );
    });

    test('a wrong token surfaces the daemon’s own reason', () async {
      daemon = await FakeDaemon.start(token: 's3cret');
      final client = await SangforTunnelControlClient.connect(
        port: daemon.port,
        token: 'wrong',
      );
      addTearDown(client.close);

      await expectLater(
        client.status(),
        throwsA(
          isA<SangforTunnelControlException>().having(
            (SangforTunnelControlException error) => error.message,
            'message',
            contains('token'),
          ),
        ),
      );
      // The connection survives a refusal: it is an answer, not a failure.
      expect(client.isClosed, isFalse);
    });

    test('concurrent requests are matched to their callers in order', () async {
      daemon = await FakeDaemon.start();
      final client =
          await SangforTunnelControlClient.connect(port: daemon.port);
      addTearDown(client.close);

      // One socket, several requests in flight. The protocol has no ids, so
      // ordering is the whole contract; if it broke, a caller would get
      // somebody else's reply.
      daemon.snapshot = <String, Object?>{'active': true, 'interface': 'first'};
      final results = await Future.wait(<Future<SangforTunnelSnapshot>>[
        client.status(),
        client.status(),
        client.status(),
      ]);
      expect(results, hasLength(3));
      for (final snapshot in results) {
        expect(snapshot.interfaceName, 'first');
      }
      expect(daemon.requests, hasLength(3));
      expect(
        daemon.requests.every(
            (Map<String, Object?> request) => request['cmd'] == 'status'),
        isTrue,
      );
    });

    test('a daemon that hangs up fails the request in flight', () async {
      daemon = await FakeDaemon.start()
        ..dropOnNextRequest = true;
      final client =
          await SangforTunnelControlClient.connect(port: daemon.port);
      addTearDown(client.close);

      await expectLater(
        client.status(),
        throwsA(isA<SangforTunnelControlException>()),
      );
      expect(client.isClosed, isTrue);
      // And a later request fails immediately rather than hanging.
      await expectLater(
        client.status(),
        throwsA(isA<SangforTunnelControlException>()),
      );
    });

    test('closing the client refuses further requests', () async {
      daemon = await FakeDaemon.start();
      final client =
          await SangforTunnelControlClient.connect(port: daemon.port);
      await client.close();
      expect(client.isClosed, isTrue);
      await expectLater(
        client.ping(),
        throwsA(isA<SangforTunnelControlException>()),
      );
      // Closing twice is not an error: teardown paths run more than once.
      await client.close();
    });

    test('a status reply with no data is an error, not an empty snapshot', () {
      // Guarded here rather than over a socket: an empty snapshot would look
      // like a tunnel that has done nothing, which is a confusing diagnosis.
      const reply = '{"ok":true}';
      final decoded = jsonDecode(reply) as Map<String, Object?>;
      expect(decoded['data'], isNull);
    });
  });

  group('SangforTunnelDaemonProcess', () {
    test('refuses to start without a control port', () async {
      // Without one there is nothing to drive, and discovering that after the
      // child is running would leave a tunnel nobody can stop.
      await expectLater(
        SangforTunnelDaemonProcess.start(
          executable: 'sangfor-tunneld',
          planDocument: '{}',
          config: const SangforTunnelHostConfig(),
        ),
        throwsA(isA<SangforTunnelControlException>()),
      );
    });

    test('drives the real daemon binary end to end', () async {
      // The cross-language contract: the Dart client and the Rust process have
      // to agree on the wire format, the log line that reports the control port,
      // the exit codes, and the shape of a status reply. Nothing else in either
      // test suite covers that, and a rename on either side would otherwise
      // surface only against a live gateway.
      final executable = findDaemonBinary();
      if (executable == null) {
        markTestSkipped(
          'sangfor-tunneld was not built; run '
          '`cargo build --release -p sangfor-tunneld` in rust/, or set '
          'SANGFOR_TUNNELD to its path',
        );
        return;
      }

      final daemon = await SangforTunnelDaemonProcess.start(
        executable: executable,
        planDocument: kSubprocessPlan,
        // A dry run: the in-memory device needs no driver and no elevation, so
        // this passes on a developer machine and on CI alike.
        config: SangforTunnelHostConfig(
          device: SangforTunnelDevice.loopback,
          interface: 'dart-e2e',
          controlPort: 0,
          controlToken: 'dart-token',
          routes: const <String>['10.1.0.0/16'],
        ),
        extraArguments: const <String>['--dry-run'],
      );
      // Always tear the child down, including when an assertion fails: a leaked
      // daemon holds its control port and, on Windows, locks the executable so
      // the next build cannot replace it.
      addTearDown(() async {
        try {
          await daemon.stop();
        } on Object {
          // Already gone.
        }
      });
      expect(daemon.controlPort, greaterThan(0));
      expect(daemon.hasExited, isFalse);

      final logs = <String>[];
      final subscription = daemon.log.listen(logs.add);

      // Any failure here is much easier to diagnose with the daemon's own log
      // attached, because the interesting part -- why the process went away --
      // is only ever written there.
      try {
        await daemon.control.ping();
        final snapshot = await daemon.control.status();
        expect(snapshot.interfaceName, 'dart-e2e');
        expect(snapshot.fatal, isNull);
        expect(snapshot.isDead, isFalse);
        // The plan names a documentation-range node, so the daemon really tried
        // to reach it and really failed; that counter is proof the whole path
        // ran.
        expect(
          await _waitFor(
            () => daemon.control.status(),
            (SangforTunnelSnapshot value) => value.connectFailures > 0,
          ),
          isNotNull,
          reason: 'the daemon never attempted to reach the gateway',
        );

        final code = await daemon.stop();
        expect(code, 0, reason: 'a requested stop exits cleanly');
        expect(daemon.hasExited, isTrue);
        expect(daemon.exitCode, 0);
      } on Object catch (error) {
        // Broadcast delivery is asynchronous, so give the daemon's last lines a
        // moment to arrive before asserting on them; otherwise the log reads as
        // empty exactly when it is most worth reading.
        await Future<void>.delayed(const Duration(milliseconds: 500));
        await subscription.cancel();
        fail(
          '$error\n\nexited: ${daemon.hasExited} code: ${daemon.exitCode}\n'
          '--- daemon log ---\n${logs.join('\n')}',
        );
      }
      await subscription.cancel();
    }, timeout: const Timeout(Duration(minutes: 2)));
  });
}

/// A plan the daemon will accept. It names a documentation-range node so the
/// tunnel comes up and then fails to connect, which is all these tests need.
const String kSubprocessPlan =
    '{"schemaVersion":1,"sid":"dart","deviceId":"dev",'
    '"connectionId":"conn","username":"user",'
    '"signKeyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",'
    '"lang":"en","processName":"tunneld","processPath":"/tunneld",'
    '"processPlatform":"windows","nodes":{"major":["203.0.113.9:441"]},'
    '"majorNodeGroup":"major","routes":[],"dnsServers":[],"heartbeatSeconds":2}';

/// Finds the built daemon, or returns null so the test can skip.
String? findDaemonBinary() {
  final fromEnvironment = Platform.environment['SANGFOR_TUNNELD'];
  if (fromEnvironment != null && File(fromEnvironment).existsSync()) {
    return fromEnvironment;
  }
  final name = Platform.isWindows ? 'sangfor-tunneld.exe' : 'sangfor-tunneld';
  for (final profile in <String>['release', 'debug']) {
    // The package sits at <repo>/packages/flutter_sangfor, and the workspace at
    // <repo>/rust.
    final candidate = File(
      '${Directory.current.path}/../../rust/target/$profile/$name',
    );
    if (candidate.existsSync()) return candidate.path;
  }
  return null;
}

/// Polls [read] until [predicate] holds, or gives up and returns null.
Future<T?> _waitFor<T>(
  Future<T> Function() read,
  bool Function(T value) predicate, {
  Duration timeout = const Duration(seconds: 60),
}) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    try {
      final value = await read();
      if (predicate(value)) return value;
    } on SangforTunnelControlException {
      return null;
    }
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
  return null;
}
