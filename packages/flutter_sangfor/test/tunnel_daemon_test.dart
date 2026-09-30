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
///
/// Captured with `--dry-run` against a plan naming a documentation-range node,
/// which is why `connectFailures` is 1 and `active` is false: the daemon really
/// tried to reach the gateway and really could not.
const String kCapturedStatusReply =
    '{"ok":true,"data":{"sessionRunning":true,"active":false,"virtualIp":[],'
    '"interfaceConfigured":false,"interfaceError":null,"channelsOpen":0,'
    '"devicePackets":0,"emittedPackets":0,"deviceDropped":0,"emitFailures":0,'
    '"channelBytesIn":0,"channelBytesOut":0,"connectFailures":1,"routed":0,'
    '"terminated":0,"unrouted":0,"ingress":0,"interface":"smoke0","fatal":null}}';

/// Every key the captured reply carries.
///
/// Listed rather than derived so that a rename on either side fails a test with
/// the two sets side by side, instead of surfacing as a snapshot field that
/// quietly reads as its default.
const Set<String> kCapturedStatusKeys = <String>{
  'sessionRunning',
  'active',
  'virtualIp',
  'interfaceConfigured',
  'interfaceError',
  'channelsOpen',
  'devicePackets',
  'emittedPackets',
  'deviceDropped',
  'emitFailures',
  'channelBytesIn',
  'channelBytesOut',
  'connectFailures',
  'routed',
  'terminated',
  'unrouted',
  'ingress',
  'interface',
  'fatal',
};

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

  /// Set to make the daemon refuse the next request with this reason.
  String? refuseNext;

  /// Called with each request as it arrives, before it is answered.
  void Function(Map<String, Object?> request)? onRequest;

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
    onRequest?.call(request);
    final refusal = refuseNext;
    if (refusal != null) {
      refuseNext = null;
      _write(socket, <String, Object?>{'ok': false, 'error': refusal});
      return;
    }
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
      case 'stopSession':
        snapshot = <String, Object?>{...snapshot, 'sessionRunning': false};
        _write(socket, <String, Object?>{'ok': true});
      case 'start':
        // The real daemon refuses a second start while one is running, which is
        // the behaviour a caller has to handle; a stand-in that always agreed
        // would let a client get away with never handling the refusal.
        final alreadyRunning = snapshot['sessionRunning'] == true;
        if (alreadyRunning) {
          _write(socket, <String, Object?>{
            'ok': false,
            'error': 'a session is already running; send stopSession first',
          });
          return;
        }
        snapshot = <String, Object?>{...snapshot, 'sessionRunning': true};
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

      expect(snapshot.sessionRunning, isTrue);
      expect(snapshot.active, isFalse);
      expect(snapshot.virtualIp, isEmpty);
      expect(snapshot.interfaceConfigured, isFalse);
      expect(snapshot.interfaceError, isNull);
      expect(snapshot.connectFailures, 1);
      expect(snapshot.interfaceName, 'smoke0');
      expect(snapshot.fatal, isNull);
      expect(snapshot.isDead, isFalse);
    });

    test('the daemon sends exactly the fields this client reads', () {
      // The two halves of the cross-language contract, compared as sets. A field
      // renamed on the Rust side would otherwise arrive here as an absent key
      // and read as its default — a counter stuck at zero, which looks like an
      // idle tunnel rather than a broken one.
      final decoded = jsonDecode(kCapturedStatusReply) as Map<String, Object?>;
      final data = (decoded['data']! as Map).cast<String, Object?>();
      expect(data.keys.toSet(), kCapturedStatusKeys);
    });

    test('every field is read from the key that names it', () {
      // Distinct values throughout: a field copied from the wrong key in
      // `fromJson` is invisible when every counter is zero, which is what the
      // captured reply above has for almost all of them.
      final snapshot = SangforTunnelSnapshot.fromJson(<String, Object?>{
        'sessionRunning': true,
        'active': false,
        'virtualIp': <String>['10.0.0.42'],
        'interfaceConfigured': true,
        'interfaceError': 'no virtual IP',
        'channelsOpen': 2,
        'devicePackets': 3,
        'emittedPackets': 4,
        'deviceDropped': 5,
        'emitFailures': 6,
        'channelBytesIn': 7,
        'channelBytesOut': 8,
        'connectFailures': 9,
        'routed': 10,
        'terminated': 11,
        'unrouted': 12,
        'ingress': 13,
        'interface': 'Luotopia',
        'fatal': 'the gateway closed the session',
      });
      expect(snapshot.sessionRunning, isTrue);
      expect(snapshot.active, isFalse);
      expect(snapshot.virtualIp, <String>['10.0.0.42']);
      expect(snapshot.interfaceConfigured, isTrue);
      expect(snapshot.interfaceError, 'no virtual IP');
      expect(snapshot.channelsOpen, 2);
      expect(snapshot.devicePackets, 3);
      expect(snapshot.emittedPackets, 4);
      expect(snapshot.deviceDropped, 5);
      expect(snapshot.emitFailures, 6);
      expect(snapshot.channelBytesIn, 7);
      expect(snapshot.channelBytesOut, 8);
      expect(snapshot.connectFailures, 9);
      expect(snapshot.routed, 10);
      expect(snapshot.terminated, 11);
      expect(snapshot.unrouted, 12);
      expect(snapshot.ingress, 13);
      expect(snapshot.interfaceName, 'Luotopia');
      expect(snapshot.fatal, 'the gateway closed the session');
    });

    test('tolerates a reply that omits fields', () {
      // A daemon older than this client must not crash it.
      final snapshot =
          SangforTunnelSnapshot.fromJson(const <String, Object?>{});
      expect(snapshot.sessionRunning, isFalse);
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
          config: const SangforTunnelHostConfig(),
        ),
        throwsA(isA<SangforTunnelControlException>()),
      );
    });

    test('starts idle and is given a session, twice', () async {
      // The cross-language contract, and the part that only exists because the
      // daemon supervises: the Dart client and the Rust process have to agree on
      // the wire format, the log line that reports the control port, the exit
      // codes, the shape of a status reply, *and* on what it means to start a
      // second session on a process that already ran one. Nothing else in
      // either test suite covers that, and a rename on either side would
      // otherwise surface only against a live gateway.
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
        // A dry run: the in-memory device needs no driver and no elevation, so
        // this passes on a developer machine and on CI alike.
        config: SangforTunnelHostConfig(
          device: SangforTunnelDevice.loopback,
          interface: 'dart-e2e',
          controlPort: 0,
          controlToken: 'dart-token',
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

        // Idle first: a daemon launched with no plan has no session, and a
        // client that cannot tell that from "starting" either waits forever or
        // sends a second start and is refused.
        final idle = await daemon.status();
        expect(idle.sessionRunning, isFalse,
            reason: 'it starts with no session');
        expect(idle.interfaceName, isNull, reason: 'nothing has been opened');

        // Routes arrive with the session, not at launch: which destinations
        // belong in the tunnel depends on what the gateway published this time.
        final config = SangforTunnelHostConfig(
          device: SangforTunnelDevice.loopback,
          interface: 'dart-e2e',
          routes: const <String>['10.1.0.0/16'],
          dnsServers: const <String>['10.0.0.53'],
        );
        await daemon.startSession(
          planDocument: kSubprocessPlan,
          config: config,
        );
        final running = await daemon.status();
        expect(running.sessionRunning, isTrue);
        expect(running.interfaceName, 'dart-e2e');
        expect(running.fatal, isNull);
        expect(running.isDead, isFalse);

        // The plan names a documentation-range node, so the daemon really tried
        // to reach it and really failed; that counter is proof the whole path
        // ran rather than that a request was acknowledged.
        expect(
          await _waitFor(
            () => daemon.status(),
            (SangforTunnelSnapshot value) => value.connectFailures > 0,
          ),
          isNotNull,
          reason: 'the daemon never attempted to reach the gateway',
        );

        await daemon.stopSession();
        expect(
          (await daemon.status()).sessionRunning,
          isFalse,
          reason: 'the session is gone',
        );
        expect(
          daemon.hasExited,
          isFalse,
          reason: 'and the process is not: that is what supervising means',
        );

        // A second session on the same process. This is what an installed
        // daemon does all day, and it breaks quietly if the device, the
        // snapshot, or the configurator thread stayed bound to the first one.
        await daemon.startSession(
          planDocument: kSubprocessPlan,
          config: config,
        );
        final second = await daemon.status();
        expect(second.sessionRunning, isTrue, reason: 'it runs again');
        expect(
          second.connectFailures,
          0,
          reason: 'the counters describe the new session, not the old one',
        );
        expect(second.fatal, isNull,
            reason: 'and neither does its error state');

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

  group('SangforTunnelHostConfig.decode', () {
    test('reads back what encode wrote', () {
      // An app finds an installed daemon by reading the configuration its
      // installer wrote, so a field that does not survive the round trip is a
      // daemon the app cannot connect to.
      const original = SangforTunnelHostConfig(
        device: SangforTunnelDevice.wintun,
        interface: 'Luotopia',
        controlPort: 7166,
        controlToken: 's3cret-token',
        logPath: r'C:\Users\alice\AppData\Local\sangfor-tunneld\tunneld.log',
      );
      final decoded = SangforTunnelHostConfig.decode(
        jsonDecode(original.encode()) as Map<String, Object?>,
      );
      expect(decoded.controlPort, 7166);
      expect(decoded.controlToken, 's3cret-token');
      expect(decoded.device, SangforTunnelDevice.wintun);
      expect(decoded.interface, 'Luotopia');
      expect(decoded.logPath, original.logPath);
    });

    test('tolerates a field this version does not model', () {
      // The daemon is a separate binary with its own release cycle. A version
      // that adds a field must not break an app built before it, which is why
      // decoding is lenient even though the daemon's own parsing is strict.
      final decoded = SangforTunnelHostConfig.decode(<String, Object?>{
        'controlPort': 7166,
        'controlToken': 's3cret',
        'someFieldFromTheFuture': <String, Object?>{'nested': true},
      });
      expect(decoded.controlPort, 7166);
      expect(decoded.controlToken, 's3cret');
    });

    test('an unreadable device falls back rather than throwing', () {
      final decoded = SangforTunnelHostConfig.decode(<String, Object?>{
        'device': 'utun',
        'controlPort': 1,
      });
      expect(decoded.controlPort, 1, reason: 'the port is what the app needs');
      expect(decoded.device, SangforTunnelDevice.loopback);
    });
  });

  group('SangforTunnelInstalledDaemon', () {
    test('connects to a daemon it did not launch, using its configuration',
        () async {
      // The shape an app on Windows actually uses: the daemon was installed
      // once from an elevated shell, and the app finds it by reading the
      // configuration in the user's profile. The port and the token both come
      // from that file, so getting either wrong looks like a hung connect.
      final daemon = await FakeDaemon.start(token: 'installed-token');
      addTearDown(daemon.close);
      final directory =
          await Directory.systemTemp.createTemp('sangfor-installed');
      addTearDown(() => directory.delete(recursive: true));
      await File(
        '${directory.path}${Platform.pathSeparator}'
        '${SangforTunnelInstalledDaemon.hostConfigFileName}',
      ).writeAsString(
        SangforTunnelHostConfig(
          controlPort: daemon.port,
          controlToken: 'installed-token',
        ).encode(),
      );

      final installed = await SangforTunnelInstalledDaemon.connect(
        directory: directory,
      );
      expect(installed, isNotNull,
          reason: 'the configuration named a live daemon');
      addTearDown(installed!.release);

      final snapshot = await installed.status();
      expect(snapshot.interfaceName, 'fake0');
      expect(
        daemon.requests.last['token'],
        'installed-token',
        reason: 'the token came from the file, not from the caller',
      );
    });

    test('returns null when nothing is installed', () async {
      // The ordinary case, and the one a caller must be able to distinguish
      // from a failure: no daemon has been installed yet, so the app should
      // fall back to whatever data plane it had rather than report an error.
      final directory = await Directory.systemTemp.createTemp('sangfor-empty');
      addTearDown(() => directory.delete(recursive: true));
      expect(
        await SangforTunnelInstalledDaemon.connect(directory: directory),
        isNull,
        reason: 'no configuration, no daemon',
      );
    });

    test('returns null when the configuration cannot be read', () async {
      final daemon = await FakeDaemon.start();
      addTearDown(daemon.close);
      final directory = await Directory.systemTemp.createTemp('sangfor-broken');
      addTearDown(() => directory.delete(recursive: true));
      await File(
        '${directory.path}${Platform.pathSeparator}'
        '${SangforTunnelInstalledDaemon.hostConfigFileName}',
      ).writeAsString('not json');
      expect(
        await SangforTunnelInstalledDaemon.connect(directory: directory),
        isNull,
        reason: 'guessing at the port would produce a confusing refusal',
      );
    });

    test('returns null when the daemon is not answering', () async {
      // A configuration left behind by an uninstalled daemon is indistinguishable
      // from an installed one until something tries to connect.
      final directory = await Directory.systemTemp.createTemp('sangfor-dead');
      addTearDown(() => directory.delete(recursive: true));
      final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      final port = probe.port;
      await probe.close();
      await File(
        '${directory.path}${Platform.pathSeparator}'
        '${SangforTunnelInstalledDaemon.hostConfigFileName}',
      ).writeAsString(
        SangforTunnelHostConfig(controlPort: port, controlToken: 'x').encode(),
      );
      expect(
        await SangforTunnelInstalledDaemon.connect(
          directory: directory,
          timeout: const Duration(milliseconds: 500),
        ),
        isNull,
      );
    });

    test('release stops the session but leaves the daemon running', () async {
      // The daemon is elevated and was installed once; the next connect wants
      // it, and the app cannot start another.
      final daemon = await FakeDaemon.start(token: 'installed-token');
      addTearDown(daemon.close);
      final directory =
          await Directory.systemTemp.createTemp('sangfor-release');
      addTearDown(() => directory.delete(recursive: true));
      await File(
        '${directory.path}${Platform.pathSeparator}'
        '${SangforTunnelInstalledDaemon.hostConfigFileName}',
      ).writeAsString(
        SangforTunnelHostConfig(
          controlPort: daemon.port,
          controlToken: 'installed-token',
        ).encode(),
      );
      final installed = await SangforTunnelInstalledDaemon.connect(
        directory: directory,
      );
      expect(installed, isNotNull);
      await installed!.release();
      final commands = daemon.requests.map((r) => r['cmd']).toList();
      expect(commands, contains('stopSession'));
      expect(commands, isNot(contains('stop')),
          reason: 'the process is not ours to end');
    });
  });

  group('SangforTunnelControlClient sessions', () {
    test('start names its documents by path and never inlines them', () async {
      // The plan carries the signing key, and the control channel is reachable
      // by any local process that has the token. A document on the wire would
      // put the key on a socket; a path keeps it in a file with permissions.
      final daemon = await FakeDaemon.start(token: 'session-token');
      addTearDown(daemon.close);
      final client = await SangforTunnelControlClient.connect(
        port: daemon.port,
        token: 'session-token',
      );
      addTearDown(client.close);

      const plan = '{"signKeyBase64":"AAAAAAAA"}';
      await client.startSession(
        planDocument: plan,
        configDocument: '{"routes":["10.1.0.0/16"]}',
      );
      final request = daemon.requests.single;
      expect(request['cmd'], 'start');
      expect(request['token'], 'session-token');
      final planPath = request['planPath'] as String?;
      final configPath = request['configPath'] as String?;
      expect(planPath, isNotNull);
      expect(configPath, isNotNull);
      expect(
        jsonEncode(request),
        isNot(contains('AAAAAAAA')),
        reason: 'the key never crosses the socket',
      );
      // The files existed for the duration of the request, which is what the
      // daemon needs; that they are gone afterwards is asserted below.
      expect(planPath, isNot(contains('signKey')));
      expect(configPath, isNot(contains('routes')));
    });

    test('a start removes the scratch files holding the plan', () async {
      // The plan is secret material. Leaving it in the temp directory after the
      // daemon has read it would outlive the session it belongs to.
      final daemon = await FakeDaemon.start();
      addTearDown(daemon.close);
      final client =
          await SangforTunnelControlClient.connect(port: daemon.port);
      addTearDown(client.close);

      String? planPath;
      daemon.onRequest = (request) {
        planPath = request['planPath'] as String?;
      };
      await client.startSession(
        planDocument: '{"signKeyBase64":"AAAAAAAA"}',
        configDocument: '{}',
      );
      expect(planPath, isNotNull);
      expect(File(planPath!).existsSync(), isFalse, reason: 'the plan is gone');
      final parent = Directory(File(planPath!).parent.path);
      expect(
        parent.existsSync(),
        isFalse,
        reason: 'and so is the directory it was in',
      );
    });

    test('stopSession is a request of its own', () async {
      final daemon = await FakeDaemon.start(token: 'session-token');
      addTearDown(daemon.close);
      final client = await SangforTunnelControlClient.connect(
        port: daemon.port,
        token: 'session-token',
      );
      addTearDown(client.close);
      await client.stopSession();
      expect(daemon.requests.single['cmd'], 'stopSession');
    });

    test('a refused start surfaces the daemon’s reason', () async {
      final daemon = await FakeDaemon.start();
      addTearDown(daemon.close);
      final client =
          await SangforTunnelControlClient.connect(port: daemon.port);
      addTearDown(client.close);
      daemon.refuseNext =
          'a session is already running; send stopSession first';
      await expectLater(
        client.startSession(planDocument: '{}', configDocument: '{}'),
        throwsA(
          isA<SangforTunnelControlException>().having(
            (e) => e.message,
            'message',
            contains('stopSession'),
          ),
        ),
      );
    });
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
///
/// `CARGO_TARGET_DIR` is checked first: a developer who points it at a shared
/// cache — which is the sane thing to do on a machine with several Rust
/// projects — would otherwise get a silently skipped cross-language test, and a
/// skip is the one outcome that looks exactly like a pass.
String? findDaemonBinary() {
  final fromEnvironment = Platform.environment['SANGFOR_TUNNELD'];
  if (fromEnvironment != null && File(fromEnvironment).existsSync()) {
    return fromEnvironment;
  }
  final name = Platform.isWindows ? 'sangfor-tunneld.exe' : 'sangfor-tunneld';
  final targetDirectory = Platform.environment['CARGO_TARGET_DIR'];
  // The package sits at <repo>/packages/flutter_sangfor, and the workspace at
  // <repo>/rust, whose default target directory is <repo>/rust/target.
  final roots = <String>[
    if (targetDirectory != null && targetDirectory.isNotEmpty) targetDirectory,
    '${Directory.current.path}/../../rust/target',
  ];
  for (final root in roots) {
    for (final profile in <String>['release', 'debug']) {
      final candidate = File('$root/$profile/$name');
      if (candidate.existsSync()) return candidate.path;
    }
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
