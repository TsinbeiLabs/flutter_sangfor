import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_sangfor/flutter_sangfor_platform_interface.dart';
import 'package:flutter_sangfor/flutter_sangfor_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockFlutterSangforPlatform
    with MockPlatformInterfaceMixin
    implements FlutterSangforPlatform {
  @override
  Future<SangforSession> connect({
    required Uri server,
    required String username,
    required String password,
    String? loginDomain,
    SangforAuthType authType = SangforAuthType.password,
  }) async =>
      const SangforSession(state: SangforConnectionState.connected);

  @override
  Future<void> disconnect() async {}

  @override
  Future<SangforConnectionState> getState() async =>
      SangforConnectionState.connected;

  @override
  Future<SangforPlatformCapabilities> getCapabilities() async =>
      const SangforPlatformCapabilities(platform: 'test');
}

void main() {
  final FlutterSangforPlatform initialPlatform =
      FlutterSangforPlatform.instance;

  test('$MethodChannelFlutterSangfor is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelFlutterSangfor>());
  });

  test('getState', () async {
    FlutterSangfor flutterSangforPlugin = FlutterSangfor();
    MockFlutterSangforPlatform fakePlatform = MockFlutterSangforPlatform();
    FlutterSangforPlatform.instance = fakePlatform;

    expect(await flutterSangforPlugin.getState(),
        SangforConnectionState.connected);
  });

  test('client emits lifecycle events around connector calls', () async {
    final client = SangforClient(
      connector: FakeConnectorForEvents(),
    );
    final events = <SangforConnectionEvent>[];
    final subscription = client.events.listen(events.add);

    await client.connect(
      SangforConnectOptions(
        server: Uri.parse('https://vpn.example.test'),
        username: 'user',
        password: 'password',
      ),
    );
    await Future<void>.delayed(Duration.zero);
    expect(events.map((event) => event.state), <SangforConnectionState>[
      SangforConnectionState.connecting,
      SangforConnectionState.connected,
    ]);

    await subscription.cancel();
    await client.dispose();
  });

  test('client validates options before reaching the connector', () async {
    final connector = RecordingConnector();
    final client = SangforClient(connector: connector);
    await expectLater(
      client.connect(
        SangforConnectOptions(
          server: Uri.parse('http://vpn.example.test'),
          username: 'user',
          password: 'password',
        ),
      ),
      throwsA(isA<SangforException>()),
    );
    expect(connector.invoked, isFalse);
    await client.dispose();
  });

  test('dry-run sessions flow through the client without network access',
      () async {
    final client = SangforClient(
      connector: DryRunConnector(),
    );
    final session = await client.connect(
      SangforConnectOptions(
        server: Uri.parse('https://vpn.example.test'),
        username: 'user',
        password: 'password',
        dryRun: true,
      ),
    );
    expect(session.state, SangforConnectionState.authenticated);
    expect(session.dryRun, isTrue);
    await client.dispose();
  });
}

class RecordingConnector implements SangforConnector {
  bool invoked = false;

  @override
  SangforProduct get product => SangforProduct.atrust;

  @override
  Future<SangforSession> connect(SangforConnectOptions options) async {
    invoked = true;
    return const SangforSession(state: SangforConnectionState.connected);
  }

  @override
  Future<void> disconnect() async {}

  @override
  Future<SangforConnectionState> getState() async =>
      SangforConnectionState.connected;

  @override
  Future<SangforPlatformCapabilities> getCapabilities() async =>
      const SangforPlatformCapabilities(platform: 'test');
}

class DryRunConnector implements SangforConnector {
  @override
  SangforProduct get product => SangforProduct.atrust;

  @override
  Future<SangforSession> connect(SangforConnectOptions options) async {
    if (options.dryRun) {
      return const SangforSession(
        state: SangforConnectionState.authenticated,
        dryRun: true,
      );
    }
    throw StateError('Dry-run connector must not perform network I/O');
  }

  @override
  Future<void> disconnect() async {}

  @override
  Future<SangforConnectionState> getState() async =>
      SangforConnectionState.disconnected;

  @override
  Future<SangforPlatformCapabilities> getCapabilities() async =>
      const SangforPlatformCapabilities(platform: 'test');
}

class FakeConnectorForEvents implements SangforConnector {
  @override
  SangforProduct get product => SangforProduct.atrust;

  @override
  Future<SangforSession> connect(SangforConnectOptions options) async =>
      const SangforSession(state: SangforConnectionState.connected);

  @override
  Future<void> disconnect() async {}

  @override
  Future<SangforConnectionState> getState() async =>
      SangforConnectionState.connected;

  @override
  Future<SangforPlatformCapabilities> getCapabilities() async =>
      const SangforPlatformCapabilities(platform: 'test');
}
