import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_test/flutter_test.dart';

/// Records every write and replays a canned configuration.
class FakeProxyStore implements SangforSystemProxyStore {
  FakeProxyStore({
    this.initial,
    this.acceptWrites = true,
    this.needsPrivileges = false,
    this.throwOnWrite = false,
  });

  final SangforSystemProxySettings? initial;
  final bool acceptWrites;
  final bool needsPrivileges;
  final bool throwOnWrite;
  final List<SangforSystemProxySettings> writes =
      <SangforSystemProxySettings>[];
  int reads = 0;

  @override
  bool get lastFailureNeedsPrivileges => needsPrivileges;

  @override
  Future<SangforSystemProxySettings?> read() async {
    reads++;
    return initial;
  }

  @override
  Future<bool> write(SangforSystemProxySettings settings) async {
    if (throwOnWrite) throw StateError('registry is locked');
    writes.add(settings);
    return acceptWrites;
  }
}

/// Scripts `networksetup` output per argument list.
class ScriptedRunner {
  ScriptedRunner(this.responses);

  final Map<String, SangforProcessOutcome> responses;
  final List<List<String>> calls = <List<String>>[];

  Future<SangforProcessOutcome> call(
    String executable,
    List<String> arguments,
  ) async {
    calls.add(arguments);
    return responses[arguments.join(' ')] ??
        const SangforProcessOutcome(0, '', '');
  }
}

void main() {
  const servicesOutput =
      'An asterisk (*) denotes that a network service is disabled.\n'
      'Wi-Fi\n'
      'USB 10/100/1000 LAN\n'
      '*Thunderbolt Bridge\n';

  group('SangforSystemProxy', () {
    test('an injected store is used on any platform', () async {
      for (final platform in ['linux', 'android', 'ios', 'fuchsia']) {
        final proxy = SangforSystemProxy(
          store: FakeProxyStore(),
          operatingSystem: platform,
        );
        expect(
          (await proxy.apply(port: 8080)).status,
          SangforSystemProxyStatus.applied,
          reason: platform,
        );
      }
    });

    test('without a store, only windows and macos are supported', () {
      expect(
          SangforSystemProxy(operatingSystem: 'windows').isSupported, isTrue);
      expect(SangforSystemProxy(operatingSystem: 'macos').isSupported, isTrue);
      for (final platform in ['linux', 'android', 'ios', 'fuchsia']) {
        expect(
            SangforSystemProxy(operatingSystem: platform).isSupported, isFalse,
            reason: platform);
      }
    });

    test('an unsupported platform refuses to apply and to clear', () async {
      final proxy = SangforSystemProxy(operatingSystem: 'linux');
      expect((await proxy.apply(port: 8080)).status,
          SangforSystemProxyStatus.unsupported);
      expect(
          (await proxy.clear()).status, SangforSystemProxyStatus.unsupported);
    });

    test('rejects an unusable endpoint', () async {
      final store = FakeProxyStore();
      final proxy = SangforSystemProxy(store: store, operatingSystem: 'linux');
      for (final port in [0, -1, 65536]) {
        expect((await proxy.apply(port: port)).status,
            SangforSystemProxyStatus.failed,
            reason: 'port $port');
      }
      expect(
        (await proxy.apply(port: 8080, host: '  ')).status,
        SangforSystemProxyStatus.failed,
      );
      expect(store.writes, isEmpty);
    });

    test('writes the loopback proxy and restores the previous settings',
        () async {
      final store = FakeProxyStore(
        initial: const SangforSystemProxySettings(
          enabled: true,
          server: 'proxy.corp.example:3128',
          bypass: ['intranet'],
        ),
      );
      final proxy = SangforSystemProxy(store: store, operatingSystem: 'linux');

      final applied = await proxy.apply(port: 41237);
      expect(applied.status, SangforSystemProxyStatus.applied);
      expect(store.writes.single.enabled, isTrue);
      expect(store.writes.single.server, '127.0.0.1:41237');
      expect(store.writes.single.bypass, ['localhost', '127.*', '<local>']);

      // A second apply must not overwrite the saved snapshot with our own.
      await proxy.apply(port: 41238);
      expect(store.writes, hasLength(2));
      expect(store.writes.last.server, '127.0.0.1:41238');
      expect(store.reads, 1);

      final cleared = await proxy.clear();
      expect(cleared.status, SangforSystemProxyStatus.restored);
      expect(store.writes.last.enabled, isTrue);
      expect(store.writes.last.server, 'proxy.corp.example:3128');
      expect(store.writes.last.bypass, ['intranet']);
    });

    test('restores a disabled proxy when there was none', () async {
      final store = FakeProxyStore();
      final proxy = SangforSystemProxy(store: store, operatingSystem: 'linux');
      await proxy.apply(port: 1080);
      await proxy.clear();
      expect(store.writes.last.enabled, isFalse);
      expect(store.writes.last.server, isNull);
    });

    test('clearing without applying is a no-op', () async {
      final store = FakeProxyStore();
      final proxy = SangforSystemProxy(store: store, operatingSystem: 'linux');
      final result = await proxy.clear();
      expect(result.status, SangforSystemProxyStatus.restored);
      expect(store.writes, isEmpty);
      expect(store.reads, 0);
    });

    test('surfaces a privilege refusal', () async {
      final store = FakeProxyStore(
        acceptWrites: false,
        needsPrivileges: true,
      );
      final proxy = SangforSystemProxy(store: store, operatingSystem: 'linux');
      final result = await proxy.apply(port: 8080);
      expect(result.status, SangforSystemProxyStatus.needsPrivileges);
      expect(result.isSuccess, isFalse);
    });

    test('surfaces a plain refusal and a throwing store', () async {
      final refused = SangforSystemProxy(
        store: FakeProxyStore(acceptWrites: false),
        operatingSystem: 'linux',
      );
      expect((await refused.apply(port: 8080)).status,
          SangforSystemProxyStatus.failed);

      final throwing = SangforSystemProxy(
        store: FakeProxyStore(throwOnWrite: true),
        operatingSystem: 'linux',
      );
      final result = await throwing.apply(port: 8080);
      expect(result.status, SangforSystemProxyStatus.failed);
      expect(result.message, contains('registry is locked'));
    });
  });

  group('MacosSystemProxyStore', () {
    test('lists services, dropping the header and the disabled marker',
        () async {
      final runner = ScriptedRunner({
        '-listallnetworkservices':
            const SangforProcessOutcome(0, servicesOutput, ''),
      });
      final store = MacosSystemProxyStore(runner: runner.call);
      expect(await store.services(),
          ['Wi-Fi', 'USB 10/100/1000 LAN', 'Thunderbolt Bridge']);
      // Cached: no second invocation.
      await store.services();
      expect(
        runner.calls.where((call) => call.first == '-listallnetworkservices'),
        hasLength(1),
      );
    });

    test('reads the first service that has a proxy configured', () async {
      final runner = ScriptedRunner({
        '-listallnetworkservices':
            const SangforProcessOutcome(0, servicesOutput, ''),
        '-getwebproxy Wi-Fi': const SangforProcessOutcome(
          0,
          'Enabled: Yes\nServer: 127.0.0.1\nPort: 8080\n',
          '',
        ),
        '-getsecurewebproxy Wi-Fi': const SangforProcessOutcome(
          0,
          'Enabled: Yes\nServer: 127.0.0.1\nPort: 8080\n',
          '',
        ),
      });
      final store = MacosSystemProxyStore(runner: runner.call);
      final settings = await store.read();
      expect(settings?.enabled, isTrue);
      expect(settings?.server, '127.0.0.1:8080');
    });

    test('writes web, secure web, and bypass domains for every service',
        () async {
      final runner = ScriptedRunner({
        '-listallnetworkservices':
            const SangforProcessOutcome(0, 'Wi-Fi\n', ''),
      });
      final store = MacosSystemProxyStore(runner: runner.call);
      final ok = await store.write(const SangforSystemProxySettings(
        enabled: true,
        server: '127.0.0.1:41237',
        bypass: ['localhost', '127.0.0.1'],
      ));
      expect(ok, isTrue);
      expect(runner.calls, [
        ['-listallnetworkservices'],
        ['-setwebproxy', 'Wi-Fi', '127.0.0.1', '41237'],
        ['-setsecurewebproxy', 'Wi-Fi', '127.0.0.1', '41237'],
        ['-setproxybypassdomains', 'Wi-Fi', 'localhost', '127.0.0.1'],
      ]);
    });

    test('turns both proxies off when clearing', () async {
      final runner = ScriptedRunner({
        '-listallnetworkservices':
            const SangforProcessOutcome(0, 'Wi-Fi\n', ''),
      });
      final store = MacosSystemProxyStore(runner: runner.call);
      final ok = await store.write(const SangforSystemProxySettings());
      expect(ok, isTrue);
      expect(runner.calls, [
        ['-listallnetworkservices'],
        ['-setwebproxystate', 'Wi-Fi', 'off'],
        ['-setsecurewebproxystate', 'Wi-Fi', 'off'],
      ]);
    });

    test('reports an administrator refusal', () async {
      final runner = ScriptedRunner({
        '-listallnetworkservices':
            const SangforProcessOutcome(0, 'Wi-Fi\n', ''),
        '-setwebproxy Wi-Fi 127.0.0.1 8080': const SangforProcessOutcome(
          1,
          '',
          'You must be an administrator to change proxy settings.',
        ),
        '-setsecurewebproxy Wi-Fi 127.0.0.1 8080': const SangforProcessOutcome(
          1,
          '',
          'You must be an administrator to change proxy settings.',
        ),
      });
      final store = MacosSystemProxyStore(runner: runner.call);
      final ok = await store.write(const SangforSystemProxySettings(
        enabled: true,
        server: '127.0.0.1:8080',
      ));
      expect(ok, isFalse);
      expect(store.lastFailureNeedsPrivileges, isTrue);
    });

    test('a service list the tool refuses to print is a privilege failure',
        () async {
      final runner = ScriptedRunner({
        '-listallnetworkservices': const SangforProcessOutcome(
          1,
          '',
          'Operation not permitted',
        ),
      });
      final store = MacosSystemProxyStore(runner: runner.call);
      expect(
          await store.write(const SangforSystemProxySettings(
            enabled: true,
            server: '127.0.0.1:8080',
          )),
          isFalse);
      expect(store.lastFailureNeedsPrivileges, isTrue);
    });

    test('the proxy adapter maps a macOS refusal to needsPrivileges', () async {
      final runner = ScriptedRunner({
        '-listallnetworkservices':
            const SangforProcessOutcome(0, 'Wi-Fi\n', ''),
        '-setwebproxy Wi-Fi 127.0.0.1 8080': const SangforProcessOutcome(
          1,
          '',
          'Not authorized',
        ),
      });
      final proxy = SangforSystemProxy(
        store: MacosSystemProxyStore(runner: runner.call),
        operatingSystem: 'macos',
      );
      final result = await proxy.apply(port: 8080);
      expect(result.status, SangforSystemProxyStatus.needsPrivileges);
    });
  });

  group('WinINET helpers', () {
    test('splits a ProxyOverride value', () {
      expect(splitBypassList('localhost;127.*;<local>'),
          ['localhost', '127.*', '<local>']);
      expect(splitBypassList(''), isEmpty);
      expect(splitBypassList(null), isEmpty);
      expect(splitBypassList(' a ;; b '), ['a', 'b']);
    });

    test('exposes the documented value names', () {
      expect(WindowsSystemProxyStore.keyPath,
          r'Software\Microsoft\Windows\CurrentVersion\Internet Settings');
      expect(WindowsSystemProxyStore.enableValue, 'ProxyEnable');
      expect(WindowsSystemProxyStore.serverValue, 'ProxyServer');
      expect(WindowsSystemProxyStore.bypassValue, 'ProxyOverride');
    });
  });

  group('settings value type', () {
    test('isProxying requires an enabled server', () {
      expect(const SangforSystemProxySettings().isProxying, isFalse);
      expect(
        const SangforSystemProxySettings(enabled: true, server: '').isProxying,
        isFalse,
      );
      expect(
        const SangforSystemProxySettings(
          enabled: true,
          server: '127.0.0.1:8080',
        ).isProxying,
        isTrue,
      );
    });

    test('equality covers every field', () {
      const a = SangforSystemProxySettings(
        enabled: true,
        server: 'h:1',
        bypass: ['x'],
      );
      expect(a, a.copyWith());
      expect(a == a.copyWith(bypass: ['y']), isFalse);
      expect(a == a.copyWith(server: 'h:2'), isFalse);
      expect(a == a.copyWith(enabled: false), isFalse);
      expect(a.hashCode, a.copyWith().hashCode);
    });
  });
}
