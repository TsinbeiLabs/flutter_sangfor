import 'dart:async';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

/// Outcome of a system-proxy operation.
enum SangforSystemProxyStatus {
  /// The proxy was written and the OS was notified.
  applied,

  /// The previous configuration was put back.
  restored,

  /// This platform has no OS-wide HTTP proxy this package can drive.
  /// Android advertises one through `VpnService.Builder.setHttpProxy` and
  /// iOS through `NEProxySettings`; both are handled by their own adapters.
  unsupported,

  /// The change needs privileges the process does not have (a non-elevated
  /// or sandboxed process on macOS).
  needsPrivileges,

  /// The platform rejected the change for another reason.
  failed,
}

/// Result of [SangforSystemProxy.apply] or [SangforSystemProxy.clear].
class SangforSystemProxyResult {
  const SangforSystemProxyResult(this.status, [this.message = '']);

  final SangforSystemProxyStatus status;
  final String message;

  bool get isSuccess =>
      status == SangforSystemProxyStatus.applied ||
      status == SangforSystemProxyStatus.restored;

  @override
  String toString() => 'SangforSystemProxyResult($status'
      '${message.isEmpty ? '' : ', $message'})';
}

/// An OS-wide HTTP proxy configuration. [server] is `host:port`.
class SangforSystemProxySettings {
  const SangforSystemProxySettings({
    this.enabled = false,
    this.server,
    this.bypass = const <String>[],
  });

  final bool enabled;
  final String? server;
  final List<String> bypass;

  bool get isProxying => enabled && server != null && server!.isNotEmpty;

  SangforSystemProxySettings copyWith({
    bool? enabled,
    String? server,
    List<String>? bypass,
  }) =>
      SangforSystemProxySettings(
        enabled: enabled ?? this.enabled,
        server: server ?? this.server,
        bypass: bypass ?? this.bypass,
      );

  @override
  bool operator ==(Object other) =>
      other is SangforSystemProxySettings &&
      other.enabled == enabled &&
      other.server == server &&
      _sameStrings(other.bypass, bypass);

  @override
  int get hashCode => Object.hash(enabled, server, Object.hashAll(bypass));

  @override
  String toString() => 'SangforSystemProxySettings($enabled, $server, $bypass)';

  static bool _sameStrings(List<String> left, List<String> right) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }
}

/// Reads and writes the OS-wide proxy configuration. Implementations exist
/// for Windows (WinINET keys under `HKCU`) and macOS (`networksetup`);
/// tests substitute a fake.
abstract class SangforSystemProxyStore {
  /// The current configuration, or null when it could not be read.
  Future<SangforSystemProxySettings?> read();

  /// Writes [settings] and notifies running clients. Returns false when the
  /// platform refused the change.
  Future<bool> write(SangforSystemProxySettings settings);

  /// True when a refused write means "not privileged enough".
  bool get lastFailureNeedsPrivileges => false;
}

/// Drives the operating system's HTTP proxy so every proxy-honoring
/// application sends its traffic through a local tunnel proxy.
///
/// Gateways such as aTrust publish many resources as TCP-tunnel-only, which a
/// raw L3 packet device cannot forward; pointing the OS at a loopback HTTP
/// proxy is what makes those resources reachable outside the tunnel owner's
/// own process. Android does the same through
/// `VpnService.Builder.setHttpProxy`, iOS through `NEProxySettings`.
///
/// The previous configuration is captured on the first [apply] and put back
/// by [clear], so an existing user proxy survives a tunnel session.
class SangforSystemProxy {
  SangforSystemProxy({SangforSystemProxyStore? store, String? operatingSystem})
      : _store = store,
        _operatingSystem = operatingSystem ?? Platform.operatingSystem;

  final SangforSystemProxyStore? _store;
  final String _operatingSystem;
  SangforSystemProxySettings? _saved;
  bool _applied = false;

  /// Whether this platform has an OS-wide proxy this class can drive.
  bool get isSupported => _resolveStore() != null;

  /// Points the OS at `host:port`. Idempotent: a second call with the same
  /// endpoint only rewrites the configuration, it does not overwrite the
  /// saved pre-tunnel snapshot.
  Future<SangforSystemProxyResult> apply({
    required int port,
    String host = '127.0.0.1',
    List<String> bypass = const <String>['localhost', '127.*', '<local>'],
  }) async {
    if (port <= 0 || port > 65535) {
      return SangforSystemProxyResult(
        SangforSystemProxyStatus.failed,
        'proxy port $port is out of range',
      );
    }
    final trimmedHost = host.trim();
    if (trimmedHost.isEmpty) {
      return const SangforSystemProxyResult(
        SangforSystemProxyStatus.failed,
        'proxy host must not be empty',
      );
    }
    final store = _resolveStore();
    if (store == null) {
      return SangforSystemProxyResult(
        SangforSystemProxyStatus.unsupported,
        'the $_operatingSystem system proxy is not supported by this adapter',
      );
    }
    try {
      if (!_applied) {
        _saved = await store.read();
      }
      final ok = await store.write(
        SangforSystemProxySettings(
          enabled: true,
          server: '$trimmedHost:$port',
          bypass: List<String>.of(bypass),
        ),
      );
      if (!ok) {
        return SangforSystemProxyResult(
          store.lastFailureNeedsPrivileges
              ? SangforSystemProxyStatus.needsPrivileges
              : SangforSystemProxyStatus.failed,
          'the operating system refused the proxy change',
        );
      }
      _applied = true;
      return const SangforSystemProxyResult(SangforSystemProxyStatus.applied);
    } on Object catch (error) {
      return SangforSystemProxyResult(
        SangforSystemProxyStatus.failed,
        '$error',
      );
    }
  }

  /// Restores whatever the OS had before the first [apply]. Safe to call when
  /// nothing was applied.
  Future<SangforSystemProxyResult> clear() async {
    final store = _resolveStore();
    if (store == null) {
      return SangforSystemProxyResult(
        SangforSystemProxyStatus.unsupported,
        'the $_operatingSystem system proxy is not supported by this adapter',
      );
    }
    if (!_applied) {
      return const SangforSystemProxyResult(SangforSystemProxyStatus.restored);
    }
    final previous = _saved;
    _applied = false;
    _saved = null;
    try {
      final ok = await store.write(
        previous ?? const SangforSystemProxySettings(),
      );
      if (!ok) {
        return SangforSystemProxyResult(
          store.lastFailureNeedsPrivileges
              ? SangforSystemProxyStatus.needsPrivileges
              : SangforSystemProxyStatus.failed,
          'the operating system refused to restore the proxy',
        );
      }
      return const SangforSystemProxyResult(SangforSystemProxyStatus.restored);
    } on Object catch (error) {
      return SangforSystemProxyResult(
        SangforSystemProxyStatus.failed,
        '$error',
      );
    }
  }

  SangforSystemProxyStore? _resolveStore() {
    if (_store != null) return _store;
    return switch (_operatingSystem) {
      'windows' => WindowsSystemProxyStore(),
      'macos' => MacosSystemProxyStore(),
      _ => null,
    };
  }

  /// The configuration captured before the first [apply]; null when this
  /// instance never applied one. Callers that persist it can undo a proxy
  /// their process did not survive to clear.
  SangforSystemProxySettings? get lastReadSettings => _saved;

  /// Reads the live OS configuration without touching the saved snapshot.
  Future<SangforSystemProxySettings?> readCurrent() async {
    final store = _resolveStore();
    if (store == null) return null;
    try {
      return await store.read();
    } on Object {
      return null;
    }
  }

  /// Writes [settings] verbatim, bypassing the save/restore bookkeeping. Use
  /// it to undo a proxy a previous run left behind after an unclean exit.
  Future<SangforSystemProxyResult> restore(
    SangforSystemProxySettings settings,
  ) async {
    final store = _resolveStore();
    if (store == null) {
      return SangforSystemProxyResult(
        SangforSystemProxyStatus.unsupported,
        'the $_operatingSystem system proxy is not supported by this adapter',
      );
    }
    try {
      final ok = await store.write(settings);
      if (!ok) {
        return SangforSystemProxyResult(
          store.lastFailureNeedsPrivileges
              ? SangforSystemProxyStatus.needsPrivileges
              : SangforSystemProxyStatus.failed,
          'the operating system refused the proxy change',
        );
      }
      return const SangforSystemProxyResult(SangforSystemProxyStatus.restored);
    } on Object catch (error) {
      return SangforSystemProxyResult(
        SangforSystemProxyStatus.failed,
        '$error',
      );
    }
  }
}

/// WinINET-backed store: the `Internet Settings` values under
/// `HKEY_CURRENT_USER`, which every WinINET/WinHTTP client (Edge, Chrome,
/// .NET, WinHTTP services) reads. No elevation is required because the keys
/// are per user.
class WindowsSystemProxyStore implements SangforSystemProxyStore {
  WindowsSystemProxyStore({DynamicLibrary? advapi32, DynamicLibrary? wininet})
      : _advapi32 = advapi32,
        _wininet = wininet;

  static const String keyPath =
      r'Software\Microsoft\Windows\CurrentVersion\Internet Settings';
  static const String enableValue = 'ProxyEnable';
  static const String serverValue = 'ProxyServer';
  static const String bypassValue = 'ProxyOverride';
  static const String autoConfigValue = 'AutoConfigURL';

  static const int _hkeyCurrentUser = 0x80000001;
  static const int _keyQueryValue = 0x0001;
  static const int _keySetValue = 0x0002;
  static const int _regDword = 4;
  static const int _regSz = 1;
  static const int _internetOptionSettingsChanged = 39;
  static const int _internetOptionRefresh = 37;

  final DynamicLibrary? _advapi32;
  final DynamicLibrary? _wininet;
  bool _needsPrivileges = false;

  @override
  bool get lastFailureNeedsPrivileges => _needsPrivileges;

  @override
  Future<SangforSystemProxySettings?> read() async {
    final registry = _advapi32 ?? DynamicLibrary.open('advapi32.dll');
    final hkey = calloc<Pointer<Void>>();
    final pathPtr = keyPath.toNativeUtf16();
    try {
      final opened = _regOpenKeyEx(registry)(
        Pointer<Void>.fromAddress(_hkeyCurrentUser),
        pathPtr,
        0,
        _keyQueryValue,
        hkey,
      );
      if (opened != 0) return null;
      final enabled = _readDword(registry, hkey.value, enableValue) ?? 0;
      final server = _readString(registry, hkey.value, serverValue);
      final bypass = _readString(registry, hkey.value, bypassValue);
      return SangforSystemProxySettings(
        enabled: enabled != 0,
        server: server,
        bypass: splitBypassList(bypass),
      );
    } finally {
      if (hkey.value != nullptr) {
        _regCloseKey(registry)(hkey.value);
      }
      calloc
        ..free(pathPtr)
        ..free(hkey);
    }
  }

  @override
  Future<bool> write(SangforSystemProxySettings settings) async {
    _needsPrivileges = false;
    final registry = _advapi32 ?? DynamicLibrary.open('advapi32.dll');
    final hkey = calloc<Pointer<Void>>();
    final pathPtr = keyPath.toNativeUtf16();
    try {
      final opened = _regOpenKeyEx(registry)(
        Pointer<Void>.fromAddress(_hkeyCurrentUser),
        pathPtr,
        0,
        _keyQueryValue | _keySetValue,
        hkey,
      );
      if (opened != 0) {
        _needsPrivileges = opened == 5;
        return false;
      }
      final ok = _writeDword(
            registry,
            hkey.value,
            enableValue,
            settings.enabled ? 1 : 0,
          ) &&
          _writeString(
            registry,
            hkey.value,
            serverValue,
            settings.server ?? '',
          ) &&
          _writeString(
            registry,
            hkey.value,
            bypassValue,
            settings.bypass.join(';'),
          );
      if (!ok) return false;
      // A PAC script left over from a previous session would outrank the
      // static proxy, so it is cleared while the tunnel owns the proxy.
      if (settings.enabled) {
        _deleteValue(registry, hkey.value, autoConfigValue);
      }
      _notifyClients();
      return true;
    } finally {
      if (hkey.value != nullptr) {
        _regCloseKey(registry)(hkey.value);
      }
      calloc
        ..free(pathPtr)
        ..free(hkey);
    }
  }

  void _notifyClients() {
    final DynamicLibrary internet;
    try {
      internet = _wininet ?? DynamicLibrary.open('wininet.dll');
    } on Object {
      return;
    }
    final setOption = internet.lookupFunction<
        Int32 Function(Pointer<Void>, Uint32, Pointer<Void>, Uint32),
        int Function(
            Pointer<Void>, int, Pointer<Void>, int)>('InternetSetOptionW');
    setOption(nullptr, _internetOptionSettingsChanged, nullptr, 0);
    setOption(nullptr, _internetOptionRefresh, nullptr, 0);
  }

  int? _readDword(DynamicLibrary registry, Pointer<Void> hkey, String name) {
    final data = calloc<Uint32>();
    final size = calloc<Uint32>()..value = 4;
    final namePtr = name.toNativeUtf16();
    try {
      final status = _regQueryValueEx(registry)(
        hkey,
        namePtr,
        nullptr,
        nullptr,
        data.cast<Uint8>(),
        size,
      );
      return status == 0 ? data.value : null;
    } finally {
      calloc
        ..free(namePtr)
        ..free(size)
        ..free(data);
    }
  }

  String? _readString(
      DynamicLibrary registry, Pointer<Void> hkey, String name) {
    final size = calloc<Uint32>()..value = 0;
    final namePtr = name.toNativeUtf16();
    try {
      final query = _regQueryValueEx(registry);
      final probe = query(hkey, namePtr, nullptr, nullptr, nullptr, size);
      if (probe != 0) return null;
      final bytes = size.value;
      if (bytes == 0) return '';
      final buffer = calloc<Uint8>(bytes);
      try {
        final status = query(hkey, namePtr, nullptr, nullptr, buffer, size);
        if (status != 0) return null;
        final utf16 = buffer.cast<Utf16>();
        return utf16.toDartString();
      } finally {
        calloc.free(buffer);
      }
    } finally {
      calloc
        ..free(namePtr)
        ..free(size);
    }
  }

  bool _writeDword(
    DynamicLibrary registry,
    Pointer<Void> hkey,
    String name,
    int value,
  ) {
    final data = calloc<Uint32>()..value = value;
    final namePtr = name.toNativeUtf16();
    try {
      return _regSetValueEx(registry)(
            hkey,
            namePtr,
            0,
            _regDword,
            data.cast<Uint8>(),
            4,
          ) ==
          0;
    } finally {
      calloc
        ..free(namePtr)
        ..free(data);
    }
  }

  bool _writeString(
    DynamicLibrary registry,
    Pointer<Void> hkey,
    String name,
    String value,
  ) {
    final data = value.toNativeUtf16();
    final namePtr = name.toNativeUtf16();
    try {
      final length = (value.length + 1) * sizeOf<Uint16>();
      return _regSetValueEx(registry)(
            hkey,
            namePtr,
            0,
            _regSz,
            data.cast<Uint8>(),
            length,
          ) ==
          0;
    } finally {
      calloc
        ..free(namePtr)
        ..free(data);
    }
  }

  void _deleteValue(DynamicLibrary registry, Pointer<Void> hkey, String name) {
    final namePtr = name.toNativeUtf16();
    try {
      final delete = registry.lookupFunction<
          Int32 Function(Pointer<Void>, Pointer<Utf16>),
          int Function(Pointer<Void>, Pointer<Utf16>)>('RegDeleteValueW');
      delete(hkey, namePtr);
    } on Object {
      // The value is usually absent; a failure here is not fatal.
    } finally {
      calloc.free(namePtr);
    }
  }

  static int Function(
          Pointer<Void>, Pointer<Utf16>, int, int, Pointer<Pointer<Void>>)
      _regOpenKeyEx(DynamicLibrary registry) => registry.lookupFunction<
          Int32 Function(
            Pointer<Void>,
            Pointer<Utf16>,
            Uint32,
            Uint32,
            Pointer<Pointer<Void>>,
          ),
          int Function(
            Pointer<Void>,
            Pointer<Utf16>,
            int,
            int,
            Pointer<Pointer<Void>>,
          )>('RegOpenKeyExW');

  static int Function(
    Pointer<Void>,
    Pointer<Utf16>,
    Pointer<Uint32>,
    Pointer<Uint32>,
    Pointer<Uint8>,
    Pointer<Uint32>,
  ) _regQueryValueEx(DynamicLibrary registry) => registry.lookupFunction<
      Int32 Function(
        Pointer<Void>,
        Pointer<Utf16>,
        Pointer<Uint32>,
        Pointer<Uint32>,
        Pointer<Uint8>,
        Pointer<Uint32>,
      ),
      int Function(
        Pointer<Void>,
        Pointer<Utf16>,
        Pointer<Uint32>,
        Pointer<Uint32>,
        Pointer<Uint8>,
        Pointer<Uint32>,
      )>('RegQueryValueExW');

  static int Function(
          Pointer<Void>, Pointer<Utf16>, int, int, Pointer<Uint8>, int)
      _regSetValueEx(DynamicLibrary registry) => registry.lookupFunction<
          Int32 Function(
            Pointer<Void>,
            Pointer<Utf16>,
            Uint32,
            Uint32,
            Pointer<Uint8>,
            Uint32,
          ),
          int Function(
            Pointer<Void>,
            Pointer<Utf16>,
            int,
            int,
            Pointer<Uint8>,
            int,
          )>('RegSetValueExW');

  static int Function(Pointer<Void>) _regCloseKey(DynamicLibrary registry) =>
      registry.lookupFunction<
          Int32 Function(Pointer<Void>),
          int Function(
            Pointer<Void>,
          )>('RegCloseKey');
}

/// Splits a WinINET `ProxyOverride` value into its entries.
List<String> splitBypassList(String? raw) {
  if (raw == null || raw.trim().isEmpty) return const <String>[];
  return raw
      .split(';')
      .map((entry) => entry.trim())
      .where((entry) => entry.isNotEmpty)
      .toList(growable: false);
}

/// One `networksetup` invocation result.
class SangforProcessOutcome {
  const SangforProcessOutcome(this.exitCode, this.stdout, this.stderr);

  final int exitCode;
  final String stdout;
  final String stderr;

  bool get isSuccess => exitCode == 0;
}

/// Runs an external command; injectable so the macOS store is testable.
typedef SangforProcessRunner = Future<SangforProcessOutcome> Function(
  String executable,
  List<String> arguments,
);

Future<SangforProcessOutcome> runSangforProcess(
  String executable,
  List<String> arguments,
) async {
  final result = await Process.run(executable, arguments);
  return SangforProcessOutcome(
    result.exitCode,
    '${result.stdout}',
    '${result.stderr}',
  );
}

/// `networksetup`-backed store. Changing the system proxy on macOS requires
/// administrator rights, so [write] reports [lastFailureNeedsPrivileges] when
/// the tool refuses; a sandboxed process also lands there.
class MacosSystemProxyStore implements SangforSystemProxyStore {
  MacosSystemProxyStore({
    SangforProcessRunner runner = runSangforProcess,
    String executable = '/usr/sbin/networksetup',
  })  : _run = runner,
        _executable = executable;

  static const List<String> defaultBypass = <String>[
    'localhost',
    '127.0.0.1',
    '::1',
  ];

  final SangforProcessRunner _run;
  final String _executable;
  bool _needsPrivileges = false;
  List<String>? _services;

  @override
  bool get lastFailureNeedsPrivileges => _needsPrivileges;

  /// Network services that can carry a proxy, resolved once per store.
  Future<List<String>> services() async {
    final cached = _services;
    if (cached != null) return cached;
    final outcome = await _run(_executable, <String>[
      '-listallnetworkservices',
    ]);
    final services = <String>[];
    if (outcome.isSuccess) {
      for (final line in outcome.stdout.split('\n')) {
        final name = line.trim();
        if (name.isEmpty) continue;
        // The first line is a header, and disabled services are marked with
        // an asterisk.
        if (services.isEmpty &&
            name.toLowerCase().contains('network service')) {
          continue;
        }
        services.add(name.startsWith('*') ? name.substring(1).trim() : name);
      }
    }
    _services = services;
    return services;
  }

  @override
  Future<SangforSystemProxySettings?> read() async {
    final names = await services();
    if (names.isEmpty) return null;
    for (final service in names) {
      final http = await _getProxy('-getwebproxy', service);
      final https = await _getProxy('-getsecurewebproxy', service);
      final enabled = http?.enabled ?? false;
      final server = http?.server ?? https?.server;
      if (!enabled && server == null) continue;
      return SangforSystemProxySettings(
        enabled: enabled,
        server: server,
        bypass: http?.bypass ?? defaultBypass,
      );
    }
    return const SangforSystemProxySettings();
  }

  @override
  Future<bool> write(SangforSystemProxySettings settings) async {
    _needsPrivileges = false;
    final names = await services();
    if (names.isEmpty) {
      _needsPrivileges = true;
      return false;
    }
    var wrote = false;
    for (final service in names) {
      final ok = await _writeService(service, settings);
      wrote = wrote || ok;
    }
    return wrote;
  }

  Future<bool> _writeService(
    String service,
    SangforSystemProxySettings settings,
  ) async {
    if (!settings.enabled) {
      final http = await _run(_executable, <String>[
        '-setwebproxystate',
        service,
        'off',
      ]);
      final https = await _run(_executable, <String>[
        '-setsecurewebproxystate',
        service,
        'off',
      ]);
      _inspect(http);
      _inspect(https);
      return http.isSuccess || https.isSuccess;
    }
    final parts = settings.server?.split(':') ?? const <String>[];
    final host = parts.isEmpty ? '127.0.0.1' : parts.first;
    final port = parts.length > 1 ? parts[1] : '80';
    final bypass = settings.bypass.isEmpty ? defaultBypass : settings.bypass;
    final results = <SangforProcessOutcome>[
      await _run(_executable, <String>[
        '-setwebproxy',
        service,
        host,
        port,
      ]),
      await _run(_executable, <String>[
        '-setsecurewebproxy',
        service,
        host,
        port,
      ]),
      await _run(_executable, <String>[
        '-setproxybypassdomains',
        service,
        ...bypass,
      ]),
    ];
    for (final outcome in results) {
      _inspect(outcome);
    }
    // Both halves must take: an HTTPS-only failure would silently leave
    // encrypted traffic outside the tunnel.
    return results[0].isSuccess && results[1].isSuccess;
  }

  void _inspect(SangforProcessOutcome outcome) {
    if (outcome.isSuccess) return;
    final text = '${outcome.stdout}\n${outcome.stderr}'.toLowerCase();
    if (text.contains('administrator') ||
        text.contains('not authorized') ||
        text.contains('authorization') ||
        text.contains('operation not permitted')) {
      _needsPrivileges = true;
    }
  }

  Future<SangforSystemProxySettings?> _getProxy(
    String verb,
    String service,
  ) async {
    final outcome = await _run(_executable, <String>[verb, service]);
    if (!outcome.isSuccess) {
      _inspect(outcome);
      return null;
    }
    var enabled = false;
    String? server;
    String? host;
    String? port;
    for (final line in outcome.stdout.split('\n')) {
      final separator = line.indexOf(':');
      if (separator <= 0) continue;
      final key = line.substring(0, separator).trim().toLowerCase();
      final value = line.substring(separator + 1).trim();
      switch (key) {
        case 'enabled':
          enabled = value.toLowerCase() == 'yes';
        case 'server':
          host = value;
        case 'port':
          port = value;
      }
    }
    if (host != null && host.isNotEmpty && port != null && port.isNotEmpty) {
      server = '$host:$port';
    }
    return SangforSystemProxySettings(
      enabled: enabled,
      server: server,
      bypass: defaultBypass,
    );
  }
}
