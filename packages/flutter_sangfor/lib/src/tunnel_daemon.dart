/// A client for `sangfor-tunneld`, the process that runs the Rust data plane.
///
/// The tunnel lives in its own process so that it outlives the app: today the
/// data plane runs inside the Flutter isolate, so a swipe-away, an OEM memory
/// reclaim, or a normal app exit drops every connection. On Windows it also
/// removes the elevation requirement — creating a wintun adapter needs an
/// elevated process, and an app that runs `asInvoker` cannot do it at all.
///
/// Two documents cross the boundary, and the split is deliberate:
///
/// - the **session plan** ([`ATrustSessionPlan`] in `flutter_sangfor_atrust`)
///   carries what the protocol needs: credentials, signing key, node endpoints,
///   published resources, anti-MITM pins;
/// - the **host configuration** ([SangforTunnelHostConfig]) carries what only
///   the host knows: which device to open, the interface name, and which routes
///   and DNS servers to install.
///
/// Which destinations belong in the tunnel stays here, in the app, because it
/// depends on the user's route policy and custom entries as well as on what the
/// gateway published. The daemon installs the CIDRs it is given; it does not
/// second-guess them.
library;

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';

/// The kinds of packet device the daemon can open.
enum SangforTunnelDevice {
  /// Windows, on the signed wintun driver. Needs the process to be elevated —
  /// which is why a service, not the app, should own it.
  wintun('wintun'),

  /// Linux, creating `/dev/net/tun`. Needs `CAP_NET_ADMIN`.
  tun('tun'),

  /// Android or OHOS, adopting a descriptor the platform service opened.
  fd('fd'),

  /// An in-memory device. The tunnel runs and can be exercised, but nothing
  /// reaches the operating system's stack. This is what tests and `--dry-run`
  /// use.
  loopback('loopback');

  const SangforTunnelDevice(this.wireName);

  /// How the daemon's configuration document spells this device.
  final String wireName;
}

/// The host configuration document handed to the daemon.
///
/// Serialized field names match the Rust `HostConfig` exactly, and the daemon
/// **rejects unknown fields** rather than ignoring them. That is on purpose: a
/// typo in a route list would otherwise silently drop a destination from the
/// tunnel, which presents to the user as "the VPN doesn't work for this site"
/// with nothing in the log to explain it.
class SangforTunnelHostConfig {
  /// Builds a configuration. Every parameter maps to a field in the daemon's
  /// document; see `docs/rust-core.md` §6.1 for what the daemon does with them.
  const SangforTunnelHostConfig({
    this.device = SangforTunnelDevice.wintun,
    this.interface = 'sangfor0',
    this.fd,
    this.wintunDllPath,
    this.address,
    this.netmask = '255.255.255.255',
    this.gateway,
    this.routes = const <String>[],
    this.dnsServers = const <String>[],
    this.mtu = 1400,
    this.acceptUnpinnedCertificate = true,
    this.connectTimeoutSeconds = 15,
    this.controlPort,
    this.controlToken,
    this.logPath,
  });

  /// Which packet device to open.
  final SangforTunnelDevice device;

  /// The adapter or interface name.
  final String interface;

  /// The descriptor to adopt, for [SangforTunnelDevice.fd].
  final int? fd;

  /// Where `wintun.dll` lives. Defaults to the normal Windows search order,
  /// which finds the copy staged beside the executable.
  final String? wintunDllPath;

  /// The address to assign. `null` uses the virtual IP the gateway assigns,
  /// which is what a normal session wants: packets the tunnel emits carry that
  /// address as their source, so an interface configured with a different one
  /// makes the stack drop them.
  final String? address;

  /// The netmask for [address]. A tunnel address is a point-to-point peer, so
  /// this defaults to a host mask.
  final String netmask;

  /// A gateway to publish with the address. Normally `null`: the tunnel is not
  /// the default route, it carries [routes].
  final String? gateway;

  /// CIDR blocks to route through the tunnel, as the app computed them.
  final List<String> routes;

  /// DNS servers to set on the interface.
  final List<String> dnsServers;

  /// Interface MTU.
  final int mtu;

  /// Whether to accept a node certificate when the session plan carries no
  /// anti-MITM pins. Defaults to true, matching the Swift and Dart planes; set
  /// false to fail closed on a deployment that always publishes pins.
  final bool acceptUnpinnedCertificate;

  /// Seconds to wait for a TLS connect and handshake.
  final int connectTimeoutSeconds;

  /// A loopback port for the control protocol. `null` leaves the socket closed
  /// and stdin as the only channel; `0` asks the daemon to pick a free port,
  /// which it then reports in its log — see
  /// [SangforTunnelDaemonProcess.controlPort].
  final int? controlPort;

  /// The shared secret a control client must present for `status` and `stop`.
  /// Leaving this null makes the control channel open to any local process, and
  /// the daemon logs a warning when it does.
  final String? controlToken;

  /// Where the daemon writes its log. `null` means stderr.
  final String? logPath;

  /// The document as the daemon parses it.
  Map<String, Object?> toJson() => <String, Object?>{
        'device': device.wireName,
        'interface': interface,
        if (fd != null) 'fd': fd,
        if (wintunDllPath != null) 'wintunDll': wintunDllPath,
        if (address != null) 'address': address,
        'netmask': netmask,
        if (gateway != null) 'gateway': gateway,
        'routes': routes,
        'dnsServers': dnsServers,
        'mtu': mtu,
        'acceptUnpinnedCertificate': acceptUnpinnedCertificate,
        'connectTimeoutSeconds': connectTimeoutSeconds,
        if (controlPort != null) 'controlPort': controlPort,
        if (controlToken != null) 'controlToken': controlToken,
        if (logPath != null) 'logPath': logPath,
      };

  /// Encodes the document for writing to disk.
  String encode() => jsonEncode(toJson());

  /// Reads a document back.
  ///
  /// Used on a configuration the daemon's *installer* wrote, which is how an
  /// app finds the port and token of a daemon it did not launch. Tolerant of
  /// fields this class does not model, because the daemon is a separate binary
  /// with its own release cycle and a version that adds one must not break an
  /// app that was built before it.
  ///
  /// The daemon itself is strict in the other direction — it rejects unknown
  /// fields — so a document this accepts is not necessarily one it will.
  factory SangforTunnelHostConfig.decode(Map<String, Object?> json) {
    final device = json['device'];
    return SangforTunnelHostConfig(
      device: SangforTunnelDevice.values.firstWhere(
        (kind) => kind.wireName == device,
        orElse: () => SangforTunnelDevice.loopback,
      ),
      interface: json['interface'] as String? ?? 'sangfor0',
      fd: (json['fd'] as num?)?.toInt(),
      wintunDllPath: json['wintunDll'] as String?,
      address: json['address'] as String?,
      netmask: json['netmask'] as String? ?? '255.255.255.255',
      gateway: json['gateway'] as String?,
      routes: _stringList(json['routes']),
      dnsServers: _stringList(json['dnsServers']),
      mtu: (json['mtu'] as num?)?.toInt() ?? 1400,
      acceptUnpinnedCertificate:
          json['acceptUnpinnedCertificate'] as bool? ?? true,
      connectTimeoutSeconds:
          (json['connectTimeoutSeconds'] as num?)?.toInt() ?? 15,
      controlPort: (json['controlPort'] as num?)?.toInt(),
      controlToken: json['controlToken'] as String?,
      logPath: json['logPath'] as String?,
    );
  }
}

/// What the daemon reports about a running tunnel.
///
/// Nothing here is secret: counters, the assigned address, and whether the
/// interface came up. The session plan — which carries the signing key — never
/// crosses the control channel in either direction.
class SangforTunnelSnapshot {
  /// Parses a status reply's `data` object.
  const SangforTunnelSnapshot({
    required this.sessionRunning,
    required this.active,
    required this.virtualIp,
    required this.interfaceConfigured,
    required this.interfaceError,
    required this.channelsOpen,
    required this.devicePackets,
    required this.emittedPackets,
    required this.deviceDropped,
    required this.emitFailures,
    required this.channelBytesIn,
    required this.channelBytesOut,
    required this.connectFailures,
    required this.routed,
    required this.terminated,
    required this.unrouted,
    required this.ingress,
    required this.interfaceName,
    required this.fatal,
  });

  /// Decodes the daemon's `data` object, tolerating fields it does not send.
  factory SangforTunnelSnapshot.fromJson(Map<String, Object?> json) =>
      SangforTunnelSnapshot(
        sessionRunning: json['sessionRunning'] as bool? ?? false,
        active: json['active'] as bool? ?? false,
        virtualIp: _stringList(json['virtualIp']),
        interfaceConfigured: json['interfaceConfigured'] as bool? ?? false,
        interfaceError: json['interfaceError'] as String?,
        channelsOpen: _asInt(json['channelsOpen']),
        devicePackets: _asInt(json['devicePackets']),
        emittedPackets: _asInt(json['emittedPackets']),
        deviceDropped: _asInt(json['deviceDropped']),
        emitFailures: _asInt(json['emitFailures']),
        channelBytesIn: _asInt(json['channelBytesIn']),
        channelBytesOut: _asInt(json['channelBytesOut']),
        connectFailures: _asInt(json['connectFailures']),
        routed: _asInt(json['routed']),
        terminated: _asInt(json['terminated']),
        unrouted: _asInt(json['unrouted']),
        ingress: _asInt(json['ingress']),
        interfaceName: json['interface'] as String?,
        fatal: json['fatal'] as String?,
      );

  /// The daemon has a session. Distinct from [active]: a daemon that has been
  /// installed but not yet given a plan has no session, and one that is still
  /// handshaking has a session that is not yet active.
  ///
  /// A client that cannot tell those apart either waits forever for a tunnel
  /// nobody started, or starts a second one and is refused.
  final bool sessionRunning;

  /// The handshake completed and the tunnel is carrying traffic.
  final bool active;

  /// The virtual IP the gateway assigned.
  final List<String> virtualIp;

  /// The interface was configured successfully.
  final bool interfaceConfigured;

  /// Why the interface could not be configured, if it could not.
  final String? interfaceError;

  /// Channels currently open to the gateway.
  final int channelsOpen;

  /// Packets read from the device.
  final int devicePackets;

  /// Packets written to the device.
  final int emittedPackets;

  /// Packets shed because the device queue was full. Non-zero means the tunnel
  /// is behind the stack, which looks like packet loss on the far side and is
  /// not.
  final int deviceDropped;

  /// Packets the device refused.
  final int emitFailures;

  /// Bytes read from gateway channels.
  final int channelBytesIn;

  /// Bytes written to gateway channels.
  final int channelBytesOut;

  /// Connect attempts that failed.
  final int connectFailures;

  /// Egress packets forwarded as raw IP.
  final int routed;

  /// Egress packets the userspace TCP terminator claimed.
  final int terminated;

  /// Egress packets no published resource covers.
  final int unrouted;

  /// Ingress packets delivered to the local stack.
  final int ingress;

  /// The interface the daemon opened.
  final String? interfaceName;

  /// A fatal error ended the session, if one did. The control plane must log in
  /// again; restarting the tunnel with the same plan will not help.
  final String? fatal;

  /// True when the tunnel is unusable and the caller should reconnect.
  bool get isDead => fatal != null;

  @override
  String toString() => 'SangforTunnelSnapshot(session: $sessionRunning, '
      'active: $active, '
      'virtualIp: $virtualIp, interface: $interfaceName, '
      'configured: $interfaceConfigured, routed: $routed, '
      'terminated: $terminated, unrouted: $unrouted, ingress: $ingress, '
      'dropped: $deviceDropped, connectFailures: $connectFailures, '
      'fatal: $fatal)';
}

int _asInt(Object? value) => switch (value) {
      final int value => value,
      final num value => value.toInt(),
      _ => 0,
    };

List<String> _stringList(Object? value) => value is List
    ? value.whereType<String>().toList(growable: false)
    : const <String>[];

/// Removes a scratch directory, ignoring the failure to.
///
/// A directory left behind in the temp folder costs nothing; surfacing a
/// removal failure over a session that started successfully would be worse
/// than the leak. The one case that matters — the plan document holding the
/// signing key — is handled by the caller deleting it as soon as the daemon
/// has read it.
Future<void> _removeDirectory(Directory directory) async {
  try {
    await directory.delete(recursive: true);
  } on FileSystemException {
    // Ignored; see the doc comment.
  }
}

/// Thrown when the daemon refuses a control request or the connection drops.
class SangforTunnelControlException implements Exception {
  /// Wraps [message], which is the daemon's own text when it sent one.
  const SangforTunnelControlException(this.message);

  /// What went wrong.
  final String message;

  @override
  String toString() => 'SangforTunnelControlException: $message';
}

/// Speaks the daemon's control protocol over its loopback socket.
///
/// The protocol is one JSON object per line in each direction. Requests are
/// answered in order on a connection, so a single socket is shared and replies
/// are matched to callers by a queue rather than by an id in the payload.
class SangforTunnelControlClient {
  SangforTunnelControlClient._(this._socket, this._token) {
    _subscription = _socket
        .cast<List<int>>()
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(_handleLine, onError: _handleError, onDone: _handleDone);
  }

  final Socket _socket;
  final String? _token;
  final Queue<Completer<Map<String, Object?>>> _pending =
      Queue<Completer<Map<String, Object?>>>();
  StreamSubscription<String>? _subscription;
  bool _closed = false;

  /// Connects to a daemon listening on [port].
  ///
  /// [token] must match the daemon's `controlToken`, or every request but
  /// `ping` is refused.
  ///
  /// Throws [SocketException] when nothing is listening, and
  /// [SangforTunnelControlException] when the connection drops mid-handshake.
  static Future<SangforTunnelControlClient> connect({
    required int port,
    String? token,
    String host = '127.0.0.1',
    Duration timeout = const Duration(seconds: 5),
  }) async {
    final socket = await Socket.connect(host, port, timeout: timeout);
    socket.setOption(SocketOption.tcpNoDelay, true);
    return SangforTunnelControlClient._(socket, token);
  }

  /// True once [close] has run or the daemon went away.
  bool get isClosed => _closed;

  /// Asks for a snapshot of the tunnel's state.
  ///
  /// Throws [SangforTunnelControlException] when the token is wrong or the
  /// daemon refused.
  Future<SangforTunnelSnapshot> status() async {
    final reply = await _send('status');
    final data = reply['data'];
    if (data is! Map) {
      throw const SangforTunnelControlException(
        'the daemon sent a status reply with no data',
      );
    }
    return SangforTunnelSnapshot.fromJson(data.cast<String, Object?>());
  }

  /// Proves the daemon is alive and reading. Needs no token, so a caller can
  /// probe before it has one.
  Future<void> ping() => _send('ping');

  /// Asks the daemon to run a session.
  ///
  /// [planDocument] is the session plan JSON; [configDocument] is the host
  /// configuration for *this* session, which is where the routes go — an
  /// installed daemon was configured once, at install time, and which
  /// destinations belong in the tunnel depends on what the gateway published
  /// this time. Both are written to disk and named by path, because the plan
  /// carries the signing key and the control channel is reachable by any local
  /// process that has the token.
  ///
  /// Refused while a session is already running: the daemon will not quietly
  /// replace one. Call [stopSession] first.
  ///
  /// The returned future completes when the daemon has opened its device and
  /// started the host loop — not when the tunnel is up. Poll [status] for
  /// [SangforTunnelSnapshot.active].
  Future<void> startSession({
    required String planDocument,
    required String configDocument,
  }) async {
    final directory = await Directory.systemTemp.createTemp('sangfor-session');
    final planFile = File('${directory.path}${Platform.pathSeparator}plan.json');
    final configFile = File(
      '${directory.path}${Platform.pathSeparator}host.json',
    );
    try {
      await planFile.writeAsString(planDocument, flush: true);
      await configFile.writeAsString(configDocument, flush: true);
      await _send('start', <String, Object?>{
        'planPath': planFile.path,
        'configPath': configFile.path,
      });
      // The daemon has read both documents by the time it answers, so they are
      // no longer needed — and the plan is secret material that should not
      // outlive the request that carried it.
      await _removeDirectory(directory);
    } on Object {
      // Removing a scratch directory is not worth failing a connect over, and
      // leaving it behind on the error path is cheaper than a second failure
      // masking the first.
      await _removeDirectory(directory);
      rethrow;
    }
  }

  /// Ends the current session and leaves the daemon running.
  ///
  /// Idempotent: stopping a session that already died is acknowledged rather
  /// than reported as an error, because the common case is tearing down after
  /// the gateway dropped the connection.
  Future<void> stopSession() => _send('stopSession');

  /// Asks the daemon to end the session and exit.
  ///
  /// The tunnel is down by the time this returns: the daemon replies before it
  /// stops, and stopping closes the device.
  Future<void> stop() => _send('stop');

  /// Closes the connection without stopping the tunnel.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _subscription?.cancel();
    _subscription = null;
    _socket.destroy();
    _failPending('the control connection was closed');
  }

  Future<Map<String, Object?>> _send(
    String command, [
    Map<String, Object?> extra = const <String, Object?>{},
  ]) async {
    if (_closed) {
      throw const SangforTunnelControlException(
        'the control connection is closed',
      );
    }
    final completer = Completer<Map<String, Object?>>();
    _pending.add(completer);
    final request = <String, Object?>{
      'cmd': command,
      if (_token != null) 'token': _token,
      ...extra,
    };
    try {
      // `add` and no `flush`: a `Socket` is a `StreamSink`, and calling `flush`
      // while another is in flight throws "StreamSink is bound to a stream".
      // Callers are allowed to have several requests outstanding at once, and
      // the daemon answers them in order, so writes must not assume they are
      // alone. `tcpNoDelay` is set on connect, so the bytes leave promptly
      // without an explicit flush.
      _socket.add(utf8.encode('${jsonEncode(request)}\n'));
    } on Object catch (error) {
      _pending.remove(completer);
      await close();
      throw SangforTunnelControlException('sending "$command" failed: $error');
    }
    final reply = await completer.future;
    if (reply['ok'] != true) {
      throw SangforTunnelControlException(
        reply['error'] as String? ?? 'the daemon refused "$command"',
      );
    }
    return reply;
  }

  void _handleLine(String line) {
    if (line.trim().isEmpty) return;
    if (_pending.isEmpty) {
      // A reply nobody asked for. The protocol is strictly request/response, so
      // this means the two sides disagree about the conversation; dropping it
      // silently would hide that.
      return;
    }
    final completer = _pending.removeFirst();
    try {
      final decoded = jsonDecode(line);
      if (decoded is Map) {
        completer.complete(decoded.cast<String, Object?>());
      } else {
        completer.completeError(
          SangforTunnelControlException('the reply was not an object: $line'),
        );
      }
    } on FormatException catch (error) {
      completer.completeError(
        SangforTunnelControlException('the reply was not JSON: $error'),
      );
    }
  }

  void _handleError(Object error) {
    _closed = true;
    _failPending('the control connection failed: $error');
  }

  void _handleDone() {
    _closed = true;
    _failPending('the daemon closed the control connection');
  }

  void _failPending(String message) {
    while (_pending.isNotEmpty) {
      final completer = _pending.removeFirst();
      if (!completer.isCompleted) {
        completer.completeError(SangforTunnelControlException(message));
      }
    }
  }
}

/// A `sangfor-tunneld` the app can hand sessions to.
///
/// Two ways to get one, and the difference matters:
///
/// - [SangforTunnelInstalledDaemon] connects to a daemon that is already
///   running, installed as an elevated logon task. This is the one that removes
///   the elevation requirement on Windows: creating a wintun adapter needs an
///   elevated process, and an app that runs `asInvoker` cannot do it at all.
/// - [SangforTunnelDaemonProcess] launches the binary as a child. It inherits
///   the app's privileges, so it only reaches a real adapter if the app is
///   itself elevated; otherwise it is for `loopback` and `--dry-run` work.
///
/// Both speak the same protocol, so callers should not need to know which they
/// have.
abstract class SangforTunnelDaemon {
  /// Asks the daemon to run a session.
  ///
  /// Completes once the daemon has opened its device and started its host
  /// loop — **not** once the tunnel is up. Poll [status] and wait for
  /// [SangforTunnelSnapshot.active], or for
  /// [SangforTunnelSnapshot.interfaceConfigured] if the address is what
  /// matters.
  ///
  /// Throws [SangforTunnelControlException] if the daemon refuses, which it
  /// does when a session is already running. Call [stopSession] first.
  Future<void> startSession({
    required String planDocument,
    required SangforTunnelHostConfig config,
  });

  /// The daemon's view of the tunnel.
  Future<SangforTunnelSnapshot> status();

  /// Ends the session and leaves the daemon running.
  Future<void> stopSession();

  /// Gives the daemon up: ends the session, and for a child process ends the
  /// process too. An installed daemon is left running, because the next connect
  /// wants it and starting it again needs elevation the app does not have.
  Future<void> release();

  /// The daemon's log lines, as it writes them.
  ///
  /// Empty for an installed daemon unless its configuration names a log file
  /// this process can read; a child's stderr is forwarded as it arrives.
  Stream<String> get log;
}

/// A daemon installed as an elevated logon task, found by reading its
/// configuration.
///
/// The configuration lives in the *user's* profile rather than a machine-wide
/// directory because it holds the control token, and a file every local user
/// can read is not a secret. See the Rust `service` module for why this is a
/// logon task and not a Windows service.
class SangforTunnelInstalledDaemon implements SangforTunnelDaemon {
  SangforTunnelInstalledDaemon._(this._client, this.directory);

  /// The loopback port an installed daemon serves by default.
  ///
  /// Fixed rather than ephemeral: a child process reports its port on a pipe
  /// its launcher owns, but an installed daemon's stderr is a log file nobody
  /// is watching, so the app has to know where to connect.
  static const int defaultControlPort = 7166;

  /// The name of the configuration file the daemon's installer writes.
  static const String hostConfigFileName = 'host.json';

  final SangforTunnelControlClient _client;

  /// Where the daemon keeps its configuration and log.
  final Directory directory;

  /// The directory an installed daemon uses, or null when there is no user
  /// profile to put it in.
  static Directory? defaultDirectory() {
    final local = Platform.environment['LOCALAPPDATA'];
    if (local == null || local.isEmpty) return null;
    return Directory('$local${Platform.pathSeparator}sangfor-tunneld');
  }

  /// Connects to an installed daemon, or returns null when there is none.
  ///
  /// Null is the ordinary answer, not a failure: the daemon has to have been
  /// installed from an elevated shell first, and a caller that gets null should
  /// fall back to whatever data plane it had.
  ///
  /// [directory] defaults to [defaultDirectory]. [port] overrides the one in
  /// the configuration, which is useful when several daemons share a machine.
  static Future<SangforTunnelInstalledDaemon?> connect({
    Directory? directory,
    int? port,
    Duration timeout = const Duration(seconds: 5),
  }) async {
    final where = directory ?? defaultDirectory();
    if (where == null) return null;
    final file = File(
      '${where.path}${Platform.pathSeparator}$hostConfigFileName',
    );
    if (!await file.exists()) return null;

    final SangforTunnelHostConfig? config;
    try {
      config = SangforTunnelHostConfig.decode(
        jsonDecode(await file.readAsString()) as Map<String, Object?>,
      );
    } on Object {
      // A configuration this cannot parse is one an older or newer daemon
      // wrote. Guessing at the port and token would produce a connection that
      // fails with "the control token is missing or wrong", which reads as a
      // security problem rather than a version mismatch.
      return null;
    }

    final SangforTunnelControlClient client;
    try {
      client = await SangforTunnelControlClient.connect(
        port: port ?? config.controlPort ?? defaultControlPort,
        token: config.controlToken,
        timeout: timeout,
      );
    } on Object {
      return null;
    }
    return SangforTunnelInstalledDaemon._(client, where);
  }

  @override
  Future<void> startSession({
    required String planDocument,
    required SangforTunnelHostConfig config,
  }) => _client.startSession(
    planDocument: planDocument,
    configDocument: config.encode(),
  );

  @override
  Future<SangforTunnelSnapshot> status() => _client.status();

  @override
  Future<void> stopSession() => _client.stopSession();

  @override
  Future<void> release() async {
    try {
      await _client.stopSession();
    } on SangforTunnelControlException {
      // Already gone. An installed daemon that cannot be reached is not this
      // call's problem to solve, and failing a disconnect over it would leave
      // the UI stuck in "disconnecting".
    }
    // The daemon itself stays up: it is elevated, it was installed once, and
    // the next connect wants it. Only the socket is ours to close.
    await _client.close();
  }

  @override
  Stream<String> get log => const Stream<String>.empty();

  /// The daemon's log file, if its configuration named one.
  ///
  /// Worth reading when a session fails: the daemon is not this process's
  /// child, so its stderr went to a file and nowhere else.
  File? get logFile {
    final path = File(
      '${directory.path}${Platform.pathSeparator}tunneld.log',
    );
    return path.existsSync() ? path : null;
  }
}

/// A daemon launched as a child process.
///
/// This is the mode an app can use without any privilege setup: it starts the
/// binary, waits for the control socket, and drives it. The tunnel does **not**
/// outlive the app in this mode — the child is killed when the parent goes — so
/// for that, install the daemon and use [SangforTunnelInstalledDaemon].
class SangforTunnelDaemonProcess implements SangforTunnelDaemon {
  SangforTunnelDaemonProcess._(
    this._process,
    this._client,
    this.controlPort,
    this._log,
    this._directory,
  );

  /// The port the daemon reported for its control socket.
  final int controlPort;

  final Process _process;
  final SangforTunnelControlClient _client;

  /// The scratch directory holding the host configuration the child was started
  /// with. Removed when the child exits, since it names the control token.
  final Directory _directory;

  /// The daemon's stderr, forwarded by the single subscription
  /// [`_discoverPort`] holds.
  final Stream<String> _log;
  bool _exited = false;
  int? _exitCode;

  /// The daemon's log lines, as it writes them.
  ///
  /// Broadcast, so a late listener still gets what comes next; lines already
  /// emitted are not replayed. Lines written before [start] returned — including
  /// the one that reported the control port — are captured from the first byte,
  /// so startup diagnostics are not lost while the port was being discovered.
  @override
  Stream<String> get log => _log;

  /// The control client for this daemon.
  SangforTunnelControlClient get control => _client;

  /// The child's exit code, once it has exited.
  int? get exitCode => _exitCode;

  /// True once the child has exited.
  bool get hasExited => _exited;

  /// Starts [executable] idle and waits for its control socket.
  ///
  /// No plan is passed: the daemon starts with no session and is given one by
  /// [startSession], exactly as an installed daemon is. Launching it with
  /// `--plan` would work, but then the two ways of getting a daemon would start
  /// a session differently, and a caller holding a [SangforTunnelDaemon] would
  /// have to know which one it has.
  ///
  /// [config] must set `controlPort` — 0 asks the daemon to choose a free port
  /// and report it, which is what this class reads back.
  ///
  /// Throws [SangforTunnelControlException] if the daemon exits before its
  /// control socket opens, and [ProcessException] if the binary cannot be run.
  static Future<SangforTunnelDaemonProcess> start({
    required String executable,
    required SangforTunnelHostConfig config,
    List<String> extraArguments = const <String>[],
    Duration startupTimeout = const Duration(seconds: 20),
    Duration requestTimeout = const Duration(seconds: 5),
  }) async {
    if (config.controlPort == null) {
      throw const SangforTunnelControlException(
        'controlPort must be set to drive a daemon; use 0 to let it choose',
      );
    }
    final directory = await Directory.systemTemp.createTemp('sangfor-tunnel');
    final configFile =
        File('${directory.path}${Platform.pathSeparator}host.json');
    try {
      await configFile.writeAsString(config.encode(), flush: true);
      final process = await Process.start(
        executable,
        <String>['--config', configFile.path, ...extraArguments],
        // stdout carries nothing: replies go over the control socket, and logs
        // go to stderr. Leaving stdout open but unread would eventually block
        // the daemon on a full pipe.
        mode: ProcessStartMode.normal,
      );

      final logs = StreamController<String>.broadcast();
      final port = await _discoverPort(process, logs, startupTimeout);
      final client = await SangforTunnelControlClient.connect(
        port: port,
        token: config.controlToken,
        timeout: requestTimeout,
      );
      final daemon = SangforTunnelDaemonProcess._(
        process,
        client,
        port,
        logs.stream,
        directory,
      );
      daemon._watch();
      return daemon;
    } on Object {
      // Nothing owns the scratch directory yet, so this call has to clean it up;
      // on success `_watch` takes over.
      await _removeDirectory(directory);
      rethrow;
    }
  }

  @override
  Future<void> startSession({
    required String planDocument,
    required SangforTunnelHostConfig config,
  }) => _client.startSession(
    planDocument: planDocument,
    configDocument: config.encode(),
  );

  @override
  Future<SangforTunnelSnapshot> status() => _client.status();

  @override
  Future<void> stopSession() => _client.stopSession();

  @override
  Future<void> release() => stop().then((_) {});

  /// Reads the daemon's log until it reports its control port, forwarding every
  /// line to [logs] as it goes.
  ///
  /// The port is ephemeral when `controlPort` is 0, and that log line is the
  /// daemon's documented way of reporting it.
  ///
  /// One subscription serves both purposes on purpose: `Process.stderr` is a
  /// single-subscription stream, so a separate listener for the log would throw
  /// "Stream has already been listened to" — and discovering the port is only
  /// the first thing a caller does, so the log has to be captured from the very
  /// first line to avoid losing the daemon's startup diagnostics.
  static Future<int> _discoverPort(
    Process process,
    StreamController<String> logs,
    Duration timeout,
  ) async {
    const marker = 'control socket listening on 127.0.0.1:';
    final completer = Completer<int>();
    process.stderr
        .cast<List<int>>()
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(
      (String line) {
        if (!logs.isClosed) logs.add(line);
        if (completer.isCompleted) return;
        final index = line.indexOf(marker);
        if (index < 0) return;
        final port = int.tryParse(line.substring(index + marker.length).trim());
        if (port != null) completer.complete(port);
      },
      onError: (Object error) {
        if (!completer.isCompleted) completer.completeError(error);
        if (!logs.isClosed) unawaited(logs.close());
      },
      onDone: () {
        if (!completer.isCompleted) {
          completer.completeError(
            const SangforTunnelControlException(
              'the daemon exited before opening its control socket',
            ),
          );
        }
        if (!logs.isClosed) unawaited(logs.close());
      },
      cancelOnError: false,
    );
    return completer.future.timeout(
      timeout,
      onTimeout: () => throw SangforTunnelControlException(
        'the daemon did not report a control port within $timeout',
      ),
    );
  }

  /// Tracks exit and cleans up the scratch directory.
  ///
  /// The log needs no wiring here: `_discoverPort` already holds the one
  /// subscription `Process.stderr` allows and forwards every line to the
  /// broadcast stream this object exposes.
  void _watch() {
    unawaited(
      _process.exitCode.then((code) {
        _exited = true;
        _exitCode = code;
        return _shutdown();
      }),
    );
  }

  Future<void> _shutdown() async {
    await _client.close();
    await _removeDirectory(_directory);
  }

  /// Stops the tunnel and waits for the child to exit.
  ///
  /// Asks politely first, so the daemon can tear the interface down; falls back
  /// to killing it if that does not happen within [killAfter].
  Future<int> stop({Duration killAfter = const Duration(seconds: 5)}) async {
    if (_exited) return _exitCode ?? -1;
    try {
      await _client.stop();
    } on SangforTunnelControlException {
      // Already gone, or never reachable: killing is the only option left.
      _process.kill(ProcessSignal.sigkill);
    }
    final code = await _process.exitCode.timeout(
      killAfter,
      onTimeout: () {
        _process.kill(ProcessSignal.sigkill);
        return -1;
      },
    );
    _exited = true;
    _exitCode = code;
    return code;
  }

  /// Releases the client without stopping the daemon.
  ///
  /// The child keeps running and the log stream stays open — it closes itself
  /// when the daemon's stderr ends. Use [stop] to end the tunnel.
  ///
  /// The scratch directory holding the configuration is left in place while the
  /// child lives; the exit handler removes it. The daemon has already read it,
  /// so nothing depends on it surviving, but deleting it from here would race a
  /// daemon that is still starting.
  Future<void> detach() => _client.close();
}
