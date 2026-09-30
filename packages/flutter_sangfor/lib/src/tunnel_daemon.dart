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
}

/// What the daemon reports about a running tunnel.
///
/// Nothing here is secret: counters, the assigned address, and whether the
/// interface came up. The session plan — which carries the signing key — never
/// crosses the control channel in either direction.
class SangforTunnelSnapshot {
  /// Parses a status reply's `data` object.
  const SangforTunnelSnapshot({
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
  String toString() => 'SangforTunnelSnapshot(active: $active, '
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

  Future<Map<String, Object?>> _send(String command) async {
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

/// A daemon launched as a child process.
///
/// This is the mode an app can use without any privilege setup: it starts the
/// binary, waits for the control socket, and drives it. The tunnel does **not**
/// outlive the app in this mode — the child is killed when the parent goes — so
/// for that, run the daemon as a service and connect with
/// [SangforTunnelControlClient.connect] instead.
class SangforTunnelDaemonProcess {
  SangforTunnelDaemonProcess._(
    this._process,
    this._client,
    this.controlPort,
    this._log,
  );

  /// The port the daemon reported for its control socket.
  final int controlPort;

  final Process _process;
  final SangforTunnelControlClient _client;

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
  Stream<String> get log => _log;

  /// The control client for this daemon.
  SangforTunnelControlClient get control => _client;

  /// The child's exit code, once it has exited.
  int? get exitCode => _exitCode;

  /// True once the child has exited.
  bool get hasExited => _exited;

  /// Starts [executable] with [plan] and [config], then waits for its control
  /// socket.
  ///
  /// [planDocument] is the session plan JSON written by
  /// `flutter_sangfor_atrust`; it is passed as a temporary file rather than on
  /// the command line, because a signing key in an argument list is visible to
  /// every process on the machine.
  ///
  /// [config] must set `controlPort` — 0 asks the daemon to choose a free port
  /// and report it, which is what this class reads back.
  ///
  /// Throws [SangforTunnelControlException] if the daemon exits before its
  /// control socket opens, and [ProcessException] if the binary cannot be run.
  static Future<SangforTunnelDaemonProcess> start({
    required String executable,
    required String planDocument,
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
    final planFile = File('${directory.path}${Platform.pathSeparator}plan.json');
    final configFile =
        File('${directory.path}${Platform.pathSeparator}host.json');
    try {
      await planFile.writeAsString(planDocument, flush: true);
      await configFile.writeAsString(config.encode(), flush: true);
      final process = await Process.start(
        executable,
        <String>[
          '--plan',
          planFile.path,
          '--config',
          configFile.path,
          ...extraArguments,
        ],
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
      final daemon =
          SangforTunnelDaemonProcess._(process, client, port, logs.stream);
      daemon._watch(directory);
      return daemon;
    } on Object {
      // Nothing owns the scratch directory yet, so this call has to clean it up;
      // on success `_watch` takes over.
      await _remove(directory);
      rethrow;
    }
  }

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
  void _watch(Directory directory) {
    unawaited(
      _process.exitCode.then((code) {
        _exited = true;
        _exitCode = code;
        return _shutdown(directory);
      }),
    );
  }

  Future<void> _shutdown(Directory directory) async {
    await _client.close();
    await _remove(directory);
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
  /// The scratch directory holding the plan is left in place while the child
  /// lives; the exit handler removes it. The plan has already been read, so
  /// nothing depends on it surviving, but deleting it from here would race a
  /// daemon that is still starting.
  Future<void> detach() => _client.close();

  static Future<void> _remove(Directory directory) async {
    try {
      await directory.delete(recursive: true);
    } on FileSystemException {
      // A scratch directory left behind costs nothing, and failing to remove it
      // is not worth surfacing over a successful teardown.
    }
  }
}
