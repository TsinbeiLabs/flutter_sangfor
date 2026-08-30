import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'dart:io';

import 'conntrack.dart';
import 'packet.dart';
import 'resource.dart';

enum ATrustTunnelFrameType {
  data(1),
  control(2),
  heartbeat(3),
  close(4);

  const ATrustTunnelFrameType(this.value);

  final int value;

  static ATrustTunnelFrameType fromValue(int value) => values.firstWhere(
        (type) => type.value == value,
        orElse: () => throw FormatException('unknown tunnel frame type $value'),
      );
}

enum ATrustL3Command {
  authRequest(0x13),
  authResponse(0x93),
  dataRequest(0x14),
  dataResponse(0x94),
  heartbeatRequest(0x15),
  heartbeatResponse(0x95),
  secondVipResponse(0x96);

  const ATrustL3Command(this.value);

  final int value;
}

class ATrustL3IpInfo {
  const ATrustL3IpInfo({
    required this.atype,
    required this.protocol,
    required this.destinationAddress,
    required this.destinationPort,
    required this.sourceAddress,
    required this.sourcePort,
  });

  final int atype;
  final int protocol;
  final String destinationAddress;
  final int destinationPort;
  final String sourceAddress;
  final int sourcePort;

  Map<String, Object?> toMap() => <String, Object?>{
        'atype': atype,
        'protocol': protocol,
        'destAddr': destinationAddress,
        'destPort': destinationPort,
        'srcAddr': sourceAddress,
        'srcPort': sourcePort,
      };
}

class ATrustL3AuthRequest {
  const ATrustL3AuthRequest({
    required this.sid,
    required this.appId,
    required this.url,
    required this.deviceId,
    required this.connectionId,
    required this.lang,
    required this.conntrackHash,
    required this.ip,
    this.procHash,
    this.appToken,
    this.rcAppliedInfo = 0,
    this.env,
    this.domain,
  });

  final String sid;
  final String appId;
  final String url;
  final String deviceId;
  final String connectionId;
  final String lang;
  final int conntrackHash;
  final ATrustL3IpInfo ip;
  final String? procHash;
  final String? appToken;
  final int rcAppliedInfo;
  final Map<String, Object?>? env;
  final String? domain;

  Map<String, Object?> unsignedMap() => <String, Object?>{
        'sid': sid,
        'appId': appId,
        if (procHash != null) 'procHash': procHash,
        if (appToken != null) 'appToken': appToken,
        'url': url,
        'deviceId': deviceId,
        'connectionId': connectionId,
        'rcAppliedInfo': rcAppliedInfo,
        'lang': lang,
        if (env != null) 'env': env,
        'conntrackHash': conntrackHash,
        'ip': ip.toMap(),
        if (domain != null) 'domain': domain,
      };

  String signature(Uint8List signKey) =>
      (Hmac(sha256, signKey).convert(utf8.encode(jsonEncode(unsignedMap()))))
          .toString()
          .toUpperCase();

  Map<String, Object?> toMap(Uint8List signKey) => <String, Object?>{
        ...unsignedMap(),
        'xRequestSig': signature(signKey),
      };
}

enum ATrustL3FlowState { pending, authenticated, failed, expired }

class ATrustL3FlowKey {
  const ATrustL3FlowKey({
    required this.protocol,
    required this.sourceAddress,
    required this.sourcePort,
    required this.destinationAddress,
    required this.destinationPort,
  });

  final int protocol;
  final String sourceAddress;
  final int sourcePort;
  final String destinationAddress;
  final int destinationPort;

  @override
  bool operator ==(Object other) =>
      other is ATrustL3FlowKey &&
      other.protocol == protocol &&
      other.sourceAddress == sourceAddress &&
      other.sourcePort == sourcePort &&
      other.destinationAddress == destinationAddress &&
      other.destinationPort == destinationPort;

  @override
  int get hashCode => Object.hash(
        protocol,
        sourceAddress,
        sourcePort,
        destinationAddress,
        destinationPort,
      );
}

class ATrustL3Flow {
  ATrustL3Flow({
    required this.id,
    required this.key,
    required this.appId,
    required this.nodeGroupId,
    required DateTime now,
  })  : lastSeen = now,
        expiresAt = now.add(const Duration(seconds: 60));

  final int id;
  final ATrustL3FlowKey key;
  final String appId;
  final String nodeGroupId;
  final List<Uint8List> pendingPackets = <Uint8List>[];
  final ATrustTcpConntrack tcp = ATrustTcpConntrack();
  DateTime lastSeen;
  DateTime expiresAt;
  ATrustL3FlowState state = ATrustL3FlowState.pending;
  String? token;
  Object? error;
  bool authRequested = false;
  DateTime? authDeadline;
  DateTime? authRetryAt;
  int authTimeouts = 0;
}

class ATrustL3FlowTracker {
  ATrustL3FlowTracker({
    this.maxFlows = 16384,
    this.maxPendingPackets = 1024,
    this.ttl = const Duration(minutes: 10),
    DateTime Function()? clock,
  }) : _clock = clock ?? DateTime.now;

  final int maxFlows;
  final int maxPendingPackets;
  final Duration ttl;
  final DateTime Function() _clock;
  final Map<ATrustL3FlowKey, ATrustL3Flow> _flows =
      <ATrustL3FlowKey, ATrustL3Flow>{};
  int _nextId = 0;

  int get length => _flows.length;

  Iterable<ATrustL3Flow> get flows => _flows.values;

  ATrustL3Flow? lookup(ATrustL3FlowKey key) => _flows[key];

  ATrustL3Flow? flowById(int id) {
    for (final flow in _flows.values) {
      if (flow.id == id) return flow;
    }
    return null;
  }

  ATrustL3Flow getOrCreate(
    ATrustL3FlowKey key, {
    required String appId,
    required String nodeGroupId,
  }) {
    final now = _clock();
    removeExpired(now);
    final existing = _flows[key];
    if (existing != null) {
      existing.lastSeen = now;
      return existing;
    }
    if (_flows.length >= maxFlows) {
      final oldest = _flows.values.reduce(
        (left, right) => left.lastSeen.isBefore(right.lastSeen) ? left : right,
      );
      _flows.remove(oldest.key);
      oldest.state = ATrustL3FlowState.expired;
    }
    final flow = ATrustL3Flow(
      id: ++_nextId,
      key: key,
      appId: appId,
      nodeGroupId: nodeGroupId,
      now: now,
    );
    _flows[key] = flow;
    return flow;
  }

  /// Refreshes the conntrack state and expiry for a flow from a routed packet.
  void observePacket(ATrustL3FlowKey key, Uint8List packet, bool incoming) {
    final flow = _flows[key];
    if (flow == null) return;
    final now = _clock();
    flow.lastSeen = now;
    final ip = ATrustIPv4Packet(packet);
    if (!ip.valid) {
      flow.expiresAt = now.add(ttl);
      return;
    }
    switch (ip.protocol) {
      case tcpProtocol:
        final tcp = ATrustTCPPacket(ip.payload);
        if (tcp.valid) {
          flow.tcp.observeTcp(tcp, incoming);
          flow.expiresAt = now.add(flow.tcp.ttl);
        } else {
          flow.expiresAt = now.add(ttl);
        }
      case udpProtocol:
        flow.expiresAt = now.add(const Duration(seconds: 120));
      case icmpProtocol:
        flow.expiresAt = now.add(const Duration(seconds: 30));
      default:
        flow.expiresAt = now.add(ttl);
    }
  }

  bool cachePacket(ATrustL3Flow flow, Uint8List packet) {
    if (flow.state != ATrustL3FlowState.pending ||
        flow.pendingPackets.length >= maxPendingPackets) {
      return false;
    }
    flow.pendingPackets.add(Uint8List.fromList(packet));
    flow.lastSeen = _clock();
    return true;
  }

  List<Uint8List> complete(
    int flowId, {
    String? token,
    Object? error,
  }) {
    final flow = _flows.values.cast<ATrustL3Flow?>().firstWhere(
          (value) => value?.id == flowId,
          orElse: () => null,
        );
    if (flow == null || flow.state != ATrustL3FlowState.pending) {
      return const <Uint8List>[];
    }
    flow.token = token;
    flow.error = error;
    flow.state = error == null
        ? ATrustL3FlowState.authenticated
        : ATrustL3FlowState.failed;
    flow.authDeadline = null;
    final packets = List<Uint8List>.from(flow.pendingPackets);
    flow.pendingPackets.clear();
    if (error != null) {
      _flows.remove(flow.key);
    }
    return packets;
  }

  void removeById(int flowId) {
    final flow = flowById(flowId);
    if (flow != null) {
      flow.state = ATrustL3FlowState.expired;
      _flows.remove(flow.key);
    }
  }

  int removeExpired([DateTime? now]) {
    final at = now ?? _clock();
    final expired = _flows.values
        .where((flow) => at.isAfter(flow.expiresAt))
        .toList(growable: false);
    for (final flow in expired) {
      flow.state = ATrustL3FlowState.expired;
      _flows.remove(flow.key);
    }
    return expired.length;
  }
}

String _protocolName(int protocol) => switch (protocol) {
      6 => 'tcp',
      17 => 'udp',
      1 => 'icmp',
      58 => 'icmp6',
      _ => 'ip',
    };

class ATrustL3FlowTransport {
  ATrustL3FlowTransport({
    required this.sid,
    required this.deviceId,
    required this.connectionId,
    required Uint8List signKey,
    this.lang = 'en-US',
    this.env,
    ATrustL3FlowTracker? tracker,
  })  : signKey = Uint8List.fromList(signKey),
        tracker = tracker ?? ATrustL3FlowTracker();

  final String sid;
  final String deviceId;
  final String connectionId;
  final Uint8List signKey;
  final String lang;
  final Map<String, Object?>? env;
  final ATrustL3FlowTracker tracker;

  List<Uint8List> submitPacket({
    required ATrustL3FlowKey key,
    required String appId,
    required String nodeGroupId,
    required Uint8List packet,
  }) {
    final flow = tracker.getOrCreate(
      key,
      appId: appId,
      nodeGroupId: nodeGroupId,
    );
    if (flow.state == ATrustL3FlowState.authenticated && flow.token != null) {
      return <Uint8List>[_dataFrame(flow.token!, packet)];
    }
    if (flow.state != ATrustL3FlowState.pending ||
        !tracker.cachePacket(flow, packet)) {
      return const <Uint8List>[];
    }
    if (flow.authRequested) return const <Uint8List>[];
    flow.authRequested = true;
    return <Uint8List>[_authFrame(flow)];
  }

  List<Uint8List> completeAuthentication(
    int flowId, {
    required String token,
  }) {
    final flow = tracker.flowById(flowId);
    if (flow == null) return const <Uint8List>[];
    final packets = tracker.complete(flowId, token: token);
    return packets
        .map((packet) => _dataFrame(token, packet))
        .toList(growable: false);
  }

  Uint8List authFrameFor(ATrustL3Flow flow) {
    final request = ATrustL3AuthRequest(
      sid: sid,
      appId: flow.appId,
      url:
          '${_protocolName(flow.key.protocol)}:${flow.key.destinationAddress}:${flow.key.destinationPort}',
      deviceId: deviceId,
      connectionId: connectionId,
      lang: lang,
      conntrackHash: flow.id,
      env: env,
      ip: ATrustL3IpInfo(
        atype: 0x0800,
        protocol: flow.key.protocol,
        destinationAddress: flow.key.destinationAddress,
        destinationPort: flow.key.destinationPort,
        sourceAddress: flow.key.sourceAddress,
        sourcePort: flow.key.sourcePort,
      ),
    );
    final payload = Uint8List.fromList(utf8.encode(jsonEncode(
      request.toMap(signKey),
    )));
    if (payload.length > 0xffff) {
      throw ArgumentError('aTrust L3 auth request is too large');
    }
    final frame = BytesBuilder();
    frame.add(
        <int>[ATrustL3Protocol.version, ATrustL3Command.authRequest.value]);
    final length = ByteData(2)..setUint16(0, payload.length, Endian.big);
    frame.add(length.buffer.asUint8List());
    frame.add(payload);
    return frame.toBytes();
  }

  Uint8List _authFrame(ATrustL3Flow flow) => authFrameFor(flow);

  Uint8List _dataFrame(String token, Uint8List packet) =>
      ATrustL3Protocol.dataRequest(token, packet);
}

class ATrustL3Protocol {
  const ATrustL3Protocol._();

  static const int version = 0x05;

  static Uint8List authTunnelRequest(String sid) {
    final payload = Uint8List.fromList(utf8.encode(jsonEncode(<String, String>{
      'sid': sid,
    })));
    if (payload.length > 0xffff) {
      throw ArgumentError.value(payload.length, 'sid', 'payload is too large');
    }
    final result = BytesBuilder();
    result.add(<int>[version, 0x01, 0xd0, 0x53, 0x00]);
    final length = ByteData(2)..setUint16(0, payload.length, Endian.big);
    result.add(length.buffer.asUint8List());
    result.add(payload);
    result
        .add(<int>[0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    return result.toBytes();
  }

  static Uint8List dataRequest(String token, Uint8List packet) {
    if (token.length > 255 || packet.length > 0xffff) {
      throw ArgumentError('aTrust L3 data request is too large');
    }
    final result = BytesBuilder();
    result.add(<int>[version, ATrustL3Command.dataRequest.value, token.length]);
    result.add(utf8.encode(token));
    result.add(<int>[0x00, 0x00, 0x01]);
    final length = ByteData(2)..setUint16(0, packet.length, Endian.big);
    result.add(length.buffer.asUint8List());
    result.add(packet);
    return result.toBytes();
  }

  static Uint8List heartbeatRequest() => Uint8List.fromList(
        <int>[version, ATrustL3Command.heartbeatRequest.value, 0x00, 0x00],
      );

  static ATrustL3Frame decodeFrame(
    Uint8List bytes, {
    int maxPayloadLength = 0xffff,
  }) {
    if (bytes.length < 4 || bytes[0] != version) {
      throw const FormatException('invalid aTrust L3 frame header');
    }
    final command = ATrustL3Command.values.firstWhere(
      (value) => value.value == bytes[1],
      orElse: () => throw FormatException(
        'unknown aTrust L3 command 0x${bytes[1].toRadixString(16)}',
      ),
    );
    var offset = 2;
    var status = 0;
    if (command == ATrustL3Command.authResponse ||
        command == ATrustL3Command.secondVipResponse) {
      if (bytes.length < 5) throw const FormatException('truncated L3 status');
      status = bytes[offset++];
    }
    final length = ByteData.sublistView(bytes, offset, offset + 2)
        .getUint16(0, Endian.big);
    offset += 2;
    if (length > maxPayloadLength || bytes.length != offset + length) {
      throw const FormatException('invalid aTrust L3 payload length');
    }
    return ATrustL3Frame(
      command: command,
      status: status,
      payload: Uint8List.fromList(bytes.sublist(offset)),
    );
  }

  static int parseInitialVIPHeader(Uint8List header) {
    if (header.length != 4) {
      throw FormatException('invalid VIP header length ${header.length}');
    }
    if (header[0] != version) {
      throw FormatException(
        'unexpected VIP version 0x${header[0].toRadixString(16)}',
      );
    }
    if (header[1] != 0) {
      throw FormatException('VIP status ${header[1]}');
    }
    switch (header[3]) {
      case 1:
        return 6;
      case 4:
        return 18;
      case 5:
        return 22;
      default:
        throw FormatException('unsupported VIP address type ${header[3]}');
    }
  }

  static ATrustL3VirtualIP parseVirtualIPData(Uint8List data) {
    final addresses = <String>[];
    switch (data.length) {
      case 6:
        addresses.add('${data[0]}.${data[1]}.${data[2]}.${data[3]}');
      case 18:
        addresses.add(
          InternetAddress.fromRawAddress(
            Uint8List.fromList(data.sublist(0, 16)),
          ).address,
        );
      case 22:
        addresses.add('${data[0]}.${data[1]}.${data[2]}.${data[3]}');
        addresses.add(
          InternetAddress.fromRawAddress(
            Uint8List.fromList(data.sublist(4, 20)),
          ).address,
        );
      default:
        throw FormatException('unexpected VIP data length ${data.length}');
    }
    return ATrustL3VirtualIP(addresses);
  }

  static List<String> extractVIPs(Uint8List payload) {
    final decoded = jsonDecode(utf8.decode(payload));
    if (decoded is! Map) return <String>[];
    final root = Map<String, Object?>.from(decoded);
    final data = root['data'] is Map
        ? Map<String, Object?>.from(root['data'] as Map)
        : <String, Object?>{};
    var vip = root['vip']?.toString() ?? '';
    var vip6 = root['vip6']?.toString() ?? '';
    if (vip.isEmpty && vip6.isEmpty) {
      vip = data['vip']?.toString() ?? '';
      vip6 = data['vip6']?.toString() ?? '';
    }
    final result = <String>[];
    if (vip.isNotEmpty) {
      try {
        final addr = InternetAddress(vip);
        if (addr.type == InternetAddressType.IPv4) result.add(vip);
      } catch (_) {}
    }
    if (vip6.isNotEmpty) {
      try {
        final addr = InternetAddress(vip6);
        if (addr.type == InternetAddressType.IPv6) result.add(vip6);
      } catch (_) {}
    }
    return result;
  }

  static List<Uint8List> parseDataPayload(Uint8List payload) {
    if (payload.length < 4) {
      throw FormatException('data payload too short');
    }
    final tokenLen = payload[0];
    var idx = 1 + tokenLen;
    if (payload.length < idx + 3) {
      throw FormatException('data payload token overflow');
    }
    idx += 2;
    final count = payload[idx];
    idx++;
    final packets = <Uint8List>[];
    for (var i = 0; i < count; i++) {
      if (idx + 2 > payload.length) {
        throw FormatException('packet length overflow');
      }
      final plen =
          ByteData.sublistView(payload, idx, idx + 2).getUint16(0, Endian.big);
      idx += 2;
      if (idx + plen > payload.length) {
        throw FormatException('packet data overflow');
      }
      packets.add(Uint8List.fromList(payload.sublist(idx, idx + plen)));
      idx += plen;
    }
    return packets;
  }

  static ATrustL3TunnelAuthResult parseTunnelAuthResponse(Uint8List bytes) {
    var offset = 0;
    if (bytes.length < 2) {
      throw FormatException('truncated tunnel auth method response');
    }
    if (bytes[0] != version || bytes[1] != 0xD0) {
      throw FormatException(
        'unexpected tunnel auth method response: '
        '0x${bytes[0].toRadixString(16)} 0x${bytes[1].toRadixString(16)}',
      );
    }
    offset += 2;
    if (bytes.length < offset + 4) {
      throw FormatException('truncated tunnel auth header');
    }
    if (bytes[offset] != 0x53) {
      throw FormatException(
        'unexpected tunnel auth response version: 0x${bytes[offset].toRadixString(16)}',
      );
    }
    final status = bytes[offset + 1];
    final authLen = ByteData.sublistView(bytes, offset + 2, offset + 4)
        .getUint16(0, Endian.big);
    offset += 4;
    if (bytes.length < offset + authLen) {
      throw FormatException('truncated tunnel auth payload');
    }
    final authPayload = bytes.sublist(offset, offset + authLen);
    offset += authLen;
    if (status != 0) {
      throw FormatException('tunnel auth status $status');
    }
    String? deviceId;
    if (authLen > 0) {
      final decoded = jsonDecode(utf8.decode(authPayload));
      if (decoded is Map) {
        final map = Map<String, Object?>.from(decoded);
        final code = map['code'] is int
            ? map['code'] as int
            : int.tryParse('${map['code'] ?? 0}') ?? 0;
        if (code != 0) {
          throw FormatException(
            'tunnel auth failed: code $code: ${map['message'] ?? ""}',
          );
        }
        final data = map['data'] is Map
            ? Map<String, Object?>.from(map['data'] as Map)
            : <String, Object?>{};
        deviceId = data['deviceId']?.toString();
      }
    }
    if (bytes.length < offset + 4) {
      throw FormatException('truncated VIP header');
    }
    final vipHeader = Uint8List.fromList(bytes.sublist(offset, offset + 4));
    final vipDataLen = parseInitialVIPHeader(vipHeader);
    offset += 4;
    if (bytes.length < offset + vipDataLen) {
      throw FormatException('truncated VIP data');
    }
    final vipData = Uint8List.fromList(
      bytes.sublist(offset, offset + vipDataLen),
    );
    final vip = parseVirtualIPData(vipData);
    offset += vipDataLen;
    return ATrustL3TunnelAuthResult(
      authStatus: status,
      deviceId: deviceId,
      virtualIP: vip,
      consumed: offset,
    );
  }
}

class ATrustL3Frame {
  const ATrustL3Frame({
    required this.command,
    required this.status,
    required this.payload,
  });

  final ATrustL3Command command;
  final int status;
  final Uint8List payload;
}

class ATrustL3VirtualIP {
  const ATrustL3VirtualIP(this.addresses);

  final List<String> addresses;
}

class ATrustL3TunnelAuthResult {
  const ATrustL3TunnelAuthResult({
    required this.authStatus,
    required this.deviceId,
    required this.virtualIP,
    required this.consumed,
  });

  final int authStatus;
  final String? deviceId;
  final ATrustL3VirtualIP? virtualIP;
  final int consumed;
}

enum ATrustTunnelState {
  idle,
  dialing,
  handshaking,
  active,
  reconnecting,
  closing,
  closed,
  failed,
}

class ATrustTunnelStateMachine {
  ATrustTunnelState _state = ATrustTunnelState.idle;

  ATrustTunnelState get state => _state;

  void transition(ATrustTunnelState next) {
    if (!_allowed(_state, next)) {
      throw StateError('Invalid tunnel transition: $_state -> $next');
    }
    _state = next;
  }

  void fail() {
    if (_state == ATrustTunnelState.closed) {
      throw StateError('A closed tunnel cannot fail');
    }
    _state = ATrustTunnelState.failed;
  }

  void reset() {
    if (_state != ATrustTunnelState.failed &&
        _state != ATrustTunnelState.closed) {
      throw StateError('Only a failed or closed tunnel can reset');
    }
    _state = ATrustTunnelState.idle;
  }

  bool _allowed(ATrustTunnelState current, ATrustTunnelState next) {
    if (current == next) return true;
    return switch (current) {
      ATrustTunnelState.idle => next == ATrustTunnelState.dialing,
      ATrustTunnelState.dialing => next == ATrustTunnelState.handshaking ||
          next == ATrustTunnelState.closing,
      ATrustTunnelState.handshaking =>
        next == ATrustTunnelState.active || next == ATrustTunnelState.closing,
      ATrustTunnelState.active => next == ATrustTunnelState.reconnecting ||
          next == ATrustTunnelState.closing,
      ATrustTunnelState.reconnecting =>
        next == ATrustTunnelState.dialing || next == ATrustTunnelState.closing,
      ATrustTunnelState.closing => next == ATrustTunnelState.closed,
      ATrustTunnelState.closed => false,
      ATrustTunnelState.failed => next == ATrustTunnelState.closing,
    };
  }
}

class ATrustTunnelSendQueue {
  ATrustTunnelSendQueue({this.maxBytes = 4 * 1024 * 1024});

  final int maxBytes;
  final List<Uint8List> _frames = <Uint8List>[];
  int _bytes = 0;

  int get length => _frames.length;
  int get bytes => _bytes;
  bool get isEmpty => _frames.isEmpty;

  bool add(Uint8List frame) {
    if (frame.length > maxBytes - _bytes) return false;
    _frames.add(frame);
    _bytes += frame.length;
    return true;
  }

  Uint8List? removeFirst() {
    if (_frames.isEmpty) return null;
    final frame = _frames.removeAt(0);
    _bytes -= frame.length;
    return frame;
  }

  void clear() {
    _frames.clear();
    _bytes = 0;
  }
}

class ATrustTunnelHeartbeat {
  ATrustTunnelHeartbeat({
    required this.interval,
    required this.onHeartbeat,
    this.onError,
  });

  final Duration interval;
  final Future<void> Function() onHeartbeat;
  final void Function(Object error, StackTrace stackTrace)? onError;
  Timer? _timer;

  bool get isRunning => _timer?.isActive ?? false;

  void start() {
    stop();
    _timer = Timer.periodic(interval, (_) {
      unawaited(onHeartbeat().catchError((Object error, StackTrace stackTrace) {
        onError?.call(error, stackTrace);
      }));
    });
  }

  void stop() {
    _timer?.cancel();
    _timer = null;
  }
}

class ATrustTunnelReconnectPolicy {
  const ATrustTunnelReconnectPolicy({
    this.baseDelay = const Duration(seconds: 1),
    this.maxDelay = const Duration(seconds: 30),
    this.maxAttempts = 5,
  });

  final Duration baseDelay;
  final Duration maxDelay;
  final int maxAttempts;

  Duration delayForAttempt(int attempt) {
    if (attempt < 1) throw ArgumentError.value(attempt, 'attempt');
    if (attempt > maxAttempts) return Duration.zero;
    final multiplier = 1 << (attempt - 1);
    final delay = baseDelay * multiplier;
    return delay <= maxDelay ? delay : maxDelay;
  }
}

abstract interface class ATrustTunnelChannel {
  Stream<List<int>> get incoming;

  Future<void> send(Uint8List bytes);

  Future<void> close();
}

class ATrustSecureSocketChannel implements ATrustTunnelChannel {
  ATrustSecureSocketChannel._(this._socket);

  final SecureSocket _socket;

  /// Wraps an already-established TLS socket.
  factory ATrustSecureSocketChannel.fromSocket(SecureSocket socket) =>
      ATrustSecureSocketChannel._(socket);

  static Future<ATrustSecureSocketChannel> connect(
    String host,
    int port, {
    Duration? timeout,
  }) async {
    final socket = await SecureSocket.connect(
      host,
      port,
      timeout: timeout,
    );
    return ATrustSecureSocketChannel._(socket);
  }

  @override
  Stream<List<int>> get incoming => _socket;

  @override
  Future<void> send(Uint8List bytes) async {
    _socket.add(bytes);
    await _socket.flush();
  }

  @override
  Future<void> close() async => _socket.close();
}

abstract interface class ATrustPacketDevice {
  Stream<Uint8List> get packets;

  Future<void> write(Uint8List packet);

  Future<void> close();
}

class ATrustTunnelIo {
  ATrustTunnelIo({
    ATrustTunnelFrameCodec codec = const ATrustTunnelFrameCodec(),
  }) : _codec = codec;

  final ATrustTunnelFrameCodec _codec;
  final ATrustTunnelFrameDecoder _decoder = ATrustTunnelFrameDecoder();
  final ATrustTunnelSendQueue _sendQueue = ATrustTunnelSendQueue();
  StreamSubscription<Uint8List>? _deviceSubscription;
  StreamSubscription<List<int>>? _channelSubscription;
  ATrustTunnelChannel? _channel;
  ATrustPacketDevice? _device;
  bool _draining = false;

  Future<void> start({
    required ATrustTunnelChannel channel,
    required ATrustPacketDevice device,
  }) async {
    if (_channel != null || _device != null) {
      throw StateError('Tunnel I/O is already started');
    }
    _channel = channel;
    _device = device;
    _channelSubscription = channel.incoming.listen((chunk) async {
      for (final frame in _decoder.add(chunk)) {
        if (frame.type == ATrustTunnelFrameType.data) {
          await device.write(frame.payload);
        }
      }
    });
    _deviceSubscription = device.packets.listen((packet) async {
      final frame = _codec.encode(
        ATrustTunnelFrame(
          type: ATrustTunnelFrameType.data,
          payload: packet,
        ),
      );
      if (_sendQueue.add(frame)) await _drainQueue(channel);
    });
  }

  Future<void> _drainQueue(ATrustTunnelChannel channel) async {
    if (_draining) return;
    _draining = true;
    try {
      while (!_sendQueue.isEmpty) {
        final frame = _sendQueue.removeFirst();
        if (frame == null) break;
        await channel.send(frame);
      }
    } finally {
      _draining = false;
    }
  }

  Future<void> close() async {
    final channel = _channel;
    final device = _device;
    _channel = null;
    _device = null;
    await _deviceSubscription?.cancel();
    await _channelSubscription?.cancel();
    _deviceSubscription = null;
    _channelSubscription = null;
    _decoder.reset();
    _sendQueue.clear();
    _draining = false;
    await channel?.close();
    await device?.close();
  }
}

/// Product-local frame envelope used by the transport boundary.
class ATrustTunnelFrame {
  const ATrustTunnelFrame({required this.type, required this.payload});

  final ATrustTunnelFrameType type;
  final Uint8List payload;
}

/// Length-prefixed frame codec with a one-byte type field.
class ATrustTunnelFrameCodec {
  const ATrustTunnelFrameCodec({this.maxPayloadLength = 16 * 1024 * 1024});

  final int maxPayloadLength;

  Uint8List encode(ATrustTunnelFrame frame) {
    if (frame.payload.length > maxPayloadLength) {
      throw ArgumentError.value(
        frame.payload.length,
        'payload',
        'exceeds maximum tunnel frame payload',
      );
    }
    final bytes = Uint8List(5 + frame.payload.length);
    final data = ByteData.sublistView(bytes);
    data.setUint32(0, frame.payload.length + 1, Endian.big);
    data.setUint8(4, frame.type.value);
    bytes.setRange(5, bytes.length, frame.payload);
    return bytes;
  }
}

/// Incremental decoder for socket chunks that can contain partial or many frames.
class ATrustTunnelFrameDecoder {
  ATrustTunnelFrameDecoder({this.maxFrameLength = 16 * 1024 * 1024 + 1});

  final int maxFrameLength;
  final List<int> _buffer = <int>[];

  List<ATrustTunnelFrame> add(List<int> chunk) {
    _buffer.addAll(chunk);
    final frames = <ATrustTunnelFrame>[];
    while (_buffer.length >= 4) {
      final length = ByteData.sublistView(
        Uint8List.fromList(_buffer.sublist(0, 4)),
      ).getUint32(0, Endian.big);
      if (length < 1 || length > maxFrameLength) {
        _buffer.clear();
        throw FormatException('invalid tunnel frame length $length');
      }
      if (_buffer.length < 4 + length) break;
      final type = ATrustTunnelFrameType.fromValue(_buffer[4]);
      final payload = Uint8List.fromList(_buffer.sublist(5, 4 + length));
      _buffer.removeRange(0, 4 + length);
      frames.add(ATrustTunnelFrame(type: type, payload: payload));
    }
    return frames;
  }

  void reset() => _buffer.clear();
}

/// Stable candidate ordering for a node group: WAN first, then LAN, no duplicates.
List<String> atrustNodeCandidates(
  ATrustResource resource, {
  String? nodeGroupId,
}) {
  final id = nodeGroupId ?? resource.majorNodeGroup;
  final group = resource.nodeGroups[id];
  if (group == null) return const <String>[];
  return <String>{...group.wan, ...group.lan}.toList(growable: false);
}
