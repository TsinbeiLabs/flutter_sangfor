import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'easy_connect.dart';

/// Configuration advertised by /por/conf.csp.
class EasyConnectConfig {
  const EasyConnectConfig({
    this.dnsServers = const <String>[],
    this.backupDnsServers = const <String>[],
    this.mlineServers = const <String>[],
    this.mtu = 1400,
  });

  factory EasyConnectConfig.parse(String xml) {
    final l3vpn = RegExp(r'<L3VPN[^>]*>').firstMatch(xml)?.group(0) ?? '';
    final primary =
        RegExp(r'iptunDns="([^"]*)"').firstMatch(l3vpn)?.group(1) ?? '';
    final backup =
        RegExp(r'iptunDnsBak="([^"]*)"').firstMatch(l3vpn)?.group(1) ?? '';
    final mline = RegExp(r'<Mline[^>]*>').firstMatch(xml)?.group(0) ?? '';
    final mlineList =
        RegExp(r'list="([^"]*)"').firstMatch(mline)?.group(1) ?? '';
    final mtuValue = RegExp(r'mtu="(\d+)"').firstMatch(xml)?.group(1);
    return EasyConnectConfig(
      dnsServers: splitNonEmpty(primary, ';'),
      backupDnsServers: splitNonEmpty(backup, ';'),
      mlineServers: splitNonEmpty(mlineList, ';'),
      mtu: int.tryParse(mtuValue ?? '') ?? 1400,
    );
  }

  final List<String> dnsServers;
  final List<String> backupDnsServers;
  final List<String> mlineServers;
  final int mtu;

  static List<String> splitNonEmpty(String value, String separator) => value
      .split(separator)
      .map((item) => item.trim())
      .where((item) => item.isNotEmpty && item != '0.0.0.0')
      .toList(growable: false);
}

/// A routed resource entry advertised by /por/rclist.csp.
class EasyConnectResourceEntry {
  const EasyConnectResourceEntry({
    required this.id,
    required this.name,
    required this.type,
    required this.protocol,
    required this.host,
    required this.portMin,
    required this.portMax,
  });

  final String id;
  final String name;
  final int type;
  final int protocol;
  final String host;
  final int portMin;
  final int portMax;
}

/// Resource list parsed from /por/rclist.csp.
class EasyConnectResourceList {
  const EasyConnectResourceList({
    required this.entries,
    required this.dnsServers,
    this.defaultResourceId,
  });

  factory EasyConnectResourceList.parse(String xml) {
    final entries = <EasyConnectResourceEntry>[];
    for (final match in RegExp(r'<Rc\s[^>]*>').allMatches(xml)) {
      final tag = match.group(0)!;
      final id = _attr(tag, 'id');
      if (id.isEmpty) continue;
      final type = int.tryParse(_attr(tag, 'type')) ?? 0;
      if (type != 1 && type != 2) continue;
      final protoValue = int.tryParse(_attr(tag, 'proto')) ?? -1;
      final hosts = _attr(tag, 'host').split(';');
      final ports = _attr(tag, 'port').split(';');
      for (var index = 0; index < hosts.length; index++) {
        final host = hosts[index].trim();
        if (host.isEmpty) continue;
        final (portMin, portMax) = _portRange(
          index < ports.length ? ports[index] : '',
        );
        entries.add(EasyConnectResourceEntry(
          id: id,
          name: _attr(tag, 'name'),
          type: type,
          protocol: protoValue,
          host: host,
          portMin: portMin,
          portMax: portMax,
        ));
      }
    }
    final dns =
        RegExp(r'<Dns[^>]*dnsserver="([^"]*)"').firstMatch(xml)?.group(1) ?? '';
    final defaultId =
        RegExp(r'<Other[^>]*defaultRcId="([^"]*)"').firstMatch(xml)?.group(1) ??
            '';
    return EasyConnectResourceList(
      entries: entries,
      dnsServers: EasyConnectConfig.splitNonEmpty(dns, ';'),
      defaultResourceId: defaultId.isEmpty ? null : defaultId,
    );
  }

  final List<EasyConnectResourceEntry> entries;
  final List<String> dnsServers;
  final String? defaultResourceId;

  static String _attr(String tag, String name) =>
      RegExp('$name="([^"]*)"').firstMatch(tag)?.group(1) ?? '';

  static (int, int) _portRange(String value) {
    final parts = value.split('~');
    final first = int.tryParse(parts.first.trim()) ?? 0;
    final last =
        parts.length == 1 ? first : int.tryParse(parts.last.trim()) ?? first;
    return (first, last);
  }
}

/// EasyConnect L3 tunnel wire protocol.
class EasyConnectTunnelProtocol {
  const EasyConnectTunnelProtocol._();

  static const int queryIpOp = 0;
  static const int commandHeartbeatOp = 3;
  static const int txStreamOp = 5;
  static const int rxStreamOp = 6;
  static const int txResumeOp = 7;
  static const int rxResumeOp = 8;

  static const int queryIpReplyLength = 36;
  static const int nativeControlFrameLength = 40;

  /// Derives the 32-byte agent token from a TLS session id.
  static Uint8List deriveAgentToken(List<int> tlsSessionId) {
    final hexString = tlsSessionId
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join();
    if (hexString.length < 31) {
      throw ArgumentError('TLS session id is too short for token derivation');
    }
    return Uint8List.fromList(
      <int>[...utf8.encode(hexString.substring(0, 31)), 0x00],
    );
  }

  /// Builds the 48-byte tunnel token from the agent token and TWFID.
  static Uint8List deriveToken(List<int> tlsSessionId, String twfId) {
    final agentToken = deriveAgentToken(tlsSessionId);
    final twfIdBytes = utf8.encode(twfId);
    if (twfIdBytes.length != 16) {
      throw ArgumentError('TWFID must be exactly 16 bytes');
    }
    return Uint8List.fromList(<int>[...agentToken, ...twfIdBytes]);
  }

  static Uint8List queryIpMessage(Uint8List token) =>
      _handshakeMessage(queryIpOp, token, <int>[0xff, 0xff, 0xff, 0xff]);

  static Uint8List txStreamMessage(Uint8List token, List<int> reversedIp) =>
      _handshakeMessage(txStreamOp, token, reversedIp);

  static Uint8List rxStreamMessage(Uint8List token, List<int> reversedIp) =>
      _handshakeMessage(rxStreamOp, token, reversedIp);

  static Uint8List commandHeartbeatMessage(Uint8List token) =>
      _handshakeMessage(commandHeartbeatOp, token, <int>[0, 0, 0, 0]);

  static Uint8List txResumeMessage(Uint8List token, List<int> reversedIp) =>
      _handshakeMessage(txResumeOp, token, reversedIp);

  static Uint8List rxResumeMessage(Uint8List token, List<int> reversedIp) =>
      _handshakeMessage(rxResumeOp, token, reversedIp);

  static Uint8List _handshakeMessage(
    int op,
    Uint8List token,
    List<int> trailing,
  ) {
    if (token.length != 48) {
      throw ArgumentError('Tunnel token must be exactly 48 bytes');
    }
    if (trailing.length != 4) {
      throw ArgumentError('Handshake trailing bytes must be 4');
    }
    final message = Uint8List(64);
    final data = ByteData.sublistView(message);
    data.setUint32(0, op, Endian.little);
    message.setRange(4, 52, token);
    message.setRange(52, 60, List<int>.filled(8, 0));
    message.setRange(60, 64, trailing);
    return message;
  }

  /// Parses the Query-IP response and returns (clientIp, serverLanIp).
  static (List<int>, List<int>) parseQueryIpResponse(Uint8List bytes) {
    if (bytes.length < 16) {
      throw FormatException('Query-IP reply is too short');
    }
    final data = ByteData.sublistView(bytes);
    final code = data.getUint32(0, Endian.little);
    if (code != 0) {
      throw FormatException('Query-IP reply failed with code $code');
    }
    final clientIp = bytes.sublist(4, 8);
    final serverLanIp = bytes.sublist(12, 16);
    return (clientIp, serverLanIp);
  }

  static bool isNativeControlFrame(Uint8List bytes) =>
      bytes.length >= nativeControlFrameLength &&
      bytes[0] == 0x41 &&
      bytes[1] == 0x41 &&
      bytes[2] == 0x42 &&
      bytes[3] == 0x42;

  /// Parses a stream handshake reply and returns the control code.
  static int parseStreamResponse(Uint8List bytes, int expectedCode) {
    if (bytes.isEmpty) {
      throw FormatException('Stream handshake reply is empty');
    }
    if (isNativeControlFrame(bytes)) {
      return ByteData.sublistView(bytes).getUint32(4, Endian.little);
    }
    if (bytes.length >= 4) {
      final code = ByteData.sublistView(bytes).getUint32(0, Endian.little);
      if (code == expectedCode) return code;
    }
    if (bytes[0] == expectedCode) return expectedCode;
    throw FormatException(
      'Unexpected stream handshake reply: expected $expectedCode, '
      'got ${bytes[0]}',
    );
  }

  /// Parses a 40-byte native control frame and returns the control code.
  static int parseNativeControlFrame(Uint8List bytes) {
    if (!isNativeControlFrame(bytes)) {
      throw FormatException('Invalid native control frame');
    }
    return ByteData.sublistView(bytes).getUint32(4, Endian.little);
  }

  /// Builds the 76-byte TX ICMP keepalive packet.
  static Uint8List heartbeatPacket(
    List<int> clientIp,
    List<int> serverLanIp,
    Uint8List token,
  ) {
    if (clientIp.length != 4 || serverLanIp.length != 4) {
      throw ArgumentError('Heartbeat endpoints must be 4-byte IPv4');
    }
    if (token.length != 48) {
      throw ArgumentError('Tunnel token must be exactly 48 bytes');
    }
    final packet = Uint8List(76);
    packet[0] = 0x45;
    packet[1] = 0x00;
    packet[2] = 0x00;
    packet[3] = 0x4c;
    packet[4] = 0xbb;
    packet[5] = 0xaa;
    packet[6] = 0x00;
    packet[7] = 0x00;
    packet[8] = 0x40;
    packet[9] = 0x01;
    packet.setRange(12, 16, clientIp);
    packet.setRange(16, 20, serverLanIp);
    final ipChecksum = _internetChecksum(packet.sublist(0, 20));
    packet[10] = (ipChecksum >> 8) & 0xff;
    packet[11] = ipChecksum & 0xff;
    packet[20] = 0x08;
    packet[21] = 0x00;
    packet[24] = 0x55;
    packet[25] = 0x55;
    packet[26] = 0x44;
    packet[27] = 0x33;
    const marker = 'SANGFORSCSIPCLIENT';
    packet.setRange(28, 28 + marker.length, utf8.encode(marker));
    packet.setRange(46, 62, token.sublist(32, 48));
    final random = Random.secure();
    for (var index = 62; index < 70; index++) {
      packet[index] = random.nextInt(256);
    }
    const tail = 'L3VPN';
    packet.setRange(70, 75, utf8.encode(tail));
    packet[75] = 0x00;
    final icmpChecksum = _internetChecksum(packet.sublist(20));
    packet[22] = (icmpChecksum >> 8) & 0xff;
    packet[23] = icmpChecksum & 0xff;
    return packet;
  }

  static int _internetChecksum(List<int> data) {
    var sum = 0;
    for (var index = 0; index < data.length; index += 2) {
      final word = index + 1 < data.length
          ? (data[index] << 8) | data[index + 1]
          : data[index] << 8;
      sum += word;
      while (sum > 0xffff) {
        sum = (sum & 0xffff) + (sum >> 16);
      }
    }
    return (~sum) & 0xffff;
  }
}

/// Keepalive client for /por/update_session.csp.
class EasyConnectKeepaliveClient {
  EasyConnectKeepaliveClient({
    http.Client? client,
    this.interval = const Duration(seconds: 60),
  }) : _client = client ?? http.Client();

  final http.Client _client;
  final Duration interval;
  Timer? _timer;

  Future<bool> ping(Uri server, String twfId) async {
    final uri = server.replace(
      path: '/por/update_session.csp',
      queryParameters: <String, String>{
        'twfid': twfId,
        'apiversion': '1',
      },
    );
    final response = await _client.get(
      uri,
      headers: <String, String>{
        'cookie': 'TWFID=$twfId',
        'user-agent': 'EasyConnect_Linux_Ubuntu',
      },
    );
    if (response.statusCode == 404) return false;
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw EasyConnectApiException(
        'EasyConnect keepalive returned HTTP ${response.statusCode}',
        statusCode: response.statusCode,
      );
    }
    final errorCode = RegExp(r'<ErrorCode>(\d+)</ErrorCode>')
            .firstMatch(response.body)
            ?.group(1) ??
        '';
    return errorCode == '1';
  }

  void start(
    Uri server,
    String twfId, {
    void Function(Object error)? onError,
  }) {
    stop();
    _timer = Timer.periodic(interval, (_) {
      ping(server, twfId).catchError((Object error) {
        onError?.call(error);
        return false;
      });
    });
  }

  void stop() {
    _timer?.cancel();
    _timer = null;
  }
}
