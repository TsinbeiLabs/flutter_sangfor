import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

class ATrustTcpTunnelProcess {
  const ATrustTcpTunnelProcess({
    required this.name,
    required this.path,
    this.digitalSignature = 'TrustAppClosed',
    this.platform = 'Linux',
    this.description = 'TrustAppClosed',
    this.version = 'TrustAppClosed',
    this.securityEnv = 'normal',
  });

  final String name;
  final String path;
  final String digitalSignature;
  final String platform;
  final String description;
  final String version;
  final String securityEnv;

  String get fingerprint =>
      sha256.convert(utf8.encode(path)).toString().toUpperCase();

  Map<String, Object?> toMap() => <String, Object?>{
        'name': name,
        'digital_signature': digitalSignature,
        'platform': platform,
        'fingerprint': fingerprint,
        'description': description,
        'path': path,
        'version': version,
        'security_env': securityEnv,
      };
}

class ATrustTcpTunnelAuthRequest {
  const ATrustTcpTunnelAuthRequest({
    required this.sid,
    required this.appId,
    required this.url,
    required this.deviceId,
    required this.connectionId,
    required this.procHash,
    required this.userName,
    required this.lang,
    required this.destAddr,
    this.destIp,
    this.rcAppliedInfo = 0,
    this.process,
  });

  final String sid;
  final String appId;
  final String url;
  final String deviceId;
  final String connectionId;
  final String procHash;
  final String userName;
  final String lang;
  final String destAddr;
  final String? destIp;
  final int rcAppliedInfo;
  final ATrustTcpTunnelProcess? process;

  Map<String, Object?> env() => <String, Object?>{
        'application': <String, Object?>{
          'runtime': <String, Object?>{
            'process': process?.toMap() ?? <String, Object?>{},
            'process_trusted': 'TRUSTED',
          },
        },
      };

  Map<String, Object?> unsignedMap() => <String, Object?>{
        'sid': sid,
        'appId': appId,
        'url': url,
        'deviceId': deviceId,
        'connectionId': connectionId,
        'procHash': procHash,
        'userName': userName,
        'rcAppliedInfo': rcAppliedInfo,
        'lang': lang,
        'destAddr': destAddr,
        if (destIp != null) 'destIP': destIp,
        'env': env(),
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

class ATrustTcpTunnelServerResponse {
  const ATrustTcpTunnelServerResponse({
    required this.authCode,
    required this.authMessage,
    required this.connectStatus,
    required this.reuse,
    required this.consumed,
  });

  final int authCode;
  final String authMessage;
  final int connectStatus;
  final bool reuse;
  final int consumed;
}

class ATrustTcpTunnelProtocol {
  const ATrustTcpTunnelProtocol._();

  static const int version = 0x05;

  static Uint8List handshakeMessage(
    ATrustTcpTunnelAuthRequest request,
    Uint8List signKey,
    String host,
    int port, {
    bool zeroRtt = false,
  }) {
    final authJson = Uint8List.fromList(
      utf8.encode(jsonEncode(request.toMap(signKey))),
    );
    if (authJson.length > 0xffff) {
      throw ArgumentError('TCP tunnel auth request is too large');
    }
    final result = BytesBuilder();
    result.add(<int>[version, 0x01, 0x81, 0x53, 0x03]);
    final length = ByteData(2)..setUint16(0, authJson.length, Endian.big);
    result.add(length.buffer.asUint8List());
    result.add(authJson);
    result.add(destinationMessage(host, port, zeroRtt: zeroRtt));
    return result.toBytes();
  }

  static Uint8List destinationMessage(
    String host,
    int port, {
    bool zeroRtt = false,
  }) {
    final result = BytesBuilder();
    result.add(<int>[version, 0x01, zeroRtt ? 1 : 0]);
    final address = InternetAddress.tryParse(host);
    if (address != null && address.type == InternetAddressType.IPv4) {
      result.add(<int>[0x01]);
      result.add(address.rawAddress);
    } else if (address != null && address.type == InternetAddressType.IPv6) {
      result.add(<int>[0x04]);
      result.add(address.rawAddress);
    } else {
      final hostBytes = utf8.encode(host);
      if (hostBytes.length > 255) {
        throw ArgumentError('TCP tunnel destination host is too long');
      }
      result.add(<int>[0x03, hostBytes.length]);
      result.add(hostBytes);
    }
    final portBytes = ByteData(2)..setUint16(0, port, Endian.big);
    result.add(portBytes.buffer.asUint8List());
    return result.toBytes();
  }

  static ATrustTcpTunnelServerResponse parseServerResponse(Uint8List bytes) {
    var offset = 0;
    if (bytes.length < 2 || bytes[0] != version || bytes[1] != 0x81) {
      throw FormatException('unexpected TCP tunnel server hello');
    }
    offset += 2;
    if (bytes.length < offset + 2 ||
        bytes[offset] != 0x53 ||
        bytes[offset + 1] != 0x00) {
      throw FormatException('unexpected TCP tunnel auth response');
    }
    offset += 2;
    if (bytes.length < offset + 2) {
      throw FormatException('truncated TCP tunnel auth response');
    }
    final authLen = ByteData.sublistView(bytes, offset, offset + 2)
        .getUint16(0, Endian.big);
    offset += 2;
    if (bytes.length < offset + authLen) {
      throw FormatException('truncated TCP tunnel auth response');
    }
    final authPayload = bytes.sublist(offset, offset + authLen);
    offset += authLen;
    var authCode = 0;
    var authMessage = '';
    if (authLen > 0) {
      final decoded = jsonDecode(utf8.decode(authPayload));
      if (decoded is Map) {
        final map = Map<String, Object?>.from(decoded);
        authCode = map['code'] is int
            ? map['code'] as int
            : int.tryParse('${map['code'] ?? 0}') ?? 0;
        authMessage = map['message']?.toString() ?? '';
      }
    }
    if (bytes.length < offset + 4) {
      throw FormatException('truncated TCP tunnel connect reply');
    }
    if (bytes[offset] != version) {
      throw FormatException('unexpected TCP tunnel connect reply version');
    }
    final connectStatus = bytes[offset + 1];
    if (connectStatus != 0x00) {
      return ATrustTcpTunnelServerResponse(
        authCode: authCode,
        authMessage: authMessage,
        connectStatus: connectStatus,
        reuse: false,
        consumed: offset + 4,
      );
    }
    final reuse = bytes[offset + 2] == 0x01;
    final addressType = bytes[offset + 3];
    final addressLength = switch (addressType) {
      0x01 => 4,
      0x04 => 16,
      _ => throw FormatException(
          'unexpected bind address type 0x${addressType.toRadixString(16)}',
        ),
    };
    if (bytes.length < offset + 4 + addressLength + 2) {
      throw FormatException('truncated TCP tunnel connect reply');
    }
    offset += 4 + addressLength + 2;
    return ATrustTcpTunnelServerResponse(
      authCode: authCode,
      authMessage: authMessage,
      connectStatus: connectStatus,
      reuse: reuse,
      consumed: offset,
    );
  }

  static String connectStatusMessage(int status) => switch (status) {
        0x00 => 'success',
        0x01 => 'tcp tunnel server failure',
        0x02 => 'tcp tunnel connection not allowed',
        0x03 => 'network is unreachable',
        0x04 => 'host is unreachable',
        0x05 => 'connection refused',
        0x06 => 'tcp tunnel TTL expired',
        0x07 => 'tcp tunnel command not supported',
        0x08 => 'tcp tunnel address type not supported',
        _ => 'tcp tunnel connect failed with status 0x'
            '${status.toRadixString(16)}',
      };

  static Uint8List dataFrame(Uint8List data) {
    if (data.length > 0xffff) {
      throw ArgumentError('TCP tunnel data frame is too large');
    }
    final result = BytesBuilder();
    result.add(<int>[0x01, 0x00]);
    final length = ByteData(2)..setUint16(0, data.length, Endian.big);
    result.add(length.buffer.asUint8List());
    result.add(data);
    return result.toBytes();
  }

  static List<Uint8List> dataFrames(Uint8List data) {
    if (data.isEmpty) return <Uint8List>[];
    final frames = <Uint8List>[];
    for (var offset = 0; offset < data.length; offset += 0xffff) {
      final end = offset + 0xffff > data.length ? data.length : offset + 0xffff;
      frames.add(dataFrame(Uint8List.sublistView(data, offset, end)));
    }
    return frames;
  }

  static Uint8List eofFrame() =>
      Uint8List.fromList(<int>[0x01, 0x01, 0x00, 0x00]);

  static (Uint8List, bool) parseDataFrame(Uint8List bytes) {
    if (bytes.length < 4) {
      throw FormatException('truncated TCP tunnel data frame');
    }
    if (bytes[0] != 0x01) {
      throw FormatException('unexpected TCP tunnel data frame header');
    }
    if (bytes[1] == 0x01) {
      return (Uint8List(0), true);
    }
    if (bytes[1] != 0x00) {
      throw FormatException('unexpected TCP tunnel data frame type');
    }
    final length = ByteData.sublistView(bytes, 2, 4).getUint16(0, Endian.big);
    if (bytes.length < 4 + length) {
      throw FormatException('truncated TCP tunnel data frame');
    }
    return (Uint8List.fromList(bytes.sublist(4, 4 + length)), false);
  }
}
