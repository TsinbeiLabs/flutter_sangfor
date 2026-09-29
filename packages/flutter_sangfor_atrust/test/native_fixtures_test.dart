import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_sangfor_atrust/flutter_sangfor_atrust.dart';
// The IPv4/TCP builder is an internal detail of the root package; the golden
// fixtures have to pin its exact bytes, which is the whole point of this file.
// ignore: implementation_imports
import 'package:flutter_sangfor/src/tcp_packet_codec.dart';
import 'package:test/test.dart';

/// Golden fixtures for the native (Swift) aTrust data plane that runs inside
/// the iOS packet tunnel extension. The Dart implementation is the reference:
/// the extension must produce byte-identical JSON, signatures, and frames, or
/// the gateway rejects it.
///
/// Regenerate after a protocol change with:
///   UPDATE_NATIVE_FIXTURES=1 flutter test test/native_fixtures_test.dart
///
/// The file lives in the root package because that is where the Swift core and
/// its test harness are.
/// A synthetic certificate body: only its bytes matter for the digest.
final Uint8List _sampleCertificateDer = Uint8List.fromList(
  List<int>.generate(128, (index) => (index * 7 + 13) & 0xff),
);

String get _fixturePath =>
    '../flutter_sangfor/test/fixtures/native_atrust.json';

String _hex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

/// The environment block the native extension reports, spelled out instead of
/// taken from `ATrustL3ClientInfo.defaultEnv()`: that one embeds the *host*
/// platform name, which would make this golden file depend on the machine
/// generating it.
Map<String, Object?> _nativeEnv(String fingerprint) => <String, Object?>{
      'application': <String, Object?>{
        'runtime': <String, Object?>{
          'process': <String, Object?>{
            'name': 'Luotopia',
            'digital_signature': 'TrustAppClosed',
            'platform': 'iOS',
            'fingerprint': fingerprint,
            'description': 'TrustAppClosed',
            'path': _processPath,
            'version': 'TrustAppClosed',
            'security_env': 'normal',
          },
          'process_trusted': 'TRUSTED',
        },
      },
    };

const String _processPath =
    '/var/mobile/Containers/Bundle/Application/Luotopia.app';

Map<String, Object?> buildNativeFixtures() {
  final signKey = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
  final processPath = _processPath;
  final fingerprint =
      sha256.convert(utf8.encode(processPath)).toString().toUpperCase();
  final info = ATrustL3ClientInfo(
    sid: 'REDACTED_SID',
    deviceId: 'REDACTED_DEVICE',
    connectionId: 'REDACTED_CONNECTION',
    username: 'alice',
    processName: 'Luotopia',
    processPath: processPath,
    lang: 'zh-CN',
  );

  final flowKey = ATrustL3FlowKey(
    protocol: 6,
    sourceAddress: '10.0.0.42',
    sourcePort: 51000,
    destinationAddress: '203.0.113.7',
    destinationPort: 443,
  );
  final flow = ATrustL3Flow(
    id: 7,
    key: flowKey,
    appId: 'app-42',
    nodeGroupId: 'group-1',
    now: DateTime.utc(2026, 1, 1),
  );
  final transport = ATrustL3FlowTransport(
    sid: info.sid,
    deviceId: info.deviceId,
    connectionId: info.connectionId,
    signKey: signKey,
    lang: info.lang,
    env: _nativeEnv(fingerprint),
  );

  final authRequest = ATrustL3AuthRequest(
    sid: info.sid,
    appId: 'app-42',
    url: 'tcp:203.0.113.7:443',
    deviceId: info.deviceId,
    connectionId: info.connectionId,
    lang: info.lang,
    conntrackHash: 7,
    env: _nativeEnv(fingerprint),
    ip: ATrustL3IpInfo(
      atype: 0x0800,
      protocol: 6,
      destinationAddress: '203.0.113.7',
      destinationPort: 443,
      sourceAddress: '10.0.0.42',
      sourcePort: 51000,
    ),
  );
  final unsignedJson = jsonEncode(authRequest.unsignedMap());

  final tcpRequest = ATrustTcpTunnelAuthRequest(
    sid: info.sid,
    appId: 'app-42',
    url: 'tcp://vpn.example.test:443',
    deviceId: info.deviceId,
    connectionId: info.connectionId,
    procHash: fingerprint,
    userName: info.username,
    lang: info.lang,
    destAddr: 'vpn.example.test:443',
    destIp: '203.0.113.7',
    process: ATrustTcpTunnelProcess(
      name: info.processName,
      path: processPath,
      platform: 'iOS',
    ),
  );

  final samplePacket = Uint8List.fromList(<int>[
    0x45, 0, 0, 40, 0, 1, 0, 0, 64, 6, 0, 0, // IPv4 header (20)
    10, 0, 0, 42, 203, 0, 113, 7, //
    0xc7, 0x38, 0x01, 0xbb, // ports 51000 -> 443
    0, 0, 0, 1, // sequence
    0, 0, 0, 0, // acknowledgment
    0x50, 0x02, 0x20, 0x00, // data offset 5, SYN, window
    0, 0, 0, 0, // checksum, urgent
  ]);
  final meta = buildPacketMeta(samplePacket)!;

  return <String, Object?>{
    'signKeyHex': _hex(signKey),
    'sha256': <String, String>{
      'empty': _hex(sha256.convert(<int>[]).bytes),
      'abc': _hex(sha256.convert('abc'.codeUnits).bytes),
      'long': _hex(
        sha256.convert(List<int>.generate(1000, (index) => index % 251)).bytes,
      ),
    },
    'hmacSha256': <String, String>{
      'abcKeyAbcData': _hex(
        Hmac(sha256, 'abc'.codeUnits).convert('abc'.codeUnits).bytes,
      ),
      'signKeyOverAuthJson': _hex(
        Hmac(sha256, signKey).convert(utf8.encode(unsignedJson)).bytes,
      ),
    },
    'processFingerprint': fingerprint,
    // The anti-MITM pin digest: sha256 of the base64 certificate plus the
    // gateway's salt, uppercase hex. The native TLS transport has to compute
    // exactly this or every pinned node connection fails.
    'certificateDigest': <String, String>{
      'derBase64': base64Encode(_sampleCertificateDer),
      'digest': ATrustAntiMitmData(
        enable: 1,
        devicePublicKeyModulus: '',
        devicePublicKeyExponent: '',
        challenge: '',
        encryptedChallenge: '',
        mitmSignature: '',
        rsaCertificate: base64Encode(_sampleCertificateDer),
      ).certificateDigests.single,
    },
    // The hand-off document the iOS packet tunnel extension decodes with
    // Swift's Codable; the native side must accept it verbatim.
    'sessionPlan': ATrustSessionPlan(
      sid: 'REDACTED_SID',
      deviceId: 'REDACTED_DEVICE',
      connectionId: 'REDACTED_CONNECTION',
      username: 'alice',
      signKey: signKey,
      lang: 'zh-CN',
      processName: 'Luotopia',
      processPath: processPath,
      processPlatform: 'iOS',
      nodes: const <String, List<String>>{
        'group-1': <String>['203.0.113.9:441', '203.0.113.10:441'],
        'group-2': <String>['203.0.113.11:441'],
      },
      majorNodeGroup: 'group-1',
      routes: const <ATrustRoute>[
        ATrustRoute(
          host: '10.9.0.0/16',
          protocol: 'tcp',
          portMin: 0,
          portMax: 65535,
          appId: 'app-tcp',
          nodeGroupId: 'group-1',
          addrPretend: false,
          enableTcpPrefL3: false,
        ),
        ATrustRoute(
          host: 'vpn.example.test',
          protocol: 'tcp',
          portMin: 443,
          portMax: 443,
          appId: 'app-domain',
          nodeGroupId: 'group-2',
          addrPretend: true,
          enableTcpPrefL3: false,
        ),
        ATrustRoute(
          host: '10.1.0.0/16',
          protocol: 'all',
          portMin: 0,
          portMax: 65535,
          appId: 'app-l3',
          nodeGroupId: 'group-1',
          addrPretend: false,
          enableTcpPrefL3: true,
        ),
      ],
      dnsServers: const <String>['203.0.113.53'],
      virtualAddress: '10.0.0.42',
      certificateDigests: const <String>[],
      acceptAnyCertificate: true,
      dialHosts: const <String, String>{'203.0.113.7': 'vpn.example.test'},
    ).encode(),
    // Pins the exact escaping Dart's jsonEncode produces, which the native
    // encoder has to reproduce byte for byte: the signature covers this text.
    'jsonEscaping': jsonEncode(<String, Object?>{
      'quote': 'a"b',
      'backslash': 'a\\b',
      'tab': 'a\tb',
      'newline': 'a\nb',
      'carriageReturn': 'a\rb',
      'backspace': 'a\bb',
      'formFeed': 'a\fb',
      'control': 'a\u0001b\u001fb',
      'delete': 'a\u007fb',
      'nonAscii': 'aé中b',
      'int': 7,
      'negativeInt': -12,
      'true': true,
      'false': false,
      'null': null,
      'array': <Object?>[
        1,
        'two',
        <String, Object?>{'three': 3}
      ],
      'emptyObject': <String, Object?>{},
      'emptyArray': <Object?>[],
    }),
    'l3': <String, Object?>{
      'authUnsignedJson': unsignedJson,
      'authSignature': authRequest.signature(signKey),
      'authRequestFrameHex': _hex(transport.authFrameFor(flow)),
      'authTunnelRequestHex': _hex(
        ATrustL3Protocol.authTunnelRequest(info.sid),
      ),
      'dataRequestFrameHex': _hex(
        ATrustL3Protocol.dataRequest('tok-1', samplePacket),
      ),
      'heartbeatFrameHex': _hex(ATrustL3Protocol.heartbeatRequest()),
      'vipHeaderLengths': <String, int>{
        'ipv4': ATrustL3Protocol.parseInitialVIPHeader(
          Uint8List.fromList(<int>[0x05, 0x00, 0x00, 0x01]),
        ),
        'ipv6': ATrustL3Protocol.parseInitialVIPHeader(
          Uint8List.fromList(<int>[0x05, 0x00, 0x00, 0x04]),
        ),
        'dual': ATrustL3Protocol.parseInitialVIPHeader(
          Uint8List.fromList(<int>[0x05, 0x00, 0x00, 0x05]),
        ),
      },
      'handshakeResponseHex': _hex(_handshakeResponse()),
      'handshakeVip': '10.0.0.42',
    },
    'tcpTunnel': <String, Object?>{
      'unsignedJson': jsonEncode(tcpRequest.unsignedMap()),
      'signature': tcpRequest.signature(signKey),
      'handshakeHex': _hex(
        ATrustTcpTunnelProtocol.handshakeMessage(
          tcpRequest,
          signKey,
          'vpn.example.test',
          443,
        ),
      ),
      'destinationDomainHex': _hex(
        ATrustTcpTunnelProtocol.destinationMessage('vpn.example.test', 443),
      ),
      'destinationIpv4Hex': _hex(
        ATrustTcpTunnelProtocol.destinationMessage('203.0.113.7', 443),
      ),
      'dataFrameHex': _hex(
        ATrustTcpTunnelProtocol.dataFrame(
          Uint8List.fromList(<int>[1, 2, 3, 4, 5]),
        ),
      ),
      'eofFrameHex': _hex(ATrustTcpTunnelProtocol.eofFrame()),
      'serverResponseHex': _hex(_tcpServerResponse()),
      'serverResponse': <String, Object?>{
        'authCode': ATrustTcpTunnelProtocol.parseServerResponse(
          _tcpServerResponse(),
        ).authCode,
        'connectStatus': ATrustTcpTunnelProtocol.parseServerResponse(
          _tcpServerResponse(),
        ).connectStatus,
        'reuse': ATrustTcpTunnelProtocol.parseServerResponse(
          _tcpServerResponse(),
        ).reuse,
        'consumed': ATrustTcpTunnelProtocol.parseServerResponse(
          _tcpServerResponse(),
        ).consumed,
      },
    },
    'packet': <String, Object?>{
      'sampleHex': _hex(samplePacket),
      'meta': <String, Object?>{
        'atype': meta.atype,
        'protocol': meta.protocol,
        'sourceAddress': meta.sourceAddress,
        'sourcePort': meta.sourcePort,
        'destinationAddress': meta.destinationAddress,
        'destinationPort': meta.destinationPort,
      },
      'splitHexes': <String>[
        for (final packet in splitIncomingIPPackets(
          Uint8List.fromList(<int>[...samplePacket, ...samplePacket]),
        ).$1)
          _hex(packet),
      ],
      // A fully built IPv4/TCP packet, checksums included: the native builder
      // has to reproduce it byte for byte or the local stack drops it.
      'builtTcpHex': _hex(
        const SangforTcpPacketBuilder().build(
          sourceAddress: '203.0.113.7',
          destinationAddress: '10.0.0.42',
          sourcePort: 443,
          destinationPort: 51000,
          sequenceNumber: 0x11223344,
          acknowledgmentNumber: 0x55667788,
          flags: tcpFlagSyn | tcpFlagAck,
          window: 64240,
          payload: Uint8List.fromList(<int>[1, 2, 3, 4, 5]),
          mss: 1400,
          identification: 7,
        ),
      ),
      'builtTcpNoPayloadHex': _hex(
        const SangforTcpPacketBuilder().build(
          sourceAddress: '203.0.113.7',
          destinationAddress: '10.0.0.42',
          sourcePort: 443,
          destinationPort: 51000,
          sequenceNumber: 1,
          acknowledgmentNumber: 2,
          flags: tcpFlagAck,
          window: 65535,
          identification: 9,
        ),
      ),
    },
  };
}

/// A synthetic authTunnel handshake response: method ack, auth payload, VIP.
Uint8List _handshakeResponse() {
  final payload = utf8.encode(
    jsonEncode(<String, Object?>{
      'code': 0,
      'message': 'ok',
      'data': <String, Object?>{'deviceId': 'REDACTED_DEVICE'},
    }),
  );
  final builder = BytesBuilder();
  builder.add(<int>[0x05, 0xD0, 0x53, 0x00]);
  builder.add((ByteData(2)..setUint16(0, payload.length, Endian.big))
      .buffer
      .asUint8List());
  builder.add(payload);
  builder.add(<int>[0x05, 0x00, 0x00, 0x01]);
  builder.add(<int>[10, 0, 0, 42, 0, 0]);
  return builder.toBytes();
}

/// A synthetic TCP tunnel server hello: auth ok, connect ok, IPv4 bind.
Uint8List _tcpServerResponse() {
  final payload = utf8.encode(
    jsonEncode(<String, Object?>{'code': 0, 'message': 'ok'}),
  );
  final builder = BytesBuilder();
  builder.add(<int>[0x05, 0x81, 0x53, 0x00]);
  builder.add((ByteData(2)..setUint16(0, payload.length, Endian.big))
      .buffer
      .asUint8List());
  builder.add(payload);
  builder.add(<int>[0x05, 0x00, 0x00, 0x01]);
  builder.add(<int>[203, 0, 113, 7]);
  builder.add(<int>[0x01, 0xbb]);
  return builder.toBytes();
}

void main() {
  final encoded = const JsonEncoder.withIndent('  ').convert(
    buildNativeFixtures(),
  );

  test('native fixtures match the checked-in golden file', () {
    final file = File(_fixturePath);
    if (Platform.environment['UPDATE_NATIVE_FIXTURES'] == '1') {
      file.parent.createSync(recursive: true);
      file.writeAsStringSync('$encoded\n');
      return;
    }
    expect(
      file.existsSync(),
      isTrue,
      reason: 'missing $_fixturePath; regenerate with '
          'UPDATE_NATIVE_FIXTURES=1 flutter test test/native_fixtures_test.dart',
    );
    expect(file.readAsStringSync(), '$encoded\n');
  });
}
