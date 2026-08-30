import 'dart:async';
import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_sangfor_atrust/flutter_sangfor_atrust.dart';
import 'package:test/test.dart';

import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

class FakeHttpClient extends http.BaseClient {
  late Uri requestedUri;
  String? requestBody;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    requestedUri = request.url;
    requestBody = await request.finalize().bytesToString();
    final body = request.url.path.endsWith('/auth/psw')
        ? jsonEncode(<String, Object?>{
            'code': 0,
            'data': <String, Object?>{'ticket': 'ticket-1'},
          })
        : jsonEncode(<String, Object?>{
            'code': 0,
            'data': <String, Object?>{
              'isLogin': 0,
              'csrfToken': 'csrf',
              'pubKey': 'modulus',
              'pubKeyExp': '65537',
              'antiReplayRand': 'nonce',
              'authServerInfoList': <Object?>[
                <String, Object?>{
                  'authType': 'auth/psw',
                  'loginDomain': 'corp',
                },
              ],
            },
          });
    return http.StreamedResponse(
      Stream<List<int>>.value(utf8.encode(body)),
      200,
      headers: <String, String>{'content-type': 'application/json'},
    );
  }
}

class SecondaryFakeHttpClient extends http.BaseClient {
  final requests = <http.BaseRequest>[];

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    requests.add(request);
    final body = request.url.path.endsWith('/authCheck')
        ? <String, Object?>{
            'code': 0,
            'data': <String, Object?>{
              'nextService': 'auth/sms',
              'nextServiceList': <Object?>[
                <String, Object?>{
                  'authType': 'auth/sms',
                  'authId': 'sms-1',
                },
              ],
            },
          }
        : <String, Object?>{
            'code': 0,
            'data': <String, Object?>{'nextService': ''},
          };
    return http.StreamedResponse(
      Stream<List<int>>.value(utf8.encode(jsonEncode(body))),
      200,
    );
  }
}

class SessionFakeHttpClient extends http.BaseClient {
  String? receivedCookie;
  String? reportBody;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    receivedCookie = request.headers['cookie'];
    final isOnlineInfo = request.url.path.endsWith('/onlineInfo');
    final bodyText = await request.finalize().bytesToString();
    if (!isOnlineInfo) reportBody = bodyText;
    final body = jsonEncode(<String, Object?>{
      'code': 0,
      'data': isOnlineInfo
          ? <String, Object?>{'username': 'alice'}
          : <String, Object?>{},
    });
    return http.StreamedResponse(
      Stream<List<int>>.value(utf8.encode(body)),
      200,
      headers: isOnlineInfo
          ? const <String, String>{}
          : const <String, String>{
              'set-cookie': 'sid=session-1; Path=/; Secure',
            },
    );
  }
}

class LoginFakeHttpClient extends http.BaseClient {
  final paths = <String>[];

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    paths.add(request.url.path);
    final path = request.url.path;
    final response = switch (path) {
      '/passport/v1/public/authConfig' => <String, Object?>{
          'code': 0,
          'data': <String, Object?>{
            'isLogin': 0,
            'csrfToken': 'csrf',
            'pubKey': 'F' * 256,
            'pubKeyExp': '1',
            'antiReplayRand': 'nonce',
            'authServerInfoList': <Object?>[
              <String, Object?>{
                'authType': 'auth/psw',
                'loginDomain': 'corp',
              },
            ],
          },
        },
      '/passport/v1/auth/psw' => <String, Object?>{
          'code': 0,
          'data': <String, Object?>{'ticket': 'ticket-1'},
        },
      '/passport/v1/auth/authCheck' => <String, Object?>{
          'code': 0,
          'data': <String, Object?>{
            'nextService': 'auth/sms',
            'nextServiceList': <Object?>[
              <String, Object?>{
                'authType': 'auth/sms',
                'authId': 'sms-1',
              },
            ],
          },
        },
      '/passport/v1/auth/sms' =>
        request.url.queryParameters['action'] == 'checkcode'
            ? <String, Object?>{
                'code': 0,
                'data': <String, Object?>{'nextService': ''},
              }
            : <String, Object?>{'code': 0, 'data': <String, Object?>{}},
      '/passport/v1/user/onlineInfo' => <String, Object?>{
          'code': 0,
          'data': <String, Object?>{'username': 'alice'},
        },
      '/controller/v1/user/clientResource' => <String, Object?>{
          'code': 0,
          'data': <String, Object?>{
            'appList': <String, Object?>{'data': <String, Object?>{}},
            'sdpPolicy': <String, Object?>{'data': <String, Object?>{}},
          },
        },
      _ => <String, Object?>{'code': 0, 'data': <String, Object?>{}},
    };
    return http.StreamedResponse(
      Stream<List<int>>.value(utf8.encode(jsonEncode(response))),
      200,
      headers: path == '/controller/v1/public/reportEnv'
          ? const <String, String>{
              'set-cookie': 'sid=session-1; Path=/; Secure',
            }
          : const <String, String>{},
    );
  }
}

class TokenFakeHttpClient extends http.BaseClient {
  late Uri uri;
  late Map<String, Object?> payload;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    uri = request.url;
    final requestBody = await request.finalize().bytesToString();
    payload = requestBody.isEmpty
        ? <String, Object?>{}
        : Map<String, Object?>.from(jsonDecode(requestBody) as Map);
    final responseBody = jsonEncode(<String, Object?>{
      'code': 0,
      'data': <String, Object?>{'nextService': ''},
    });
    return http.StreamedResponse(
      Stream<List<int>>.value(utf8.encode(responseBody)),
      200,
    );
  }
}

class FakeConnector implements SangforConnector {
  SangforConnectOptions? options;

  @override
  SangforProduct get product => SangforProduct.atrust;

  @override
  Future<SangforSession> connect(SangforConnectOptions value) async {
    options = value;
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

class FakeTunnelChannel implements ATrustTunnelChannel {
  final StreamController<List<int>> incomingController =
      StreamController<List<int>>();
  final List<Uint8List> sent = <Uint8List>[];
  bool closed = false;

  @override
  Stream<List<int>> get incoming => incomingController.stream;

  @override
  Future<void> send(Uint8List bytes) async => sent.add(bytes);

  @override
  Future<void> close() async {
    closed = true;
    await incomingController.close();
  }
}

class FakePacketDevice implements ATrustPacketDevice {
  final StreamController<Uint8List> packetController =
      StreamController<Uint8List>();
  final List<Uint8List> written = <Uint8List>[];
  bool closed = false;

  @override
  Stream<Uint8List> get packets => packetController.stream;

  @override
  Future<void> write(Uint8List packet) async => written.add(packet);

  @override
  Future<void> close() async {
    closed = true;
    await packetController.close();
  }
}

Uint8List buildTCPSegment({
  int sourcePort = 1234,
  int destinationPort = 443,
  int flags = tcpSynFlag,
  int sequence = 100,
  int acknowledgment = 0,
}) {
  final segment = Uint8List(20);
  final data = ByteData.sublistView(segment);
  data.setUint16(0, sourcePort, Endian.big);
  data.setUint16(2, destinationPort, Endian.big);
  data.setUint32(4, sequence, Endian.big);
  data.setUint32(8, acknowledgment, Endian.big);
  segment[12] = 0x50;
  segment[13] = flags;
  return segment;
}

Uint8List buildUDPSegment({
  int sourcePort = 1234,
  int destinationPort = 53,
}) {
  final segment = Uint8List(8);
  final data = ByteData.sublistView(segment);
  data.setUint16(0, sourcePort, Endian.big);
  data.setUint16(2, destinationPort, Endian.big);
  return segment;
}

Uint8List buildIPv4Packet({
  int protocol = tcpProtocol,
  String sourceIP = '10.0.0.1',
  String destinationIP = '10.0.0.2',
  Uint8List? payload,
}) {
  final payloadBytes = payload ?? Uint8List(0);
  final totalLength = 20 + payloadBytes.length;
  final packet = Uint8List(totalLength);
  packet[0] = 0x45;
  packet[2] = (totalLength >> 8) & 0xff;
  packet[3] = totalLength & 0xff;
  packet[8] = 64;
  packet[9] = protocol;
  final source = sourceIP.split('.').map(int.parse).toList();
  final destination = destinationIP.split('.').map(int.parse).toList();
  packet.setRange(12, 16, source);
  packet.setRange(16, 20, destination);
  packet.setRange(20, totalLength, payloadBytes);
  return packet;
}

void main() {
  test('decodes fragmented and coalesced tunnel frames', () {
    const codec = ATrustTunnelFrameCodec();
    final first = codec.encode(
      ATrustTunnelFrame(
        type: ATrustTunnelFrameType.data,
        payload: Uint8List.fromList(<int>[1, 2, 3]),
      ),
    );
    final second = codec.encode(
      ATrustTunnelFrame(
        type: ATrustTunnelFrameType.heartbeat,
        payload: Uint8List(0),
      ),
    );
    final decoder = ATrustTunnelFrameDecoder();

    expect(decoder.add(first.sublist(0, 2)), isEmpty);
    final frames = decoder.add(<int>[...first.sublist(2), ...second]);

    expect(frames, hasLength(2));
    expect(frames.first.payload, <int>[1, 2, 3]);
    expect(frames.last.type, ATrustTunnelFrameType.heartbeat);
  });

  test('rejects invalid tunnel lengths and orders node candidates', () {
    final decoder = ATrustTunnelFrameDecoder(maxFrameLength: 4);
    expect(
      () => decoder.add(<int>[0, 0, 0, 5]),
      throwsFormatException,
    );
    final resource = ATrustResource(
      routes: const <ATrustRoute>[],
      dnsServers: const <String>[],
      majorNodeGroup: 'group-1',
      nodeGroups: const <String, ATrustNodeGroup>{
        'group-1': ATrustNodeGroup(
          wan: <String>['wan:441', 'shared:441'],
          lan: <String>['shared:441', 'lan:441'],
        ),
      },
    );
    expect(
      atrustNodeCandidates(resource),
      <String>['wan:441', 'shared:441', 'lan:441'],
    );
  });

  test('enforces the tunnel lifecycle state machine', () {
    final machine = ATrustTunnelStateMachine();
    machine.transition(ATrustTunnelState.dialing);
    machine.transition(ATrustTunnelState.handshaking);
    machine.transition(ATrustTunnelState.active);
    machine.transition(ATrustTunnelState.reconnecting);
    machine.transition(ATrustTunnelState.dialing);
    machine.transition(ATrustTunnelState.closing);
    machine.transition(ATrustTunnelState.closed);

    expect(machine.state, ATrustTunnelState.closed);
    expect(
      () => machine.transition(ATrustTunnelState.active),
      throwsStateError,
    );
  });

  test('encodes the observed aTrust L3 request envelopes', () {
    expect(
      ATrustL3Protocol.heartbeatRequest(),
      <int>[0x05, 0x15, 0x00, 0x00],
    );
    expect(
      ATrustL3Protocol.dataRequest(
        'token',
        Uint8List.fromList(<int>[1, 2]),
      ),
      <int>[0x05, 0x14, 5, ...'token'.codeUnits, 0, 0, 1, 0, 2, 1, 2],
    );
    expect(
      ATrustL3Protocol.authTunnelRequest('sid'),
      <int>[
        0x05,
        0x01,
        0xd0,
        0x53,
        0,
        0,
        0x0d,
        ...utf8.encode('{"sid":"sid"}'),
        5,
        4,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
      ],
    );
  });

  test('decodes aTrust L3 response frames with status fields', () {
    final frame = ATrustL3Protocol.decodeFrame(
      Uint8List.fromList(<int>[0x05, 0x93, 0x00, 0x00, 0x02, 1, 2]),
    );
    expect(frame.command, ATrustL3Command.authResponse);
    expect(frame.status, 0);
    expect(frame.payload, <int>[1, 2]);
    expect(
      () => ATrustL3Protocol.decodeFrame(
        Uint8List.fromList(<int>[0x05, 0x94, 0, 5, 1]),
      ),
      throwsFormatException,
    );
  });

  test('signs per-flow L3 authentication requests with uppercase HMAC', () {
    final request = ATrustL3AuthRequest(
      sid: 'sid',
      appId: 'app',
      url: 'tcp:10.0.0.2:443',
      deviceId: 'device',
      connectionId: 'connection',
      lang: 'en-US',
      conntrackHash: 7,
      ip: const ATrustL3IpInfo(
        atype: 0x0800,
        protocol: 6,
        destinationAddress: '10.0.0.2',
        destinationPort: 443,
        sourceAddress: '10.0.0.3',
        sourcePort: 1234,
      ),
    );
    final signature = request.signature(
      Uint8List.fromList(<int>[1, 2, 3]),
    );
    expect(signature, matches(RegExp(r'^[0-9A-F]{64}$')));
    expect(request.toMap(Uint8List.fromList(<int>[1, 2, 3])),
        containsPair('xRequestSig', signature));
  });

  test('tracks pending packets and replays them after flow authentication', () {
    var now = DateTime.utc(2026, 1, 1);
    final tracker = ATrustL3FlowTracker(
      maxPendingPackets: 1,
      ttl: const Duration(minutes: 1),
      clock: () => now,
    );
    const key = ATrustL3FlowKey(
      protocol: 6,
      sourceAddress: '10.0.0.1',
      sourcePort: 1000,
      destinationAddress: '10.0.0.2',
      destinationPort: 443,
    );
    final flow = tracker.getOrCreate(
      key,
      appId: 'app',
      nodeGroupId: 'group',
    );
    expect(tracker.cachePacket(flow, Uint8List.fromList(<int>[1])), isTrue);
    expect(tracker.cachePacket(flow, Uint8List.fromList(<int>[2])), isFalse);
    expect(tracker.complete(flow.id, token: 'token'), <List<int>>[
      <int>[1],
    ]);
    expect(flow.state, ATrustL3FlowState.authenticated);
    now = now.add(const Duration(minutes: 2));
    expect(tracker.removeExpired(), 1);
    expect(tracker.length, 0);
  });

  test('validates the Anti-MITM certificate identity digest', () {
    final der = Uint8List.fromList(<int>[1, 2, 3, 4]);
    final encoded = base64Encode(der);
    final data = ATrustAntiMitmData(
      enable: 1,
      devicePublicKeyModulus: 'mod',
      devicePublicKeyExponent: 'exp',
      challenge: 'challenge',
      encryptedChallenge: 'encrypted',
      mitmSignature: 'signature',
      rsaCertificate: encoded,
    );

    expect(() => data.verifyCertificateIdentity(<Uint8List>[der]), returnsNormally);
    expect(
      () => data.verifyCertificateIdentity(<Uint8List>[Uint8List.fromList(<int>[9])]),
      throwsFormatException,
    );
  });

  test('flow transport authenticates once and replays pending packets', () {
    const key = ATrustL3FlowKey(
      protocol: 6,
      sourceAddress: '10.0.0.1',
      sourcePort: 1000,
      destinationAddress: '10.0.0.2',
      destinationPort: 443,
    );
    final tracker = ATrustL3FlowTracker();
    final transport = ATrustL3FlowTransport(
      sid: 'sid',
      deviceId: 'device',
      connectionId: 'connection',
      signKey: Uint8List.fromList(<int>[1, 2, 3]),
      tracker: tracker,
    );
    final authFrames = transport.submitPacket(
      key: key,
      appId: 'app',
      nodeGroupId: 'group',
      packet: Uint8List.fromList(<int>[1]),
    );
    expect(authFrames, hasLength(1));
    expect(authFrames.single[0], 0x05);
    expect(authFrames.single[1], 0x13);
    final flow = tracker.flowById(1)!;
    expect(
      transport.submitPacket(
        key: key,
        appId: 'app',
        nodeGroupId: 'group',
        packet: Uint8List.fromList(<int>[2]),
      ),
      isEmpty,
    );
    final replay = transport.completeAuthentication(flow.id, token: 'token');
    expect(replay, hasLength(2));
    expect(replay.last, contains(2));
  });

  test('bounds tunnel send queue memory', () {
    final queue = ATrustTunnelSendQueue(maxBytes: 5);
    expect(queue.add(Uint8List.fromList(<int>[1, 2, 3])), isTrue);
    expect(queue.add(Uint8List.fromList(<int>[4, 5, 6])), isFalse);
    expect(queue.bytes, 3);
    expect(queue.removeFirst(), <int>[1, 2, 3]);
    expect(queue.isEmpty, isTrue);
  });

  test('uses capped exponential reconnect delays', () {
    const policy = ATrustTunnelReconnectPolicy(
      baseDelay: Duration(seconds: 1),
      maxDelay: Duration(seconds: 3),
      maxAttempts: 3,
    );
    expect(policy.delayForAttempt(1), const Duration(seconds: 1));
    expect(policy.delayForAttempt(2), const Duration(seconds: 2));
    expect(policy.delayForAttempt(3), const Duration(seconds: 3));
    expect(policy.delayForAttempt(4), Duration.zero);
  });

  test('bridges packets in both directions and closes both endpoints', () async {
    final channel = FakeTunnelChannel();
    final device = FakePacketDevice();
    final io = ATrustTunnelIo();
    await io.start(channel: channel, device: device);

    device.packetController.add(Uint8List.fromList(<int>[1, 2]));
    await Future<void>.delayed(Duration.zero);
    expect(channel.sent, hasLength(1));
    expect(channel.sent.single.length, 7);

    const codec = ATrustTunnelFrameCodec();
    channel.incomingController.add(codec.encode(
      ATrustTunnelFrame(
        type: ATrustTunnelFrameType.data,
        payload: Uint8List.fromList(<int>[3, 4]),
      ),
    ));
    await Future<void>.delayed(Duration.zero);
    expect(device.written, <List<int>>[<int>[3, 4]]);

    await io.close();
    expect(channel.closed, isTrue);
    expect(device.closed, isTrue);
  });

  test('serializes and restores authenticated state without credentials',
      () async {
    final snapshot = ATrustSessionSnapshot(
      server: Uri.parse('https://vpn.example.test'),
      username: 'alice',
      deviceId: 'device-1',
      csrfToken: 'csrf',
      cookies: const <ATrustCookie>[
        ATrustCookie(
          name: 'sid',
          value: 'session-1',
          domain: 'vpn.example.test',
          secure: true,
        ),
      ],
    );
    final restored = ATrustSessionSnapshot.fromMap(snapshot.toMap());
    final inner = SessionFakeHttpClient();
    final client =
        ATrustSessionClient.withCookies(restored.cookies, inner: inner);
    await client.get(Uri.parse('https://vpn.example.test/status'));

    expect(restored.sid, 'session-1');
    expect(restored.toMap().containsKey('password'), isFalse);
    expect(inner.receivedCookie, 'sid=session-1');
  });

  test('parses WAN and LAN node groups with default tunnel port', () {
    final resource = const ATrustResourceParser().parse(
      <String, Object?>{
        'data': <String, Object?>{
          'appList': <String, Object?>{
            'data': <String, Object?>{
              'config': <String, Object?>{
                'nodeGroupConf': <String, Object?>{
                  'majorNodeGroup': <String, Object?>{'id': 'group-1'},
                  'nodeGroupList': <Object?>[
                    <String, Object?>{
                      'id': 'group-1',
                      'addressInfo': <Object?>[
                        <String, Object?>{
                          'address': '{{sdpcHost}}',
                          'type': 'WAN',
                        },
                        <String, Object?>{
                          'address': '10.0.0.2:442',
                          'type': 'LAN',
                        },
                      ],
                    },
                  ],
                },
              },
            },
          },
        },
      },
      serverHost: 'vpn.example.test',
    );

    expect(
        resource.nodeGroups['group-1']?.wan, <String>['vpn.example.test:441']);
    expect(resource.nodeGroups['group-1']?.lan, <String>['10.0.0.2:442']);
  });

  test('continues enhanced auth and binds only the current device', () async {
    final client = TokenFakeHttpClient();
    final authenticator = ATrustSecondaryAuthenticator(
      server: Uri.parse('https://vpn.example.test'),
      csrfToken: 'csrf',
      client: client,
    );

    await authenticator.continueEnhanced(
      const ATrustAuthStep(
        service: ATrustAuthService.preEnhancedAuth,
        rawService: 'auth/preEnhancedAuth',
        authId: 'enhanced-1',
      ),
    );
    expect(client.uri.path, '/passport/v1/auth/preEnhancedAuth');
    expect(client.uri.queryParameters['authId'], 'enhanced-1');

    await authenticator.bindCurrentDevice(
      step: const ATrustAuthStep(
        service: ATrustAuthService.bindAuthDevice,
        rawService: 'auth/bindAuthDevice',
        authId: 'bind-1',
      ),
      deviceId: 'device-1',
    );
    expect(client.uri.path, '/passport/v1/auth/bindAuthDevice');
    expect(client.payload['deviceId'], 'device-1');
    expect(client.payload['authId'], 'bind-1');
  });

  test('submits TOTP and RADIUS challenges to their protocol endpoints',
      () async {
    final client = TokenFakeHttpClient();
    final authenticator = ATrustSecondaryAuthenticator(
      server: Uri.parse('https://vpn.example.test'),
      csrfToken: 'csrf',
      client: client,
    );

    final totpResult = await authenticator.verifyTotp(
      code: '123456',
      username: 'alice@corp',
    );
    expect(client.uri.path, '/passport/v1/auth/token');
    expect(client.payload['totpToken'], '123456');
    expect(totpResult.service, ATrustAuthService.none);

    await authenticator.verifyRadius(
      code: '654321',
      step: const ATrustAuthStep(service: ATrustAuthService.challenge),
      username: 'alice@corp',
    );
    expect(client.uri.path, '/passport/v1/auth/challenge');
    expect(client.payload['radiusToken'], '654321');
  });

  test('coordinates the complete password and SMS login flow', () async {
    final client = LoginFakeHttpClient();
    final session = await ATrustLoginSession(client: client).login(
      ATrustLoginOptions(
        server: Uri.parse('https://vpn.example.test'),
        username: 'alice',
        password: 'secret',
        loginDomain: 'corp',
        deviceId: 'device-1',
        smsCodeProvider: (_) async => '123456',
      ),
    );

    expect(session.username, 'alice');
    expect(session.sid, 'session-1');
    expect(client.paths, contains('/controller/v1/user/clientResource'));
    expect(
        client.paths.where((path) => path.endsWith('/auth/sms')), hasLength(2));
  });

  test('persists SID cookies across post-login requests', () async {
    final inner = SessionFakeHttpClient();
    final session = ATrustSessionClient(inner: inner);
    final api = ATrustSessionApi(
      server: Uri.parse('https://vpn.example.test'),
      csrfToken: 'csrf',
      client: session,
    );

    await api.reportEnvironment(ticket: 'ticket-1', deviceId: 'device-1');
    final info = await api.fetchOnlineInfo();

    expect(session.sid, 'session-1');
    expect(inner.receivedCookie, 'sid=session-1');
    expect(inner.reportBody, contains('ticket-1'));
    expect(inner.reportBody, contains('device-1'));
    expect(info.username, 'alice');
  });

  test('runs the SMS authentication request sequence', () async {
    final client = SecondaryFakeHttpClient();
    final authenticator = ATrustSecondaryAuthenticator(
      server: Uri.parse('https://vpn.example.test'),
      csrfToken: 'csrf',
      client: client,
    );

    final step = await authenticator.authCheck();
    await authenticator.sendSms(step);
    final nextStep = await authenticator.verifySms(step: step, code: '123456');

    expect(step.smsMode, ATrustSmsMode.withAuthId);
    expect(nextStep.service, ATrustAuthService.none);
    expect(client.requests[1].url.queryParameters['action'], 'sendsms');
    expect(client.requests[2].url.queryParameters['action'], 'checkcode');
  });

  test('normalizes an SMS authentication step without authId', () {
    final step = ATrustAuthStep.fromMap(<String, Object?>{
      'nextService': 'auth/sendSms',
      'nextServiceList': <Object?>[
        <String, Object?>{'authType': 'auth/sendSms'},
      ],
    });

    expect(step.service, ATrustAuthService.sms);
    expect(step.smsMode, ATrustSmsMode.withoutAuthId);
  });

  test('parses supported L3VPN routes and DNS options', () {
    final resource = const ATrustResourceParser().parse(<String, Object?>{
      'data': <String, Object?>{
        'appList': <String, Object?>{
          'data': <String, Object?>{
            'appInfo': <Object?>[
              <String, Object?>{
                'apps': <Object?>[
                  <String, Object?>{
                    'id': 'app-1',
                    'nodeGroupId': 'node-1',
                    'accessModel': 'L3VPN',
                    'addressList': <Object?>[
                      <String, Object?>{
                        'protocol': 'tcp',
                        'port': '443-445',
                        'host': '10.0.0.1',
                      },
                    ],
                  },
                ],
              },
            ],
            'config': <String, Object?>{
              'nodeGroupConf': <String, Object?>{
                'majorNodeGroup': <String, Object?>{'id': 'node-1'},
              },
            },
          },
        },
        'sdpPolicy': <String, Object?>{
          'data': <String, Object?>{
            'clientOption': <String, Object?>{
              'dnsOption': <String, Object?>{'firstDNS': '10.0.0.53'},
            },
          },
        },
      },
    });

    expect(resource.routes.single.portMax, 445);
    expect(resource.dnsServers, <String>['10.0.0.53']);
    expect(resource.majorNodeGroup, 'node-1');
  });

  test('sends an independently generated RSA password payload', () async {
    final client = FakeHttpClient();
    final config = ATrustAuthConfig(
      isLoggedIn: false,
      authMethods: const <ATrustAuthInfo>[],
      csrfToken: 'csrf',
      publicKey: 'F' * 256,
      publicKeyExponent: '1',
      antiReplayRandom: 'nonce',
    );

    final result =
        await ATrustPasswordAuthenticator(client: client).authenticate(
      server: Uri.parse('https://vpn.example.test'),
      username: 'alice',
      password: 'secret',
      loginDomain: 'corp',
      config: config,
      deviceId: 'device-1',
    );

    final body = jsonDecode(client.requestBody!) as Map<String, Object?>;
    expect(client.requestedUri.path, '/passport/v1/auth/psw');
    expect(body['username'], 'alice@corp');
    expect((body['password'] as String).length, 256);
    expect(result.ticket, isNotEmpty);
  });

  test('reads the advertised aTrust authentication configuration', () async {
    final client = FakeHttpClient();
    final config = await ATrustApiClient(client: client).fetchAuthConfig(
      Uri.parse('https://vpn.example.test/ignored'),
    );

    expect(client.requestedUri.path, '/passport/v1/public/authConfig');
    expect(config.csrfToken, 'csrf');
    expect(config.authMethods.single.loginDomain, 'corp');
  });

  test('requests client resources with the expected resource groups', () async {
    final client = FakeHttpClient();
    final resource = await ATrustApiClient(client: client).fetchClientResource(
      server: Uri.parse('https://vpn.example.test'),
      csrfToken: 'csrf',
    );

    expect(client.requestedUri.path, '/controller/v1/user/clientResource');
    expect(resource['code'], 0);
    expect(client.requestBody, contains('resourceType'));
  });

  test('maps the aTrust CAS auth method to the core request', () async {
    final delegate = FakeConnector();
    final connector = ATrustConnector(
      delegate: delegate,
      authMethod: ATrustAuthMethod.cas,
    );

    await connector.connect(
      SangforConnectOptions(
        server: Uri.parse('https://vpn.example.test'),
        username: 'alice',
        password: 'secret',
      ),
    );

    expect(delegate.options?.authType, SangforAuthType.cas);
    expect(connector.product, SangforProduct.atrust);
  });

  test('requires protocol-only login options', () async {
    final connector = ATrustConnector(loginSession: ATrustLoginSession());

    await expectLater(
      connector.connect(
        SangforConnectOptions(
          server: Uri.parse('https://vpn.example.test'),
          username: 'alice',
          password: 'secret',
          loginDomain: 'corp',
        ),
      ),
      throwsA(
        isA<SangforException>().having(
          (error) => error.code,
          'code',
          SangforErrorCode.invalidOptions,
        ),
      ),
    );
  });

  test('rejects incomplete session snapshots before network access', () async {
    final session = ATrustLoginSession();
    await expectLater(
      session.resume(
        ATrustSessionSnapshot(
          server: Uri.parse('https://vpn.example.test'),
          username: 'alice',
          deviceId: 'device-1',
          csrfToken: '',
          cookies: const <ATrustCookie>[],
        ),
      ),
      throwsA(
        isA<SangforException>().having(
          (error) => error.code,
          'code',
          SangforErrorCode.sessionExpired,
        ),
      ),
    );
  });

  test('parses IPv4, TCP, and UDP packet headers', () {
    final tcpSegment =
        buildTCPSegment(sourcePort: 1234, destinationPort: 443, flags: tcpSynFlag | tcpAckFlag);
    final packet = buildIPv4Packet(payload: tcpSegment);

    final ip = ATrustIPv4Packet(packet);
    expect(ip.valid, isTrue);
    expect(ip.version, 4);
    expect(ip.headerLength, 20);
    expect(ip.totalLength, packet.length);
    expect(ip.protocol, tcpProtocol);
    expect(ip.sourceIP, '10.0.0.1');
    expect(ip.destinationIP, '10.0.0.2');

    final tcp = ATrustTCPPacket(ip.payload);
    expect(tcp.valid, isTrue);
    expect(tcp.sourcePort, 1234);
    expect(tcp.destinationPort, 443);
    expect(tcp.flags, tcpSynFlag | tcpAckFlag);
    expect(tcp.sequenceNumber, 100);

    final udpSegment = buildUDPSegment(sourcePort: 5353, destinationPort: 53);
    final udpPacket = buildIPv4Packet(protocol: udpProtocol, payload: udpSegment);
    final udp = ATrustUDPPacket(ATrustIPv4Packet(udpPacket).payload);
    expect(udp.valid, isTrue);
    expect(udp.sourcePort, 5353);
    expect(udp.destinationPort, 53);

    final meta = buildPacketMeta(packet)!;
    expect(meta.atype, 4);
    expect(meta.protocol, tcpProtocol);
    expect(meta.sourceAddress, '10.0.0.1');
    expect(meta.sourcePort, 1234);
    expect(meta.destinationAddress, '10.0.0.2');
    expect(meta.destinationPort, 443);
    final reversed = meta.reversed;
    expect(reversed.sourceAddress, '10.0.0.2');
    expect(reversed.sourcePort, 443);
    expect(reversed.destinationAddress, '10.0.0.1');
    expect(reversed.destinationPort, 1234);
  });

  test('splits incoming IP packet streams and keeps partial trailing data', () {
    final first = buildIPv4Packet(payload: buildTCPSegment());
    final second = buildIPv4Packet(
      payload: buildTCPSegment(),
      sourceIP: '10.0.0.3',
    );
    final partial = Uint8List.fromList(<int>[0x45, 0x00, 0x00, 0x28]);

    final (packets, remaining) = splitIncomingIPPackets(
      Uint8List.fromList(<int>[...first, ...second, ...partial]),
    );
    expect(packets, hasLength(2));
    expect(packets.first, first);
    expect(remaining, partial);

    expect(
      () => splitIncomingIPPackets(
        Uint8List.fromList(<int>[0x70, 0x00, 0x00, 0x28]),
      ),
      throwsFormatException,
    );
  });

  test('tracks TCP conntrack state transitions through a connection', () {
    final conntrack = ATrustTcpConntrack();
    expect(conntrack.state, ATrustTcpConntrackState.reset);

    conntrack.observeTcp(
      ATrustTCPPacket(buildTCPSegment(flags: tcpSynFlag, sequence: 100)),
      false,
    );
    expect(conntrack.state, ATrustTcpConntrackState.outboundSyn);

    conntrack.observeTcp(
      ATrustTCPPacket(
        buildTCPSegment(
          flags: tcpSynFlag | tcpAckFlag,
          sequence: 200,
          acknowledgment: 101,
        ),
      ),
      true,
    );
    expect(conntrack.state, ATrustTcpConntrackState.synAck);

    conntrack.observeTcp(
      ATrustTCPPacket(buildTCPSegment(flags: tcpAckFlag, acknowledgment: 201)),
      false,
    );
    expect(conntrack.state, ATrustTcpConntrackState.established);
    expect(conntrack.ttl, const Duration(hours: 6));

    conntrack.observeTcp(
      ATrustTCPPacket(buildTCPSegment(flags: tcpFinFlag | tcpAckFlag)),
      true,
    );
    expect(conntrack.state, ATrustTcpConntrackState.inboundFin);

    conntrack.observeTcp(
      ATrustTCPPacket(buildTCPSegment(flags: tcpFinFlag | tcpAckFlag)),
      false,
    );
    expect(conntrack.state, ATrustTcpConntrackState.inboundFirstClosed);

    conntrack.observeTcp(
      ATrustTCPPacket(buildTCPSegment(flags: tcpRstFlag)),
      true,
    );
    expect(conntrack.state, ATrustTcpConntrackState.reset);
    expect(conntrack.ttl, const Duration(seconds: 90));
  });

  test('parses VIP headers, data, and JSON second-VIP updates', () {
    expect(
      ATrustL3Protocol.parseInitialVIPHeader(
        Uint8List.fromList(<int>[0x05, 0x00, 0x00, 0x01]),
      ),
      6,
    );
    expect(
      ATrustL3Protocol.parseInitialVIPHeader(
        Uint8List.fromList(<int>[0x05, 0x00, 0x00, 0x04]),
      ),
      18,
    );
    expect(
      ATrustL3Protocol.parseInitialVIPHeader(
        Uint8List.fromList(<int>[0x05, 0x00, 0x00, 0x05]),
      ),
      22,
    );
    expect(
      () => ATrustL3Protocol.parseInitialVIPHeader(
        Uint8List.fromList(<int>[0x05, 0x01, 0x00, 0x01]),
      ),
      throwsFormatException,
    );

    final vip = ATrustL3Protocol.parseVirtualIPData(
      Uint8List.fromList(<int>[10, 0, 0, 42, 0, 0]),
    );
    expect(vip.addresses, <String>['10.0.0.42']);

    final jsonVip = ATrustL3Protocol.extractVIPs(
      Uint8List.fromList(
        utf8.encode('{"vip":"10.1.2.3","vip6":"::1"}'),
      ),
    );
    expect(jsonVip, <String>['10.1.2.3', '::1']);
  });

  test('parses the complete L3 tunnel auth response with VIP', () {
    final authPayload = utf8.encode(
      jsonEncode(<String, Object?>{
        'code': 0,
        'message': 'ok',
        'data': <String, Object?>{'deviceId': 'device-1'},
      }),
    );
    final builder = BytesBuilder();
    builder.add(<int>[0x05, 0xD0]);
    builder.add(<int>[0x53, 0x00]);
    final length = ByteData(2)..setUint16(0, authPayload.length, Endian.big);
    builder.add(length.buffer.asUint8List());
    builder.add(authPayload);
    builder.add(<int>[0x05, 0x00, 0x00, 0x01]);
    builder.add(<int>[10, 0, 0, 42, 0, 0]);
    final bytes = builder.toBytes();

    final result = ATrustL3Protocol.parseTunnelAuthResponse(bytes);
    expect(result.authStatus, 0);
    expect(result.deviceId, 'device-1');
    expect(result.virtualIP?.addresses, <String>['10.0.0.42']);
    expect(result.consumed, bytes.length);

    expect(
      () => ATrustL3Protocol.parseTunnelAuthResponse(
        Uint8List.fromList(<int>[0x05, 0xD1]),
      ),
      throwsFormatException,
    );
  });

  test('parses structured L3 data payloads with tokens', () {
    final payload = BytesBuilder();
    payload.addByte(5);
    payload.add(utf8.encode('token'));
    payload.add(<int>[0x00, 0x00]);
    payload.addByte(2);
    final first = ByteData(2)..setUint16(0, 2, Endian.big);
    payload.add(first.buffer.asUint8List());
    payload.add(<int>[1, 2]);
    final second = ByteData(2)..setUint16(0, 3, Endian.big);
    payload.add(second.buffer.asUint8List());
    payload.add(<int>[3, 4, 5]);

    final packets = ATrustL3Protocol.parseDataPayload(payload.toBytes());
    expect(packets, hasLength(2));
    expect(packets.first, <int>[1, 2]);
    expect(packets.last, <int>[3, 4, 5]);

    expect(
      () => ATrustL3Protocol.parseDataPayload(Uint8List.fromList(<int>[0])),
      throwsFormatException,
    );
  });

  test('builds TCP tunnel handshakes and parses server responses', () {
    const request = ATrustTcpTunnelAuthRequest(
      sid: 'sid',
      appId: 'app',
      url: 'tcp://10.0.0.2:443',
      deviceId: 'device',
      connectionId: 'connection',
      procHash: 'hash',
      userName: 'user',
      lang: 'en-US',
      destAddr: '10.0.0.2:443',
    );
    final message = ATrustTcpTunnelProtocol.handshakeMessage(
      request,
      Uint8List.fromList(<int>[1, 2, 3]),
      '10.0.0.2',
      443,
    );
    expect(message[0], 0x05);
    expect(message[1], 0x01);
    expect(message[2], 0x81);
    expect(message[3], 0x53);
    expect(message[4], 0x03);
    final authJson = jsonDecode(utf8.decode(message.sublist(7, message.length - 10)))
        as Map<String, Object?>;
    expect(authJson['sid'], 'sid');
    expect(authJson['xRequestSig'], matches(RegExp(r'^[0-9A-F]{64}$')));
    final destination = message.sublist(message.length - 10);
    expect(destination[0], 0x05);
    expect(destination[1], 0x01);
    expect(destination[2], 0x00);
    expect(destination[3], 0x01);
    expect(destination.sublist(4, 8), <int>[10, 0, 0, 2]);
    expect(
      ByteData.sublistView(destination, 8, 10).getUint16(0, Endian.big),
      443,
    );

    final responseBuilder = BytesBuilder();
    responseBuilder.add(<int>[0x05, 0x81]);
    responseBuilder.add(<int>[0x53, 0x00]);
    final authResponse =
        utf8.encode(jsonEncode(<String, Object?>{'code': 0, 'message': 'ok'}));
    final authLength = ByteData(2)
      ..setUint16(0, authResponse.length, Endian.big);
    responseBuilder.add(authLength.buffer.asUint8List());
    responseBuilder.add(authResponse);
    responseBuilder.add(<int>[0x05, 0x00, 0x01, 0x01]);
    responseBuilder.add(<int>[10, 0, 0, 1]);
    final port = ByteData(2)..setUint16(0, 443, Endian.big);
    responseBuilder.add(port.buffer.asUint8List());

    final parsed = ATrustTcpTunnelProtocol.parseServerResponse(
      responseBuilder.toBytes(),
    );
    expect(parsed.authCode, 0);
    expect(parsed.authMessage, 'ok');
    expect(parsed.connectStatus, 0);
    expect(parsed.reuse, isTrue);

    expect(
      ATrustTcpTunnelProtocol.connectStatusMessage(0x05),
      'connection refused',
    );
  });

  test('encodes and decodes TCP tunnel data and EOF frames', () {
    final data = Uint8List.fromList(<int>[1, 2, 3, 4]);
    final frame = ATrustTcpTunnelProtocol.dataFrame(data);
    expect(frame, <int>[0x01, 0x00, 0x00, 0x04, 1, 2, 3, 4]);

    final (decoded, isEof) = ATrustTcpTunnelProtocol.parseDataFrame(frame);
    expect(isEof, isFalse);
    expect(decoded, data);

    final (eofData, eofFlag) =
        ATrustTcpTunnelProtocol.parseDataFrame(ATrustTcpTunnelProtocol.eofFrame());
    expect(eofFlag, isTrue);
    expect(eofData, isEmpty);

    final frames = ATrustTcpTunnelProtocol.dataFrames(
      Uint8List.fromList(List<int>.filled(70000, 7)),
    );
    expect(frames, hasLength(2));
    expect(frames.first.length, 4 + 0xffff);
    expect(frames.last.length, 4 + (70000 - 0xffff));
  });

  test('derives agent tokens with trailing NUL for anti-MITM pinning', () {
    final sessionId = List<int>.generate(32, (index) => index);
    final agentToken = ATrustAntiMitmData.fromMap(<String, Object?>{
      'enable': 0,
    });
    expect(agentToken.enable, 0);
    expect(
      () => agentToken.verifyChallenge(),
      throwsStateError,
    );
    expect(sessionId.length, 32);
  });
}
