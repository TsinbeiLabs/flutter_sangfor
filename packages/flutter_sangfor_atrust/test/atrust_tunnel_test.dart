import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_sangfor_atrust/flutter_sangfor_atrust.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

class ScriptedTunnelChannel implements ATrustTunnelChannel {
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
    if (!incomingController.isClosed) {
      await incomingController.close();
    }
  }
}

Uint8List _len16(int value) {
  final data = ByteData(2)..setUint16(0, value, Endian.big);
  return data.buffer.asUint8List();
}

Uint8List buildL3HandshakeResponse({String deviceId = 'device-1'}) {
  final payload = utf8.encode(
    jsonEncode(<String, Object?>{
      'code': 0,
      'message': 'ok',
      'data': <String, Object?>{'deviceId': deviceId},
    }),
  );
  final builder = BytesBuilder();
  builder.add(<int>[0x05, 0xD0, 0x53, 0x00]);
  builder.add(_len16(payload.length));
  builder.add(payload);
  builder.add(<int>[0x05, 0x00, 0x00, 0x01]);
  builder.add(<int>[10, 0, 0, 42, 0, 0]);
  return builder.toBytes();
}

Uint8List buildAuthRespFrame(
  int conntrackHash,
  String token, {
  int status = 0,
}) {
  final payload = utf8.encode(
    jsonEncode(<String, Object?>{
      'code': 0,
      'message': 'ok',
      'data': <String, Object?>{
        'conntrackHash': conntrackHash,
        'connectToken': token,
      },
    }),
  );
  final builder = BytesBuilder();
  builder.add(<int>[0x05, 0x93, status]);
  builder.add(_len16(payload.length));
  builder.add(payload);
  return builder.toBytes();
}

Uint8List buildDataRespFrame(Uint8List packet) {
  final builder = BytesBuilder();
  builder.add(<int>[0x05, 0x94]);
  builder.add(_len16(packet.length));
  builder.add(packet);
  return builder.toBytes();
}

Uint8List buildHeartbeatRespFrame() =>
    Uint8List.fromList(<int>[0x05, 0x95, 0x00, 0x00]);

Uint8List buildSecondVipFrame(List<String> addresses) {
  final payload = utf8.encode(jsonEncode(<String, Object?>{
    'vip': addresses.isNotEmpty ? addresses.first : '',
    'vip6': addresses.length > 1 ? addresses[1] : '',
  }));
  final builder = BytesBuilder();
  builder.add(<int>[0x05, 0x96, 0x00]);
  builder.add(_len16(payload.length));
  builder.add(payload);
  return builder.toBytes();
}

ATrustL3ClientInfo testInfo() => const ATrustL3ClientInfo(
      sid: 'sid-1',
      deviceId: 'device-1',
      connectionId: 'conn-1',
      username: 'alice',
    );

void main() {
  test('stream decoder handles fragmented and coalesced L3 frames', () {
    final decoder = ATrustL3FrameStreamDecoder();
    final heartbeat = buildHeartbeatRespFrame();
    final data = buildDataRespFrame(Uint8List.fromList(<int>[1, 2, 3]));

    expect(decoder.add(heartbeat.sublist(0, 3)), isEmpty);
    final frames = decoder.add(
      Uint8List.fromList(<int>[...heartbeat.sublist(3), ...data]),
    );
    expect(frames, hasLength(2));
    expect(frames.first.command, ATrustL3Command.heartbeatResponse);
    expect(frames.last.command, ATrustL3Command.dataResponse);
    expect(frames.last.payload, <int>[1, 2, 3]);

    expect(
      () =>
          decoder.add(Uint8List.fromList(<int>[0x06, 0x93, 0x00, 0x00, 0x00])),
      throwsFormatException,
    );
  });

  test('handshake parser consumes the full sequence and keeps leftovers', () {
    final parser = ATrustL3HandshakeParser();
    final response = buildL3HandshakeResponse();
    final leftoverBytes = <int>[0x05, 0x95, 0x00, 0x00];

    final whole = Uint8List.fromList(<int>[...response, ...leftoverBytes]);
    final parsed = parser.add(whole);
    expect(parsed, isNotNull);
    expect(parsed!.$1.deviceId, 'device-1');
    expect(parsed.$1.virtualIP?.addresses, <String>['10.0.0.42']);
    expect(parsed.$2, leftoverBytes);

    final incremental = ATrustL3HandshakeParser();
    ATrustL3TunnelAuthResult? result;
    for (var offset = 0; offset < whole.length && result == null; offset++) {
      final parsedChunk = incremental.add(<int>[whole[offset]]);
      if (parsedChunk != null) {
        result = parsedChunk.$1;
      }
    }
    expect(result, isNotNull);
    expect(result!.virtualIP?.addresses, <String>['10.0.0.42']);

    final badParser = ATrustL3HandshakeParser();
    expect(
      () => badParser.add(Uint8List.fromList(<int>[0x05, 0xD1])),
      throwsFormatException,
    );
  });

  test('connection start performs the authTunnel handshake', () async {
    final channel = ScriptedTunnelChannel();
    channel.incomingController.add(buildL3HandshakeResponse());
    final connection = ATrustL3TunnelConnection(
      channel: channel,
      info: testInfo(),
      signKey: Uint8List.fromList(<int>[1, 2, 3]),
    );
    final vips = <List<String>>[];
    await connection.start();
    connection.close();

    expect(channel.sent, hasLength(1));
    expect(channel.sent.first[0], 0x05);
    expect(channel.sent.first[1], 0x01);
    expect(channel.sent.first[2], 0xD0);
    expect(connection.handshakeResult?.virtualIP?.addresses,
        <String>['10.0.0.42']);
    expect(vips, isEmpty);
  });

  test('connection authenticates flows and replays pending packets', () async {
    final channel = ScriptedTunnelChannel();
    channel.incomingController.add(buildL3HandshakeResponse());
    final connection = ATrustL3TunnelConnection(
      channel: channel,
      info: testInfo(),
      signKey: Uint8List.fromList(<int>[1, 2, 3]),
      authScanInterval: const Duration(milliseconds: 10),
      heartbeatInterval: const Duration(seconds: 30),
    );
    await connection.start();

    final packet = buildIPv4PacketToTest('10.0.0.1', 1000, '10.3.0.2', 443);
    await connection.sendPacket(
      packet,
      appId: 'app-1',
      nodeGroupId: 'group-1',
    );
    await Future<void>.delayed(const Duration(milliseconds: 20));
    // authTunnelRequest + auth request
    expect(channel.sent, hasLength(2));
    final authFrame = channel.sent[1];
    expect(authFrame[0], 0x05);
    expect(authFrame[1], 0x13);
    final authJson =
        jsonDecode(utf8.decode(authFrame.sublist(4))) as Map<String, Object?>;
    final conntrackHash = (authJson['conntrackHash'] as num).toInt();
    expect(authJson['appId'], 'app-1');
    expect(
      authJson['xRequestSig'],
      matches(RegExp(r'^[0-9A-F]{64}$')),
    );

    channel.incomingController.add(
      buildAuthRespFrame(conntrackHash, 'token-1'),
    );
    await Future<void>.delayed(const Duration(milliseconds: 20));
    // Replayed pending packet as an authenticated data frame.
    expect(channel.sent, hasLength(3));
    final dataFrame = channel.sent[2];
    expect(dataFrame[0], 0x05);
    expect(dataFrame[1], 0x14);
    expect(dataFrame[2], 'token-1'.length);
    expect(
      utf8.decode(dataFrame.sublist(3, 3 + 'token-1'.length)),
      'token-1',
    );

    // Subsequent packets on the authenticated flow go out directly.
    await connection.sendPacket(
      packet,
      appId: 'app-1',
      nodeGroupId: 'group-1',
    );
    expect(channel.sent, hasLength(4));
    expect(channel.sent[3][1], 0x14);
    await connection.close();
  });

  test('connection delivers inbound packets and VIP updates', () async {
    final channel = ScriptedTunnelChannel();
    channel.incomingController.add(buildL3HandshakeResponse());
    final vipUpdates = <List<String>>[];
    final received = <Uint8List>[];
    final connection = ATrustL3TunnelConnection(
      channel: channel,
      info: testInfo(),
      signKey: Uint8List.fromList(<int>[1, 2, 3]),
      heartbeatInterval: const Duration(seconds: 30),
      onVip: vipUpdates.add,
    );
    await connection.start();
    connection.incoming.listen(received.add);

    final inbound = buildIPv4PacketToTest('10.3.0.2', 443, '10.0.0.1', 1000);
    channel.incomingController.add(buildDataRespFrame(inbound));
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(received, hasLength(1));
    expect(received.single, inbound);

    channel.incomingController.add(buildSecondVipFrame(<String>['10.9.9.9']));
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(vipUpdates, hasLength(2));
    expect(vipUpdates.first, <String>['10.0.0.42']);
    expect(vipUpdates.last, <String>['10.9.9.9']);
    await connection.close();
  });

  test('connection retries flow auth after a 0x85 retry status', () async {
    final channel = ScriptedTunnelChannel();
    channel.incomingController.add(buildL3HandshakeResponse());
    final connection = ATrustL3TunnelConnection(
      channel: channel,
      info: testInfo(),
      signKey: Uint8List.fromList(<int>[1, 2, 3]),
      authScanInterval: const Duration(milliseconds: 10),
      authRetryWait: const Duration(milliseconds: 30),
      heartbeatInterval: const Duration(seconds: 30),
    );
    await connection.start();
    final packet = buildIPv4PacketToTest('10.0.0.1', 1000, '10.3.0.2', 443);
    await connection.sendPacket(
      packet,
      appId: 'app-1',
      nodeGroupId: 'group-1',
    );
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(channel.sent, hasLength(2));

    final authFrame = channel.sent[1];
    final conntrackHash = (jsonDecode(utf8.decode(authFrame.sublist(4)))
        as Map<String, Object?>)['conntrackHash'] as num;
    channel.incomingController.add(
      buildAuthRespFrame(conntrackHash.toInt(), '', status: 0x85),
    );
    await Future<void>.delayed(const Duration(milliseconds: 20));
    // Retry is scheduled but not yet dispatched (retryWait 30ms).
    expect(channel.sent, hasLength(2));
    await Future<void>.delayed(const Duration(milliseconds: 60));
    expect(channel.sent, hasLength(3));
    expect(channel.sent[2][1], 0x13);
    await connection.close();
  });

  test('connection closes after repeated heartbeat misses', () async {
    final channel = ScriptedTunnelChannel();
    channel.incomingController.add(buildL3HandshakeResponse());
    final errors = <Object>[];
    final connection = ATrustL3TunnelConnection(
      channel: channel,
      info: testInfo(),
      signKey: Uint8List.fromList(<int>[1, 2, 3]),
      heartbeatInterval: const Duration(milliseconds: 20),
      heartbeatMissLimit: 3,
      onError: errors.add,
    );
    await connection.start();
    // start() wrote the handshake so the first tick clears the write flag.
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect(connection.isClosed, isTrue);
    expect(errors, hasLength(1));
    expect(channel.closed, isTrue);
  });

  test('node selector probes WAN first and falls back to LAN', () async {
    final latencies = <String, Duration>{
      'fast': const Duration(milliseconds: 10),
      'slow': const Duration(milliseconds: 100),
      'lan': const Duration(milliseconds: 15),
    };
    Future<Duration?> dialer(String host, int port, Duration timeout) async =>
        latencies[host];

    final selector = ATrustNodeSelector();
    final best = await selector.select(
      <String, ATrustNodeGroup>{
        'g1': const ATrustNodeGroup(wan: <String>['fast:441', 'slow:441']),
        'g2': const ATrustNodeGroup(lan: <String>['lan:441']),
        'g3': const ATrustNodeGroup(wan: <String>['dead:441']),
      },
      dialer: dialer,
    );
    expect(best['g1'], 'fast:441');
    expect(best['g2'], 'lan:441');
    expect(best.containsKey('g3'), isFalse);
  });

  test('route matching covers CIDR, ranges, domains, and TCP preference', () {
    final routes = <ATrustRoute>[
      const ATrustRoute(
        host: '10.1.0.0/16',
        protocol: 'all',
        portMin: 0,
        portMax: 65535,
        appId: 'cidr-app',
        nodeGroupId: 'g1',
        addrPretend: true,
      ),
      const ATrustRoute(
        host: '10.2.0.1~10.2.0.5',
        protocol: 'tcp',
        portMin: 80,
        portMax: 90,
        appId: 'range-app',
        nodeGroupId: 'g1',
        addrPretend: true,
      ),
      const ATrustRoute(
        host: '*.example.com',
        protocol: 'tcp',
        portMin: 443,
        portMax: 443,
        appId: 'domain-app',
        nodeGroupId: 'g2',
        addrPretend: true,
      ),
      const ATrustRoute(
        host: '10.4.0.1',
        protocol: 'tcp',
        portMin: 22,
        portMax: 22,
        appId: 'tcp-app',
        nodeGroupId: 'g2',
        addrPretend: true,
        enableTcpPrefL3: true,
      ),
    ];

    expect(matchL3Route(routes, '10.1.2.3', 'udp', 53)?.appId, 'cidr-app');
    expect(matchTcpRoute(routes, '10.2.0.3', 85)?.appId, 'range-app');
    expect(matchL3Route(routes, '10.2.0.3', 'tcp', 85), isNull);
    expect(matchL3Route(routes, '10.1.2.3', 'tcp', 80), isNull);
    expect(matchL3Route(routes, '10.4.0.1', 'tcp', 22)?.appId, 'tcp-app');
    expect(matchTcpRoute(routes, '10.4.0.1', 22), isNull);
    expect(matchTcpRoute(routes, 'www.example.com', 443)?.appId, 'domain-app');
    expect(atrustRouteHostCovers('10.1.0.0/16', '10.1.255.254'), isTrue);
    expect(atrustRouteHostCovers('10.1.0.0/16', '10.2.0.0'), isFalse);
    expect(atrustRouteDomainCovers('*.example.com', 'a.example.com'), isTrue);
    expect(atrustRouteDomainCovers('*.example.com', 'example.org'), isFalse);
  });

  test('tunnel manager queries the virtual IP and routes packets', () async {
    final channels = <ScriptedTunnelChannel>[];
    Future<ATrustTunnelChannel> factory(String host, int port) async {
      final channel = ScriptedTunnelChannel();
      channel.incomingController.add(buildL3HandshakeResponse());
      channels.add(channel);
      return channel;
    }

    final resource = ATrustResource(
      routes: <ATrustRoute>[
        const ATrustRoute(
          host: '10.5.0.0/24',
          protocol: 'all',
          portMin: 0,
          portMax: 65535,
          appId: 'app-1',
          nodeGroupId: 'group-1',
          addrPretend: true,
          enableTcpPrefL3: true,
        ),
      ],
      dnsServers: const <String>['10.0.0.53'],
      majorNodeGroup: 'group-1',
      nodeGroups: const <String, ATrustNodeGroup>{
        'group-1': ATrustNodeGroup(wan: <String>['vpn.example.test:441']),
      },
    );

    final tunnel = ATrustTunnel(
      resource: resource,
      info: testInfo(),
      signKey: Uint8List.fromList(<int>[1, 2, 3]),
      socketFactory: factory,
      bestNodes: const <String, String>{'group-1': 'vpn.example.test:441'},
    );
    final received = <Uint8List>[];
    tunnel.incoming.listen(received.add);

    final address = await tunnel.start();
    expect(address, '10.0.0.42');
    // One channel for Query-IP, one for the tunnel connection.
    expect(channels, hasLength(2));
    expect(channels.first.closed, isTrue);
    expect(channels.last.sent.first[1], 0x01);

    final packet = buildIPv4PacketToTest('10.0.0.1', 1000, '10.5.0.2', 443);
    final routed = await tunnel.sendPacket(packet);
    expect(routed, isTrue);
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(channels.last.sent, hasLength(2));
    expect(channels.last.sent[1][1], 0x13);

    final unmatched = buildIPv4PacketToTest('10.0.0.1', 1000, '10.9.9.9', 443);
    expect(await tunnel.sendPacket(unmatched), isFalse);

    final inbound = buildIPv4PacketToTest('10.5.0.2', 443, '10.0.0.1', 1000);
    channels.last.incomingController.add(buildDataRespFrame(inbound));
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(received, hasLength(1));
    await tunnel.close();
  });

  test('TCP tunnel client handshakes, streams raw data, and frames reuse',
      () async {
    final authJson = utf8.encode(jsonEncode(<String, Object?>{
      'code': 0,
      'message': 'ok',
    }));
    Uint8List serverReply({bool reuse = true}) {
      final builder = BytesBuilder();
      builder.add(<int>[0x05, 0x81, 0x53, 0x00]);
      builder.add(_len16(authJson.length));
      builder.add(authJson);
      builder.add(<int>[0x05, 0x00, reuse ? 0x01 : 0x00, 0x01]);
      builder.add(<int>[10, 0, 0, 1]);
      builder.add(<int>[0x01, 0xbb]);
      return builder.toBytes();
    }

    const request = ATrustTcpTunnelAuthRequest(
      sid: 'sid-1',
      appId: 'app-1',
      url: 'tcp://10.5.0.2:443',
      deviceId: 'device-1',
      connectionId: 'conn-1',
      procHash: 'hash',
      userName: 'alice',
      lang: 'en-US',
      destAddr: '10.5.0.2:443',
    );

    // Raw mode (zeroRtt disabled).
    final rawChannel = ScriptedTunnelChannel();
    rawChannel.incomingController.add(serverReply(reuse: true));
    final rawConn = await ATrustTcpTunnelClient.connect(
      channel: rawChannel,
      request: request,
      signKey: Uint8List.fromList(<int>[1, 2, 3]),
      host: '10.5.0.2',
      port: 443,
    );
    expect(rawConn.raw, isTrue);
    expect(rawConn.serverResponse?.reuse, isTrue);
    await rawConn.send(Uint8List.fromList(<int>[9, 8, 7]));
    expect(rawChannel.sent.last, <int>[9, 8, 7]);
    final rawReceived = <Uint8List>[];
    rawConn.incoming.listen(rawReceived.add);
    rawChannel.incomingController.add(<int>[1, 2, 3]);
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(rawReceived, hasLength(1));
    await rawConn.close();

    // Reuse mode (zeroRtt enabled and server agrees).
    final reuseChannel = ScriptedTunnelChannel();
    reuseChannel.incomingController.add(serverReply(reuse: true));
    final reuseConn = await ATrustTcpTunnelClient.connect(
      channel: reuseChannel,
      request: request,
      signKey: Uint8List.fromList(<int>[1, 2, 3]),
      host: '10.5.0.2',
      port: 443,
      zeroRtt: true,
    );
    expect(reuseConn.reuse, isTrue);
    await reuseConn.send(Uint8List.fromList(<int>[4, 5]));
    expect(reuseChannel.sent.last, <int>[0x01, 0x00, 0x00, 0x02, 4, 5]);
    final reuseReceived = <Uint8List>[];
    reuseConn.incoming.listen(reuseReceived.add);
    reuseChannel.incomingController.add(<int>[0x01, 0x00, 0x00, 0x03, 6, 7, 8]);
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(reuseReceived, hasLength(1));
    expect(reuseReceived.single, <int>[6, 7, 8]);
    await reuseConn.closeWrite();
    expect(
      reuseChannel.sent.last,
      <int>[0x01, 0x01, 0x00, 0x00],
    );
  });

  test('connector establishes the tunnel and returns a connected session',
      () async {
    final channels = <ScriptedTunnelChannel>[];
    final client = TunneledLoginHttpClient();
    final connector = ATrustConnector(
      loginSession: ATrustLoginSession(client: client),
      socketFactory: (host, port) async {
        final channel = ScriptedTunnelChannel();
        channel.incomingController.add(buildL3HandshakeResponse());
        channels.add(channel);
        return channel;
      },
      // Real DNS cannot resolve the fixture domain; probe it in-process so
      // the test does not depend on the host resolver.
      nodeDialer: (host, port, timeout) async => const Duration(milliseconds: 1),
    );
    final session = await connector.connect(
      SangforConnectOptions(
        server: Uri.parse('https://vpn.example.test'),
        username: 'alice',
        password: 'secret',
        loginDomain: 'corp',
        deviceId: 'device-1',
      ),
    );

    expect(session.state, SangforConnectionState.connected);
    expect(session.virtualAddress, '10.0.0.42');
    expect(session.dnsServers, <String>['10.0.0.53']);
    expect(connector.tunnel, isNotNull);
    // Query-IP plus the group connection.
    expect(channels, hasLength(2));

    final tunnel = connector.tunnel!;
    final packet = buildIPv4PacketToTest('10.0.0.1', 1000, '10.6.0.2', 443);
    expect(await tunnel.sendPacket(packet), isTrue);
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(channels.last.sent, hasLength(2));
    expect(channels.last.sent[1][1], 0x13);

    await connector.disconnect();
    expect(channels.last.closed, isTrue);
    expect(connector.tunnel, isNull);
  });

  test('connector skips the tunnel when startTunnel is disabled', () async {
    final client = TunneledLoginHttpClient();
    final connector = ATrustConnector(
      loginSession: ATrustLoginSession(client: client),
      startTunnel: false,
    );
    final session = await connector.connect(
      SangforConnectOptions(
        server: Uri.parse('https://vpn.example.test'),
        username: 'alice',
        password: 'secret',
        loginDomain: 'corp',
        deviceId: 'device-1',
      ),
    );
    expect(session.state, SangforConnectionState.authenticated);
    expect(session.virtualAddress, isNull);
    expect(connector.tunnel, isNull);
  });
}

Uint8List buildIPv4PacketToTest(
  String source,
  int sourcePort,
  String destination,
  int destinationPort,
) {
  final tcp = Uint8List(20);
  final tcpData = ByteData.sublistView(tcp);
  tcpData.setUint16(0, sourcePort, Endian.big);
  tcpData.setUint16(2, destinationPort, Endian.big);
  tcp[13] = tcpSynFlag;
  final src = source.split('.').map(int.parse).toList();
  final dst = destination.split('.').map(int.parse).toList();
  final packet = Uint8List(40);
  packet[0] = 0x45;
  packet[2] = 0x00;
  packet[3] = 40;
  packet[9] = tcpProtocol;
  packet.setRange(12, 16, src);
  packet.setRange(16, 20, dst);
  packet.setRange(20, 40, tcp);
  return packet;
}

class TunneledLoginHttpClient extends http.BaseClient {
  final List<String> paths = <String>[];

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
          'data': <String, Object?>{'nextService': ''},
        },
      '/passport/v1/user/onlineInfo' => <String, Object?>{
          'code': 0,
          'data': <String, Object?>{'username': 'alice'},
        },
      '/controller/v1/user/clientResource' => <String, Object?>{
          'code': 0,
          'data': <String, Object?>{
            'appList': <String, Object?>{
              'data': <String, Object?>{
                'appInfo': <Object?>[
                  <String, Object?>{
                    'apps': <Object?>[
                      <String, Object?>{
                        'id': 'app-1',
                        'nodeGroupId': 'group-1',
                        'accessModel': 'L3VPN',
                        'enableTCPPrefL3': true,
                        'addressList': <Object?>[
                          <String, Object?>{
                            'protocol': 'all',
                            'port': '0-65535',
                            'host': '10.6.0.0/24',
                          },
                        ],
                      },
                    ],
                  },
                ],
                'config': <String, Object?>{
                  'nodeGroupConf': <String, Object?>{
                    'majorNodeGroup': <String, Object?>{'id': 'group-1'},
                    'nodeGroupList': <Object?>[
                      <String, Object?>{
                        'id': 'group-1',
                        'addressInfo': <Object?>[
                          <String, Object?>{
                            'address': 'vpn.example.test',
                            'type': 'WAN',
                          },
                        ],
                      },
                    ],
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
