import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_sangfor_easy_connect/flutter_sangfor_easy_connect.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

class FakeConnector implements SangforConnector {
  @override
  SangforProduct get product => SangforProduct.easyConnect;

  @override
  Future<SangforSession> connect(SangforConnectOptions options) async =>
      const SangforSession(state: SangforConnectionState.connected);

  @override
  Future<void> disconnect() async {}

  @override
  Future<SangforConnectionState> getState() async =>
      SangforConnectionState.connected;

  @override
  Future<SangforPlatformCapabilities> getCapabilities() async =>
      const SangforPlatformCapabilities(platform: 'test');
}

class FakeEasyConnectHttpClient extends http.BaseClient {
  final List<http.BaseRequest> requests = <http.BaseRequest>[];

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    requests.add(request);
    final body = request.url.path.endsWith('/login_auth.csp')
        ? '<Auth><TwfID>twf-1</TwfID><RSA_ENCRYPT_KEY>${'F' * 256}</RSA_ENCRYPT_KEY><RSA_ENCRYPT_EXP>65537</RSA_ENCRYPT_EXP><CSRF_RAND_CODE>nonce</CSRF_RAND_CODE></Auth>'
        : '<Auth><Result>1</Result></Auth>';
    return http.StreamedResponse(
      Stream<List<int>>.value(utf8.encode(body)),
      200,
    );
  }
}

class FakeDataPlaneHttpClient extends http.BaseClient {
  final List<http.BaseRequest> requests = <http.BaseRequest>[];
  final Map<String, String> bodies = <String, String>{
    '/por/login_auth.csp':
        '<Auth><TwfID>twf-1</TwfID><RSA_ENCRYPT_KEY>${'F' * 256}</RSA_ENCRYPT_KEY><RSA_ENCRYPT_EXP>65537</RSA_ENCRYPT_EXP><CSRF_RAND_CODE>nonce</CSRF_RAND_CODE></Auth>',
    '/por/login_psw.csp': '<Auth><Result>1</Result></Auth>',
    '/por/conf.csp':
        '<Conf><L3VPN iptunDns="10.0.0.53" iptunDnsBak="10.0.0.54"/>'
        '<Mline enable="1" list="host1:443;host2:443"/><Htp mtu="1400"/></Conf>',
    '/por/rclist.csp':
        '<Resource><Rcs><Rc id="1" name="web" type="1" proto="0" '
        'host="10.0.0.1;10.0.0.2" port="80;443"/>'
        '<Rc id="2" name="l3" type="2" proto="-1" '
        'host="10.1.0.0~10.1.255.255" port="0~65535"/></Rcs>'
        '<Dns dnsserver="10.0.0.53;10.0.0.54"/>'
        '<Other defaultRcId="1"/></Resource>',
    '/por/update_session.csp':
        '<Auth><Message>success</Message><ErrorCode>1</ErrorCode>'
        '<TwfID>twf-1</TwfID></Auth>',
  };

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    requests.add(request);
    final body = bodies[request.url.path] ?? '<Auth><Result>1</Result></Auth>';
    return http.StreamedResponse(
      Stream<List<int>>.value(utf8.encode(body)),
      200,
    );
  }
}

void main() {
  test('identifies the Easy Connect product', () {
    expect(
      EasyConnectConnector(delegate: FakeConnector()).product,
      SangforProduct.easyConnect,
    );
  });

  test('performs the XML password login exchange', () async {
    final client = FakeEasyConnectHttpClient();
    final session = await EasyConnectLoginSession(client: client).login(
      EasyConnectLoginOptions(
        server: Uri.parse('https://vpn.example.test'),
        username: 'alice',
        password: 'secret',
      ),
    );

    expect(session.twfId, 'twf-1');
    expect(client.requests, hasLength(2));
    expect(client.requests[0].url.path, '/por/login_auth.csp');
    expect(client.requests[1].url.path, '/por/login_psw.csp');
    expect(client.requests[1].headers['cookie'], 'TWFID=twf-1');
    expect(
      (client.requests[1] as http.Request).body,
      contains('svpn_password='),
    );
  });

  test('rejects non-HTTPS EasyConnect servers', () async {
    await expectLater(
      EasyConnectLoginSession().login(
        EasyConnectLoginOptions(
          server: Uri.parse('http://vpn.example.test'),
          username: 'alice',
          password: 'secret',
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

  test('dry-run connector returns an authenticated session without network',
      () async {
    final connector = EasyConnectConnector(
      loginSession: EasyConnectLoginSession(),
    );
    final session = await connector.connect(
      SangforConnectOptions(
        server: Uri.parse('https://vpn.example.test'),
        username: 'alice',
        password: 'secret',
        dryRun: true,
      ),
    );
    expect(session.state, SangforConnectionState.authenticated);
    expect(session.dryRun, isTrue);
    expect(session.dnsServers, isEmpty);
  });

  test('connector login fetches conf.csp DNS servers into the session',
      () async {
    final client = FakeDataPlaneHttpClient();
    final connector = EasyConnectConnector(
      loginSession: EasyConnectLoginSession(client: client),
      startTunnel: false,
    );
    final session = await connector.connect(
      SangforConnectOptions(
        server: Uri.parse('https://vpn.example.test'),
        username: 'alice',
        password: 'secret',
      ),
    );
    expect(session.state, SangforConnectionState.authenticated);
    expect(session.dnsServers, <String>['10.0.0.53']);
    expect(
      client.requests.map((request) => request.url.path),
      containsAllInOrder(<String>[
        '/por/login_auth.csp',
        '/por/login_psw.csp',
        '/por/conf.csp',
      ]),
    );
  });

  test('fetches resource lists through rclist.csp after login', () async {
    final client = FakeDataPlaneHttpClient();
    final session = EasyConnectLoginSession(client: client);
    await session.login(
      EasyConnectLoginOptions(
        server: Uri.parse('https://vpn.example.test'),
        username: 'alice',
        password: 'secret',
      ),
    );
    final resources = await session.fetchResourceList(
      Uri.parse('https://vpn.example.test'),
    );
    expect(resources.entries, hasLength(3));
    expect(resources.dnsServers, <String>['10.0.0.53', '10.0.0.54']);
    expect(resources.defaultResourceId, '1');
    final l3 = resources.entries.last;
    expect(l3.type, 2);
    expect(l3.host, '10.1.0.0~10.1.255.255');
    expect(l3.portMin, 0);
    expect(l3.portMax, 65535);
  });

  test('rejects resource fetches before login', () {
    final session = EasyConnectLoginSession();
    expect(
      () => session.fetchConfig(Uri.parse('https://vpn.example.test')),
      throwsA(isA<EasyConnectApiException>()),
    );
  });

  test('parses conf.csp XML with DNS, backup DNS, and Mline lists', () {
    const xml = '<Conf>'
        '<L3VPN iptunDns="10.0.0.53" iptunDnsBak="10.0.0.54"/>'
        '<Mline enable="1" list="host1:443;host2:443;host3:443"/>'
        '<Htp mtu="1400"/></Conf>';
    final config = EasyConnectConfig.parse(xml);
    expect(config.dnsServers, <String>['10.0.0.53']);
    expect(config.backupDnsServers, <String>['10.0.0.54']);
    expect(config.mlineServers, <String>[
      'host1:443',
      'host2:443',
      'host3:443',
    ]);
    expect(config.mtu, 1400);
  });

  test('filters invalid DNS entries while parsing conf.csp', () {
    const xml = '<Conf>'
        '<L3VPN iptunDns="0.0.0.0;;10.0.0.53" iptunDnsBak=""/>'
        '</Conf>';
    final config = EasyConnectConfig.parse(xml);
    expect(config.dnsServers, <String>['10.0.0.53']);
    expect(config.backupDnsServers, isEmpty);
  });

  test('derives the tunnel token from a TLS session id and TWFID', () {
    final sessionId = List<int>.generate(32, (index) => index);
    final agentToken = EasyConnectTunnelProtocol.deriveAgentToken(sessionId);
    expect(agentToken.length, 32);
    expect(agentToken[31], 0x00);
    final expectedHex = sessionId
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join()
        .substring(0, 31);
    expect(utf8.decode(agentToken.sublist(0, 31)), expectedHex);

    final token =
        EasyConnectTunnelProtocol.deriveToken(sessionId, 'twf-1234567890ab');
    expect(token.length, 48);
    expect(utf8.decode(token.sublist(32, 48)), 'twf-1234567890ab');

    expect(
      () => EasyConnectTunnelProtocol.deriveToken(sessionId, 'short'),
      throwsArgumentError,
    );
  });

  test('builds Query-IP, RX, TX, and heartbeat handshake messages', () {
    final token = Uint8List.fromList(List<int>.filled(48, 0x42));

    final queryIp = EasyConnectTunnelProtocol.queryIpMessage(token);
    expect(queryIp.length, 64);
    expect(queryIp[0], 0);
    expect(queryIp[3], 0);
    expect(queryIp[4], 0x42);
    expect(queryIp[63], 0xff);

    final rx = EasyConnectTunnelProtocol.rxStreamMessage(token, [1, 2, 3, 4]);
    expect(rx[0], 6);
    expect(rx[4], 0x42);
    expect(rx[60], 1);

    final tx = EasyConnectTunnelProtocol.txStreamMessage(token, [1, 2, 3, 4]);
    expect(tx[0], 5);
    expect(tx[63], 4);

    final command = EasyConnectTunnelProtocol.commandHeartbeatMessage(token);
    expect(command[0], 3);
    expect(command[63], 0);
  });

  test('parses Query-IP replies with client and server LAN IPs', () {
    final response = Uint8List(36);
    final data = ByteData.sublistView(response);
    data.setUint32(0, 0, Endian.little);
    response.setRange(4, 8, <int>[10, 166, 80, 12]);
    response.setRange(12, 16, <int>[10, 166, 64, 3]);

    final (clientIp, serverLanIp) =
        EasyConnectTunnelProtocol.parseQueryIpResponse(response);
    expect(clientIp, <int>[10, 166, 80, 12]);
    expect(serverLanIp, <int>[10, 166, 64, 3]);

    data.setUint32(0, 5, Endian.little);
    expect(
      () => EasyConnectTunnelProtocol.parseQueryIpResponse(response),
      throwsFormatException,
    );
  });

  test('parses stream replies including native AABB control frames', () {
    final nativeFrame = Uint8List(40);
    nativeFrame.setRange(0, 4, <int>[0x41, 0x41, 0x42, 0x42]);
    ByteData.sublistView(nativeFrame).setUint32(4, 1, Endian.little);
    expect(
      EasyConnectTunnelProtocol.parseStreamResponse(nativeFrame, 1),
      1,
    );
    expect(
      EasyConnectTunnelProtocol.parseNativeControlFrame(nativeFrame),
      1,
    );

    final legacy = Uint8List.fromList(<int>[0x02]);
    expect(
      EasyConnectTunnelProtocol.parseStreamResponse(legacy, 2),
      2,
    );

    final body = Uint8List(36);
    ByteData.sublistView(body).setUint32(0, 1, Endian.little);
    expect(
      EasyConnectTunnelProtocol.parseStreamResponse(body, 1),
      1,
    );

    final invalid = Uint8List.fromList(<int>[0x41, 0x41, 0x42, 0x42]);
    expect(
      () => EasyConnectTunnelProtocol.parseNativeControlFrame(invalid),
      throwsFormatException,
    );
  });

  test('builds heartbeat packets with valid IP and ICMP checksums', () {
    final token = Uint8List.fromList(List<int>.filled(48, 0x42));
    final packet = EasyConnectTunnelProtocol.heartbeatPacket(
      <int>[10, 166, 80, 12],
      <int>[10, 166, 64, 3],
      token,
    );
    expect(packet.length, 76);
    expect(packet[0], 0x45);
    expect(packet[2], 0x00);
    expect(packet[3], 0x4c);
    expect(packet[9], 0x01);
    expect(packet.sublist(12, 16), <int>[10, 166, 80, 12]);
    expect(packet.sublist(16, 20), <int>[10, 166, 64, 3]);
    expect(utf8.decode(packet.sublist(28, 46)), 'SANGFORSCSIPCLIENT');
    expect(packet.sublist(46, 62), token.sublist(32, 48));
    expect(utf8.decode(packet.sublist(70, 75)), 'L3VPN');
    expect(packet[75], 0x00);

    var ipSum = 0;
    for (var offset = 0; offset < 20; offset += 2) {
      ipSum += (packet[offset] << 8) | packet[offset + 1];
    }
    ipSum = (ipSum & 0xffff) + (ipSum >> 16);
    expect((~ipSum) & 0xffff, 0);

    expect(
      () => EasyConnectTunnelProtocol.heartbeatPacket(
        <int>[1, 2, 3],
        <int>[10, 166, 64, 3],
        token,
      ),
      throwsArgumentError,
    );
  });

  test('pings update_session.csp for HTTP keepalive', () async {
    final client = FakeDataPlaneHttpClient();
    final keepalive = EasyConnectKeepaliveClient(client: client);
    final alive = await keepalive.ping(
      Uri.parse('https://vpn.example.test'),
      'twf-1',
    );
    expect(alive, isTrue);
    final request = client.requests.single;
    expect(request.url.path, '/por/update_session.csp');
    expect(request.url.queryParameters['twfid'], 'twf-1');
    expect(request.headers['cookie'], 'TWFID=twf-1');

    keepalive.stop();
  });
}
