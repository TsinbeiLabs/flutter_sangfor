import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_sangfor_easy_connect/flutter_sangfor_easy_connect.dart';
import 'package:test/test.dart';

class _FakeTransport implements EasyConnectPacketTransport {
  final _incoming = StreamController<Uint8List>.broadcast();
  final sent = <Uint8List>[];
  void Function(Uint8List packet)? onSend;

  @override
  Stream<Uint8List> get incoming => _incoming.stream;

  @override
  Future<void> sendPacket(Uint8List packet) async {
    sent.add(packet);
    onSend?.call(packet);
  }

  void inject(Uint8List packet) {
    _incoming.add(packet);
  }
}

const List<int> _clientIp = <int>[172, 16, 1, 30];
const List<int> _serverIp = <int>[10, 0, 0, 9];
const List<int> _dnsIp = <int>[10, 0, 0, 53];
const int _serverPort = 80;

/// A scripted TCP peer at [_serverIp]:[_serverPort] over the fake transport.
class _FakeTcpPeer {
  _FakeTcpPeer(this._transport, {this.dropFirstDataSegment = false});

  final _FakeTransport _transport;
  final bool dropFirstDataSegment;

  static const int peerIss = 5000;
  final List<Uint8List> received = <Uint8List>[];
  int _sndNxt = peerIss + 1;
  int _clientPort = 0;
  int _clientIss = 0;
  bool resetReceived = false;
  int _ignoredDataSegments = 0;

  void handlePacket(Uint8List packet) {
    final ip = parseIpv4Packet(packet);
    if (ip == null || ip.protocol != ipProtocolTcp) return;
    final segment = parseTcpSegment(ip.srcIp, ip.dstIp, ip.payload);
    if (segment == null || segment.dstPort != _serverPort) return;
    if (segment.rst) {
      resetReceived = true;
      return;
    }
    if (segment.syn && !segment.hasAck) {
      _clientPort = segment.srcPort;
      _clientIss = segment.seq;
      _reply(
        flags: tcpFlagSyn | tcpFlagAck,
        seq: peerIss,
        ack: (segment.seq + 1) & 0xffffffff,
        options: mssOption(1400),
      );
      return;
    }
    if (segment.hasAck) {
      if (segment.payload.isNotEmpty) {
        if (dropFirstDataSegment && _ignoredDataSegments == 0) {
          _ignoredDataSegments++;
          return;
        }
        _ignoredDataSegments++;
        received.add(segment.payload);
        final ackNumber = (segment.seq + segment.payload.length) & 0xffffffff;
        _reply(
          flags: tcpFlagAck | tcpFlagPsh,
          seq: _sndNxt,
          ack: ackNumber,
          payload: segment.payload,
        );
        _sndNxt = (_sndNxt + segment.payload.length) & 0xffffffff;
      }
      if (segment.fin) {
        _reply(
          flags: tcpFlagAck,
          seq: _sndNxt,
          ack: (segment.seq + 1) & 0xffffffff,
        );
      }
    }
  }

  /// Sends data with an explicit sequence number for out-of-order tests.
  void sendDataAt(int seq, Uint8List data) {
    _reply(
      flags: tcpFlagAck | tcpFlagPsh,
      seq: seq,
      ack: (_clientIss + 1) & 0xffffffff,
      payload: data,
    );
  }

  void sendReset() {
    _reply(
      flags: tcpFlagRst | tcpFlagAck,
      seq: _sndNxt,
      ack: (_clientIss + 1) & 0xffffffff,
    );
  }

  void _reply({
    required int flags,
    required int seq,
    required int ack,
    Uint8List? payload,
    List<int> options = const <int>[],
  }) {
    final segment = buildTcpSegment(
      srcIp: _serverIp,
      dstIp: _clientIp,
      srcPort: _serverPort,
      dstPort: _clientPort,
      seq: seq,
      ack: ack,
      flags: flags,
      window: 0xffff,
      payload: payload,
      options: options,
    );
    final packet = buildIpPacket(
      srcIp: _serverIp,
      dstIp: _clientIp,
      protocol: ipProtocolTcp,
      payload: segment,
    );
    _transport.inject(packet);
  }
}

EasyConnectTcpProxy _startProxy(
  _FakeTransport transport, {
  Duration initialRto = const Duration(seconds: 1),
  List<String> dnsServers = const <String>[],
  Duration dnsTimeout = const Duration(seconds: 4),
}) {
  final proxy = EasyConnectTcpProxy(
    tunnel: transport,
    sourceIp: _clientIp,
    initialRto: initialRto,
    dnsServers: dnsServers,
    dnsTimeout: dnsTimeout,
  );
  proxy.start();
  return proxy;
}

void main() {
  test('handshake, data exchange, and clean close', () async {
    final transport = _FakeTransport();
    final peer = _FakeTcpPeer(transport);
    transport.onSend = peer.handlePacket;
    final proxy = _startProxy(transport);

    final connection = await proxy.dialTcp('10.0.0.9', _serverPort);
    expect(connection.isClosed, isFalse);

    await connection.send(Uint8List.fromList('hello'.codeUnits));
    final received = <Uint8List>[];
    final echoed = Completer<void>();
    final streamDone = Completer<void>();
    final subscription = connection.incoming.listen(
      (chunk) {
        received.add(chunk);
        if (!echoed.isCompleted) echoed.complete();
      },
      onDone: streamDone.complete,
    );
    await echoed.future.timeout(const Duration(seconds: 5));
    expect(utf8.decode(received.single), 'hello');
    expect(peer.received.length, 1);
    expect(utf8.decode(peer.received.first), 'hello');

    await connection.close();
    await streamDone.future.timeout(const Duration(seconds: 5));
    expect(connection.isClosed, isTrue);
    await subscription.cancel();
    await proxy.close();
  });

  test('sends data larger than the MSS as multiple segments', () async {
    final transport = _FakeTransport();
    final peer = _FakeTcpPeer(transport);
    transport.onSend = peer.handlePacket;
    final proxy = _startProxy(transport);

    final connection = await proxy.dialTcp('10.0.0.9', _serverPort);
    final payload = Uint8List.fromList(
      List<int>.generate(3000, (index) => index & 0xff),
    );
    final received = BytesBuilder();
    final allEchoed = Completer<void>();
    final subscription = connection.incoming.listen(
      (chunk) {
        received.add(chunk);
        if (received.length == payload.length) allEchoed.complete();
      },
    );
    await connection.send(payload);

    final dataSegments = transport.sent
        .map(parseIpv4Packet)
        .whereType<Ipv4Packet>()
        .where((ip) => ip.protocol == ipProtocolTcp)
        .map((ip) => parseTcpSegment(ip.srcIp, ip.dstIp, ip.payload))
        .whereType<TcpSegment>()
        .where((segment) => segment.payload.isNotEmpty)
        .toList();
    expect(dataSegments.length, greaterThanOrEqualTo(3));
    for (final segment in dataSegments) {
      expect(segment.payload.length, lessThanOrEqualTo(1300));
    }
    final reassembled = BytesBuilder();
    for (final segment in dataSegments) {
      reassembled.add(segment.payload);
    }
    expect(reassembled.toBytes(), payload);

    await allEchoed.future.timeout(const Duration(seconds: 5));
    expect(received.toBytes(), payload);
    await subscription.cancel();
    await connection.close();
    await proxy.close();
  });

  test('retransmits a dropped data segment', () async {
    final transport = _FakeTransport();
    final peer = _FakeTcpPeer(transport, dropFirstDataSegment: true);
    transport.onSend = peer.handlePacket;
    final proxy = _startProxy(
      transport,
      initialRto: const Duration(milliseconds: 120),
    );

    final connection = await proxy.dialTcp('10.0.0.9', _serverPort);
    await connection.send(Uint8List.fromList('retry me'.codeUnits));

    final echoed = await connection.incoming.first
        .timeout(const Duration(seconds: 5));
    expect(utf8.decode(echoed), 'retry me');
    expect(peer.received.length, 1);

    final dataPackets = transport.sent
        .map(parseIpv4Packet)
        .whereType<Ipv4Packet>()
        .where((ip) => ip.protocol == ipProtocolTcp)
        .map((ip) => parseTcpSegment(ip.srcIp, ip.dstIp, ip.payload))
        .whereType<TcpSegment>()
        .where((segment) => segment.payload.isNotEmpty)
        .toList();
    expect(dataPackets.length, greaterThanOrEqualTo(2));
    expect(dataPackets.first.seq, dataPackets.last.seq);

    await connection.close();
    await proxy.close();
  });

  test('surfaces a peer reset as a stream error', () async {
    final transport = _FakeTransport();
    final peer = _FakeTcpPeer(transport);
    transport.onSend = peer.handlePacket;
    final proxy = _startProxy(transport);

    final connection = await proxy.dialTcp('10.0.0.9', _serverPort);
    final errors = <Object>[];
    final subscription = connection.incoming.listen(
      (chunk) {},
      onError: errors.add,
      cancelOnError: false,
    );
    await Future<void>.delayed(Duration.zero);
    peer.sendReset();
    await Future<void>.delayed(Duration.zero);
    expect(errors, hasLength(1));
    expect(errors.first, isA<EasyConnectTcpResetException>());
    expect(connection.isClosed, isTrue);
    await subscription.cancel();
    await proxy.close();
  });

  test('delivers out-of-order segments in order', () async {
    final transport = _FakeTransport();
    final peer = _FakeTcpPeer(transport);
    transport.onSend = peer.handlePacket;
    final proxy = _startProxy(transport);

    final connection = await proxy.dialTcp('10.0.0.9', _serverPort);
    final received = BytesBuilder();
    final done = Completer<void>();
    final subscription = connection.incoming.listen(
      (chunk) {
        received.add(chunk);
        if (received.length == 6) done.complete();
      },
    );
    await Future<void>.delayed(Duration.zero);

    const base = _FakeTcpPeer.peerIss + 1;
    peer.sendDataAt(base + 3, Uint8List.fromList([4, 5, 6]));
    peer.sendDataAt(base, Uint8List.fromList([1, 2, 3]));
    await done.future.timeout(const Duration(seconds: 5));
    expect(received.toBytes(), [1, 2, 3, 4, 5, 6]);

    await subscription.cancel();
    await connection.close();
    await proxy.close();
  });

  test('half-close keeps the receive side open', () async {
    final transport = _FakeTransport();
    final peer = _FakeTcpPeer(transport);
    transport.onSend = peer.handlePacket;
    final proxy = _startProxy(transport);

    final connection = await proxy.dialTcp('10.0.0.9', _serverPort);
    await connection.closeWrite();
    await Future<void>.delayed(Duration.zero);
    peer.sendDataAt(
      (_FakeTcpPeer.peerIss + 1) & 0xffffffff,
      Uint8List.fromList('late'.codeUnits),
    );
    final late = await connection.incoming.first
        .timeout(const Duration(seconds: 5));
    expect(utf8.decode(late), 'late');

    await connection.close();
    await proxy.close();
  });

  test('dial times out when the peer is silent', () async {
    final transport = _FakeTransport();
    final proxy = _startProxy(transport);

    await expectLater(
      proxy.dialTcp(
        '10.0.0.9',
        _serverPort,
        timeout: const Duration(milliseconds: 200),
      ),
      throwsA(isA<TimeoutException>()),
    );
    await proxy.close();
  });

  test('resolves names through the tunnel DNS', () async {
    final transport = _FakeTransport();
    void handleUdp(Uint8List packet) {
      final ip = parseIpv4Packet(packet);
      if (ip == null || ip.protocol != ipProtocolUdp) return;
      final datagram = parseUdpDatagram(ip.payload);
      if (datagram == null || datagram.dstPort != 53) return;
      final query = datagram.payload;
      final id = (query[0] << 8) | query[1];
      var offset = 12;
      while (query[offset] != 0) {
        offset += 1 + query[offset];
      }
      final question = query.sublist(12, offset + 5);
      final answer = <int>[
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
        0x00, 0x04, 10, 1, 2, 3,
      ];
      final reply = <int>[
        (id >> 8) & 0xff, id & 0xff, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        ...question,
        ...answer,
      ];
      final replyDatagram = buildUdpDatagram(
        srcIp: _dnsIp,
        dstIp: _clientIp,
        srcPort: 53,
        dstPort: datagram.srcPort,
        payload: Uint8List.fromList(reply),
      );
      transport.inject(
        buildIpPacket(
          srcIp: _dnsIp,
          dstIp: _clientIp,
          protocol: ipProtocolUdp,
          payload: replyDatagram,
        ),
      );
    }

    transport.onSend = handleUdp;
    final proxy = _startProxy(transport, dnsServers: <String>['10.0.0.53']);

    final address = await proxy.resolveHost('vpn.internal');
    expect(address, <int>[10, 1, 2, 3]);
    await proxy.close();
  });

  test('DNS failure surfaces as an exception', () async {
    final transport = _FakeTransport();
    void handleUdp(Uint8List packet) {
      final ip = parseIpv4Packet(packet);
      if (ip == null || ip.protocol != ipProtocolUdp) return;
      final datagram = parseUdpDatagram(ip.payload);
      if (datagram == null || datagram.dstPort != 53) return;
      final query = datagram.payload;
      final id = (query[0] << 8) | query[1];
      // NXDOMAIN with no answers.
      final reply = Uint8List.fromList(<int>[
        (id >> 8) & 0xff, id & 0xff, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        ...query.sublist(12),
      ]);
      final replyDatagram = buildUdpDatagram(
        srcIp: _dnsIp,
        dstIp: _clientIp,
        srcPort: 53,
        dstPort: datagram.srcPort,
        payload: reply,
      );
      transport.inject(
        buildIpPacket(
          srcIp: _dnsIp,
          dstIp: _clientIp,
          protocol: ipProtocolUdp,
          payload: replyDatagram,
        ),
      );
    }

    transport.onSend = handleUdp;
    final proxy = _startProxy(
      transport,
      dnsServers: <String>['10.0.0.53'],
      dnsTimeout: const Duration(milliseconds: 300),
    );

    await expectLater(
      proxy.resolveHost('missing.internal'),
      throwsA(isA<EasyConnectDnsException>()),
    );
    await proxy.close();
  });
}
