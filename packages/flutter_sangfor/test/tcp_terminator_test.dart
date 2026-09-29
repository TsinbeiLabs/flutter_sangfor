import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_sangfor/src/tcp_packet_codec.dart';
import 'package:flutter_test/flutter_test.dart';

const String _clientAddress = '10.0.0.42';
const String _serverAddress = '202.114.64.7';
const int _clientPort = 51000;
const int _serverPort = 443;

/// An in-memory upstream: what the tunnel hands back for a dial.
class FakeUpstream implements SangforTcpStream {
  final StreamController<Uint8List> _controller = StreamController<Uint8List>();
  final List<Uint8List> sent = <Uint8List>[];
  bool closed = false;
  bool writeClosed = false;

  @override
  Stream<Uint8List> get incoming => _controller.stream;

  @override
  bool get isClosed => closed;

  @override
  Future<void> send(Uint8List data) async {
    if (closed) throw StateError('upstream is closed');
    sent.add(data);
  }

  @override
  Future<void> closeWrite() async {
    writeClosed = true;
  }

  @override
  Future<void> close() async {
    closed = true;
    if (!_controller.isClosed) {
      await _controller.close();
    }
  }

  void deliver(List<int> bytes) => _controller.add(Uint8List.fromList(bytes));

  void fail(Object error) => _controller.addError(error);

  void finish() => unawaited(_controller.close());

  String get sentText =>
      sent.map((chunk) => String.fromCharCodes(chunk)).join();
}

/// A tunnel double that records what the terminator declined to claim.
class FakeRawTunnel implements SangforPacketTunnel {
  final StreamController<Uint8List> _incoming =
      StreamController<Uint8List>.broadcast();
  final List<Uint8List> forwarded = <Uint8List>[];
  bool closed = false;

  @override
  Stream<Uint8List> get incoming => _incoming.stream;

  @override
  bool get isClosed => closed;

  @override
  Future<bool> sendPacket(Uint8List packet) async {
    forwarded.add(packet);
    return true;
  }

  @override
  Future<void> close() async {
    closed = true;
    if (!_incoming.isClosed) {
      await _incoming.close();
    }
  }

  void inject(Uint8List packet) => _incoming.add(packet);
}

/// Builds a terminator plus the records a test needs to assert on.
class _Harness {
  _Harness({
    this.dialDelay = Duration.zero,
    this.dialError,
    bool Function(String host, int port)? filter,
    String? Function(String host, int port)? hostResolver,
    Duration retransmitTimeout = const Duration(milliseconds: 40),
    int maximumSegmentSize = 1400,
    int maximumRetransmits = 8,
  }) {
    terminator = SangforTcpTerminator(
      dialer: (String host, int port) async {
        dialed.add('$host:$port');
        final failure = dialError;
        if (failure != null) throw failure;
        if (dialDelay > Duration.zero) {
          await Future<void>.delayed(dialDelay);
        }
        final upstream = FakeUpstream();
        streams.add(upstream);
        return upstream;
      },
      shouldTerminate:
          filter ?? (String host, int port) => host == _serverAddress,
      dialHostResolver: hostResolver,
      maximumSegmentSize: maximumSegmentSize,
      initialRetransmitTimeout: retransmitTimeout,
      maximumRetransmits: maximumRetransmits,
      onError: (Object error) => errors.add(error),
    );
  }

  late final SangforTcpTerminator terminator;
  final List<Uint8List> emitted = <Uint8List>[];
  final List<String> dialed = <String>[];
  final List<FakeUpstream> streams = <FakeUpstream>[];
  final List<Object> errors = <Object>[];
  final Duration dialDelay;
  final Object? dialError;

  StreamSubscription<Uint8List>? _subscription;

  _Harness start() {
    _subscription = terminator.outgoing.listen(emitted.add);
    return this;
  }

  Future<void> dispose() async {
    await _subscription?.cancel();
    await terminator.close();
  }

  FakeUpstream get upstream => streams.last;

  SangforTcpSegment get last => SangforTcpSegment.parse(emitted.last)!;

  List<SangforTcpSegment> get segments => emitted
      .map((packet) => SangforTcpSegment.parse(packet))
      .whereType<SangforTcpSegment>()
      .toList(growable: false);

  List<SangforTcpSegment> get dataSegments => segments
      .where((segment) => segment.payload.isNotEmpty)
      .toList(growable: false);
}

Uint8List clientPacket({
  required int sequence,
  required int acknowledgment,
  required int flags,
  List<int> payload = const <int>[],
  int window = 65535,
  int? mss,
}) =>
    const SangforTcpPacketBuilder().build(
      sourceAddress: _clientAddress,
      destinationAddress: _serverAddress,
      sourcePort: _clientPort,
      destinationPort: _serverPort,
      sequenceNumber: sequence,
      acknowledgmentNumber: acknowledgment,
      flags: flags,
      window: window,
      payload: Uint8List.fromList(payload),
      mss: mss,
    );

final Uint8List udpPacket = Uint8List.fromList(<int>[
  0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, //
  10, 0, 0, 42, 202, 114, 64, 7, //
  0, 0, 0, 0, 0, 0, 0, 0, //
]);

/// Feeds a SYN and returns the terminator's SYN-ACK.
Future<SangforTcpSegment> _acceptSyn(
  _Harness harness, {
  int window = 65535,
  int? mss,
}) async {
  harness.terminator.accept(
    clientPacket(
      sequence: 1000,
      acknowledgment: 0,
      flags: tcpFlagSyn,
      window: window,
      mss: mss ?? 1460,
    ),
  );
  await pumpEventQueue();
  return harness.segments.firstWhere(
    (segment) => segment.isSyn && segment.isAck,
  );
}

/// Completes a handshake and returns the terminator's initial sequence number.
Future<int> _handshake(_Harness harness, {int window = 65535}) async {
  final synAck = await _acceptSyn(harness, window: window);
  harness.terminator.accept(
    clientPacket(
      sequence: 1001,
      acknowledgment: synAck.sequenceNumber + 1,
      flags: tcpFlagAck,
      window: window,
    ),
  );
  await pumpEventQueue();
  return synAck.sequenceNumber;
}

void main() {
  group('packet codec', () {
    test('round-trips a segment with payload and options', () {
      final packet = const SangforTcpPacketBuilder().build(
        sourceAddress: _clientAddress,
        destinationAddress: _serverAddress,
        sourcePort: _clientPort,
        destinationPort: _serverPort,
        sequenceNumber: 0x11223344,
        acknowledgmentNumber: 0x55667788,
        flags: tcpFlagSyn | tcpFlagAck,
        window: 64240,
        payload: Uint8List.fromList(<int>[1, 2, 3, 4, 5]),
        mss: 1400,
        identification: 7,
      );
      final segment = SangforTcpSegment.parse(packet)!;
      expect(segment.sourceAddress, _clientAddress);
      expect(segment.destinationAddress, _serverAddress);
      expect(segment.sourcePort, _clientPort);
      expect(segment.destinationPort, _serverPort);
      expect(segment.sequenceNumber, 0x11223344);
      expect(segment.acknowledgmentNumber, 0x55667788);
      expect(segment.isSyn, isTrue);
      expect(segment.isAck, isTrue);
      expect(segment.window, 64240);
      expect(segment.maximumSegmentSize, 1400);
      expect(segment.payload, <int>[1, 2, 3, 4, 5]);
      expect(segment.tcpLength, 24 + 5);
      expect(
          segment.flowKey,
          '$_clientAddress:$_clientPort-'
          '$_serverAddress:$_serverPort');
      expect(
          segment.reversedFlowKey,
          '$_serverAddress:$_serverPort-'
          '$_clientAddress:$_clientPort');
    });

    test('rejects buffers that are not IPv4/TCP', () {
      expect(SangforTcpSegment.parse(Uint8List(10)), isNull);
      expect(SangforTcpSegment.parse(udpPacket), isNull);
      final ipv6 = Uint8List.fromList(<int>[
        0x60, 0, 0, 0, //
        ...List<int>.filled(36, 0),
      ]);
      expect(SangforTcpSegment.parse(ipv6), isNull);
    });

    test('computes checksums a verifier accepts', () {
      final packet = const SangforTcpPacketBuilder().build(
        sourceAddress: '192.168.1.5',
        destinationAddress: '93.184.216.34',
        sourcePort: 40000,
        destinationPort: 80,
        sequenceNumber: 1,
        acknowledgmentNumber: 2,
        flags: tcpFlagAck | tcpFlagPsh,
        window: 1024,
        payload: Uint8List.fromList(List<int>.generate(37, (index) => index)),
      );
      // A correct IPv4 header sums to all ones, checksum field included.
      expect(_folded(_sumRange(packet, 0, 20)), 0xffff);
      // The same holds for the TCP checksum over its pseudo-header.
      final stored = (packet[36] << 8) | packet[37];
      packet[36] = 0;
      packet[37] = 0;
      expect(tcpChecksum(packet), stored);
    });

    test('rejects an unusable endpoint', () {
      expect(
        () => const SangforTcpPacketBuilder().build(
          sourceAddress: 'not-an-ip',
          destinationAddress: _serverAddress,
          sourcePort: 1,
          destinationPort: 2,
          sequenceNumber: 0,
          acknowledgmentNumber: 0,
          flags: tcpFlagSyn,
          window: 0,
        ),
        throwsArgumentError,
      );
    });

    test('sequence arithmetic wraps', () {
      expect(tcpSequenceAdd(0xffffffff, 2), 1);
      expect(tcpSequenceDifference(0xffffffff, 1), 2);
      expect(tcpSequenceDifference(1, 0xffffffff), -2);
      expect(tcpSequenceDifference(5, 5), 0);
    });

    test('parses the MSS option past a no-op', () {
      final packet = Uint8List.fromList(<int>[
        0x45, 0, 0, 48, 0, 0, 0, 0, 64, 6, 0, 0, //
        10, 0, 0, 42, 202, 114, 64, 7, //
        0xc3, 0x50, 0x01, 0xbb, // ports
        0, 0, 0, 1, // sequence
        0, 0, 0, 0, // acknowledgment
        0x70, 0x02, 0xff, 0xff, // data offset 7, SYN, window
        0, 0, 0, 0, // checksum, urgent
        1, 1, 2, 4, 0x05, 0xb4, 0, 0, // NOP, NOP, MSS=1460, padding
      ]);
      expect(SangforTcpSegment.parse(packet)?.maximumSegmentSize, 1460);
    });
  });

  group('SangforTcpTerminator', () {
    test('declines non-TCP, non-SYN, and non-matching flows', () async {
      final harness = _Harness().start();
      addTearDown(harness.dispose);
      expect(harness.terminator.accept(udpPacket), isFalse);
      expect(harness.terminator.accept(Uint8List(4)), isFalse);
      final elsewhere = const SangforTcpPacketBuilder().build(
        sourceAddress: _clientAddress,
        destinationAddress: '8.8.8.8',
        sourcePort: _clientPort,
        destinationPort: 53,
        sequenceNumber: 1,
        acknowledgmentNumber: 0,
        flags: tcpFlagSyn,
        window: 65535,
      );
      expect(harness.terminator.accept(elsewhere), isFalse);
      // A bare data packet for an unknown flow is not claimed either.
      expect(
        harness.terminator.accept(
          clientPacket(
            sequence: 1,
            acknowledgment: 1,
            flags: tcpFlagAck,
            payload: <int>[1, 2, 3],
          ),
        ),
        isFalse,
      );
      expect(
          harness.terminator.accept(
            clientPacket(sequence: 1000, acknowledgment: 0, flags: tcpFlagSyn),
          ),
          isTrue);
      await pumpEventQueue();
      expect(harness.emitted, hasLength(1));
      expect(harness.terminator.connectionCount, 1);
    });

    test('completes the handshake and dials through the tunnel', () async {
      final harness = _Harness().start();
      addTearDown(harness.dispose);
      final synAck = await _acceptSyn(harness, window: 64240);
      expect(synAck.isSyn, isTrue);
      expect(synAck.isAck, isTrue);
      expect(synAck.sourceAddress, _serverAddress);
      expect(synAck.destinationAddress, _clientAddress);
      expect(synAck.sourcePort, _serverPort);
      expect(synAck.destinationPort, _clientPort);
      expect(synAck.acknowledgmentNumber, 1001);
      expect(synAck.maximumSegmentSize, 1400);
      expect(harness.dialed, <String>['$_serverAddress:$_serverPort']);

      final ourIss = synAck.sequenceNumber;
      harness.terminator.accept(
        clientPacket(
          sequence: 1001,
          acknowledgment: ourIss + 1,
          flags: tcpFlagAck,
        ),
      );
      await pumpEventQueue();
      expect(harness.terminator.connectionCount, 1);

      harness.upstream.deliver(<int>[0x48, 0x69]);
      await pumpEventQueue();
      final data = harness.dataSegments.single;
      expect(data.payload, <int>[0x48, 0x69]);
      expect(data.sequenceNumber, ourIss + 1);
      expect(data.acknowledgmentNumber, 1001);
      expect(data.sourceAddress, _serverAddress);
    });

    test('relays client bytes upstream in order', () async {
      final harness = _Harness().start();
      addTearDown(harness.dispose);
      final ourIss = await _handshake(harness);
      harness.terminator.accept(
        clientPacket(
          sequence: 1001,
          acknowledgment: ourIss + 1,
          flags: tcpFlagAck | tcpFlagPsh,
          payload: 'GET / HTTP/1.1\r\n\r\n'.codeUnits,
        ),
      );
      await pumpEventQueue();
      expect(harness.upstream.sentText, 'GET / HTTP/1.1\r\n\r\n');
      expect(harness.last.acknowledgmentNumber, 1001 + 18);
      expect(harness.last.payload, isEmpty);
    });

    test('buffers the first flight until the dial resolves', () async {
      final harness = _Harness(
        dialDelay: const Duration(milliseconds: 40),
      ).start();
      addTearDown(harness.dispose);
      final synAck = await _acceptSyn(harness);
      harness.terminator.accept(
        clientPacket(
          sequence: 1001,
          acknowledgment: synAck.sequenceNumber + 1,
          flags: tcpFlagAck | tcpFlagPsh,
          payload: <int>[1, 2, 3],
        ),
      );
      await pumpEventQueue();
      expect(harness.streams, isEmpty);
      await Future<void>.delayed(const Duration(milliseconds: 80));
      await pumpEventQueue();
      expect(harness.upstream.sent, hasLength(1));
      expect(harness.upstream.sent.single, <int>[1, 2, 3]);
    });

    test('respects the peer window and resumes after an ACK', () async {
      final harness = _Harness().start();
      addTearDown(harness.dispose);
      final synAck = await _acceptSyn(harness, window: 100);
      harness.terminator.accept(
        clientPacket(
          sequence: 1001,
          acknowledgment: synAck.sequenceNumber + 1,
          flags: tcpFlagAck,
          window: 100,
        ),
      );
      await pumpEventQueue();
      harness.upstream.deliver(List<int>.filled(250, 7));
      await pumpEventQueue();
      expect(harness.dataSegments, hasLength(1));
      expect(harness.dataSegments.single.payload, hasLength(100));

      harness.terminator.accept(
        clientPacket(
          sequence: 1001,
          acknowledgment: harness.dataSegments.single.sequenceNumber + 100,
          flags: tcpFlagAck,
        ),
      );
      await pumpEventQueue();
      final delivered = harness.dataSegments.fold<int>(
        0,
        (sum, segment) => sum + segment.payload.length,
      );
      expect(delivered, 250);
      expect(harness.dataSegments, hasLength(2));
    });

    test('segments a large response at the MSS', () async {
      final harness = _Harness(maximumSegmentSize: 100).start();
      addTearDown(harness.dispose);
      final synAck = await _acceptSyn(harness, mss: 100);
      harness.terminator.accept(
        clientPacket(
          sequence: 1001,
          acknowledgment: synAck.sequenceNumber + 1,
          flags: tcpFlagAck,
        ),
      );
      await pumpEventQueue();
      final body = List<int>.generate(350, (index) => index % 251);
      harness.upstream.deliver(body);
      await pumpEventQueue();
      expect(
        harness.dataSegments.map((segment) => segment.payload.length),
        <int>[100, 100, 100, 50],
      );
      expect(
        harness.dataSegments.expand((segment) => segment.payload).toList(),
        body,
      );
      // Sequence numbers must advance by exactly the payload length.
      for (var index = 1; index < harness.dataSegments.length; index++) {
        final previous = harness.dataSegments[index - 1];
        expect(
          harness.dataSegments[index].sequenceNumber,
          previous.sequenceNumber + previous.payload.length,
        );
      }
    });

    test('a cumulative ACK releases every segment it covers', () async {
      final harness = _Harness().start();
      addTearDown(harness.dispose);
      final synAck = await _acceptSyn(harness);
      harness.terminator.accept(
        clientPacket(
          sequence: 1001,
          acknowledgment: synAck.sequenceNumber + 1,
          flags: tcpFlagAck,
        ),
      );
      await pumpEventQueue();
      harness.upstream.deliver(List<int>.filled(3000, 7));
      await pumpEventQueue();
      final sent = harness.dataSegments;
      expect(sent, hasLength(3));
      final last = sent.last;
      final cumulativeAck = last.sequenceNumber + last.payload.length;

      // One ACK covering all three segments must retire all of them; the
      // inverted comparison this replaces left the window shut forever.
      harness.terminator.accept(
        clientPacket(
          sequence: 1001,
          acknowledgment: cumulativeAck,
          flags: tcpFlagAck,
        ),
      );
      await pumpEventQueue();
      harness.upstream.finish();
      await pumpEventQueue();
      expect(
        harness.segments.any((segment) => segment.isFin),
        isTrue,
        reason: 'nothing is left unacknowledged, so the FIN is released',
      );
    });

    test('a partial ACK only releases the segments it covers', () async {
      final harness = _Harness().start();
      addTearDown(harness.dispose);
      final synAck = await _acceptSyn(harness);
      harness.terminator.accept(
        clientPacket(
          sequence: 1001,
          acknowledgment: synAck.sequenceNumber + 1,
          flags: tcpFlagAck,
        ),
      );
      await pumpEventQueue();
      harness.upstream.deliver(List<int>.filled(3000, 7));
      await pumpEventQueue();
      final sent = harness.dataSegments;
      expect(sent, hasLength(3));

      // Acknowledge only the first segment: the FIN must stay pending.
      harness.terminator.accept(
        clientPacket(
          sequence: 1001,
          acknowledgment: sent.first.sequenceNumber + sent.first.payload.length,
          flags: tcpFlagAck,
        ),
      );
      await pumpEventQueue();
      harness.upstream.finish();
      await pumpEventQueue();
      expect(
        harness.segments.any((segment) => segment.isFin),
        isFalse,
        reason: 'two segments are still unacknowledged',
      );

      // Acknowledging the rest releases it.
      final last = sent.last;
      harness.terminator.accept(
        clientPacket(
          sequence: 1001,
          acknowledgment: last.sequenceNumber + last.payload.length,
          flags: tcpFlagAck,
        ),
      );
      await pumpEventQueue();
      expect(
        harness.segments.any((segment) => segment.isFin),
        isTrue,
      );
    });

    test('clamps the MSS to the smaller offer', () async {
      final harness = _Harness().start();
      addTearDown(harness.dispose);
      expect((await _acceptSyn(harness, mss: 536)).maximumSegmentSize, 536);
      final wide = _Harness(maximumSegmentSize: 500).start();
      addTearDown(wide.dispose);
      expect((await _acceptSyn(wide, mss: 1460)).maximumSegmentSize, 500);
    });

    test('retransmits the SYN-ACK while the handshake stalls', () async {
      final harness = _Harness().start();
      addTearDown(harness.dispose);
      await _acceptSyn(harness);
      expect(harness.emitted, hasLength(1));
      await Future<void>.delayed(const Duration(milliseconds: 120));
      await pumpEventQueue();
      expect(harness.emitted.length, greaterThanOrEqualTo(2));
      expect(harness.emitted[1], harness.emitted[0]);
    });

    test('gives up and resets after too many retransmits', () async {
      final harness = _Harness(
        retransmitTimeout: const Duration(milliseconds: 5),
        maximumRetransmits: 3,
      ).start();
      addTearDown(harness.dispose);
      await _acceptSyn(harness);
      await Future<void>.delayed(const Duration(milliseconds: 200));
      await pumpEventQueue();
      expect(harness.terminator.connectionCount, 0);
      expect(harness.last.isRst, isTrue);
      expect(harness.errors, isNotEmpty);
    });

    test('half-closes upstream on FIN and finishes with its own', () async {
      final harness = _Harness().start();
      addTearDown(harness.dispose);
      final ourIss = await _handshake(harness);
      harness.terminator.accept(
        clientPacket(
          sequence: 1001,
          acknowledgment: ourIss + 1,
          flags: tcpFlagFin | tcpFlagAck,
        ),
      );
      await pumpEventQueue();
      expect(harness.upstream.writeClosed, isTrue);
      expect(
        harness.segments.any((segment) => segment.isFin),
        isFalse,
        reason: 'our FIN waits for the upstream to finish',
      );

      harness.upstream.deliver(<int>[9]);
      harness.upstream.finish();
      await pumpEventQueue();
      expect(
        harness.segments.any((segment) => segment.isFin),
        isFalse,
        reason: 'the queued byte is still unacknowledged',
      );

      final data = harness.dataSegments.single;
      harness.terminator.accept(
        clientPacket(
          sequence: 1002,
          acknowledgment: data.sequenceNumber + data.payload.length,
          flags: tcpFlagAck,
        ),
      );
      await pumpEventQueue();
      final fin = harness.segments.firstWhere((segment) => segment.isFin);
      expect(fin.isAck, isTrue);
      expect(fin.sequenceNumber, data.sequenceNumber + 1);

      harness.terminator.accept(
        clientPacket(
          sequence: 1002,
          acknowledgment: fin.sequenceNumber + 1,
          flags: tcpFlagAck,
        ),
      );
      await pumpEventQueue();
      expect(harness.terminator.connectionCount, 0);
      expect(harness.upstream.closed, isTrue);
    });

    test('a reset from the client tears the flow down', () async {
      final harness = _Harness().start();
      addTearDown(harness.dispose);
      await _handshake(harness);
      harness.terminator.accept(
        clientPacket(sequence: 1001, acknowledgment: 0, flags: tcpFlagRst),
      );
      await pumpEventQueue();
      expect(harness.terminator.connectionCount, 0);
      expect(harness.upstream.closed, isTrue);
    });

    test('resets the client when the dial fails', () async {
      final harness = _Harness(
        dialError: StateError('no TCP tunnel resource for host:443'),
      ).start();
      addTearDown(harness.dispose);
      await _acceptSyn(harness);
      await pumpEventQueue();
      expect(harness.errors.single.toString(), contains('no TCP tunnel'));
      expect(harness.last.isRst, isTrue);
      expect(harness.terminator.connectionCount, 0);
    });

    test('resets the client when the upstream fails mid-flow', () async {
      final harness = _Harness().start();
      addTearDown(harness.dispose);
      await _handshake(harness);
      harness.upstream.fail(StateError('tunnel died'));
      await pumpEventQueue();
      expect(harness.errors, isNotEmpty);
      expect(harness.last.isRst, isTrue);
      expect(harness.terminator.connectionCount, 0);
    });

    test('answers a retransmitted data segment with a duplicate ACK', () async {
      final harness = _Harness().start();
      addTearDown(harness.dispose);
      final ourIss = await _handshake(harness);
      final data = clientPacket(
        sequence: 1001,
        acknowledgment: ourIss + 1,
        flags: tcpFlagAck | tcpFlagPsh,
        payload: <int>[1, 2, 3, 4],
      );
      harness.terminator.accept(data);
      await pumpEventQueue();
      final before = harness.emitted.length;
      harness.terminator.accept(data);
      await pumpEventQueue();
      expect(harness.emitted.length, before + 1);
      expect(harness.last.acknowledgmentNumber, 1005);
      expect(harness.last.payload, isEmpty);
      expect(harness.upstream.sent, hasLength(1));
    });

    test('drops a segment that opens a gap', () async {
      final harness = _Harness().start();
      addTearDown(harness.dispose);
      final ourIss = await _handshake(harness);
      harness.terminator.accept(
        clientPacket(
          sequence: 1010,
          acknowledgment: ourIss + 1,
          flags: tcpFlagAck | tcpFlagPsh,
          payload: <int>[1, 2, 3],
        ),
      );
      await pumpEventQueue();
      expect(harness.upstream.sent, isEmpty);
      expect(harness.last.acknowledgmentNumber, 1001);
      // Filling the gap delivers both flights in order.
      harness.terminator.accept(
        clientPacket(
          sequence: 1001,
          acknowledgment: ourIss + 1,
          flags: tcpFlagAck | tcpFlagPsh,
          payload: List<int>.filled(9, 5),
        ),
      );
      await pumpEventQueue();
      expect(harness.upstream.sent, hasLength(1));
      expect(harness.upstream.sent.single, hasLength(9));
      expect(harness.last.acknowledgmentNumber, 1010);
    });

    test('resolves the dial host through the resolver', () async {
      final harness = _Harness(
        hostResolver: (String host, int port) =>
            host == _serverAddress ? 'portal.whu.edu.cn' : null,
      ).start();
      addTearDown(harness.dispose);
      await _handshake(harness);
      expect(harness.dialed, <String>['portal.whu.edu.cn:$_serverPort']);
    });

    test('closing the terminator releases every connection', () async {
      final harness = _Harness().start();
      await _handshake(harness);
      expect(harness.terminator.connectionCount, 1);
      await harness.terminator.close();
      expect(harness.terminator.connectionCount, 0);
      expect(harness.terminator.isClosed, isTrue);
      expect(harness.upstream.closed, isTrue);
      expect(
          harness.terminator.accept(
            clientPacket(sequence: 1, acknowledgment: 0, flags: tcpFlagSyn),
          ),
          isFalse);
      await harness.dispose();
    });
  });

  group('SangforTerminatingTunnel', () {
    test('claims terminated flows and forwards the rest', () async {
      final harness = _Harness().start();
      addTearDown(harness.dispose);
      final inner = FakeRawTunnel();
      final tunnel = SangforTerminatingTunnel(
        inner: inner,
        terminator: harness.terminator,
      );
      final merged = <Uint8List>[];
      final subscription = tunnel.incoming.listen(merged.add);
      addTearDown(subscription.cancel);

      final claimed = clientPacket(
        sequence: 1000,
        acknowledgment: 0,
        flags: tcpFlagSyn,
        mss: 1460,
      );
      expect(await tunnel.sendPacket(claimed), isTrue);
      expect(inner.forwarded, isEmpty);

      final unclaimed = const SangforTcpPacketBuilder().build(
        sourceAddress: _clientAddress,
        destinationAddress: '8.8.8.8',
        sourcePort: _clientPort,
        destinationPort: 53,
        sequenceNumber: 1,
        acknowledgmentNumber: 0,
        flags: tcpFlagSyn,
        window: 65535,
      );
      expect(await tunnel.sendPacket(unclaimed), isTrue);
      expect(inner.forwarded, <Uint8List>[unclaimed]);

      final fromTunnel = Uint8List.fromList(<int>[1, 2, 3]);
      inner.inject(fromTunnel);
      await pumpEventQueue();
      expect(merged, contains(fromTunnel));
      expect(
        merged.any((packet) => SangforTcpSegment.parse(packet) != null),
        isTrue,
        reason: 'the SYN-ACK must reach the device',
      );

      await tunnel.close();
      expect(inner.closed, isTrue);
      expect(tunnel.isClosed, isTrue);
    });

    test('closing both sources ends the merged stream', () async {
      final harness = _Harness().start();
      final inner = FakeRawTunnel();
      final tunnel = SangforTerminatingTunnel(
        inner: inner,
        terminator: harness.terminator,
      );
      var done = false;
      final subscription = tunnel.incoming.listen(
        (Uint8List _) {},
        onDone: () => done = true,
      );
      await harness.terminator.close();
      await pumpEventQueue();
      expect(done, isFalse, reason: 'the inner tunnel is still live');
      await inner.close();
      await pumpEventQueue();
      expect(done, isTrue);
      await subscription.cancel();
      await harness.dispose();
    });
  });
}

int _sumRange(Uint8List data, int start, int end) {
  var sum = 0;
  for (var index = start; index + 1 < end; index += 2) {
    sum += (data[index] << 8) | data[index + 1];
  }
  return sum;
}

int _folded(int sum) {
  var value = sum;
  while (value >> 16 != 0) {
    value = (value & 0xffff) + (value >> 16);
  }
  return value;
}
