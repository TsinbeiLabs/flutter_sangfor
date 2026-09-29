import 'dart:async';
import 'dart:collection';
import 'dart:math';
import 'dart:typed_data';

import 'socks5.dart';
import 'tcp_packet_codec.dart';
import 'tunnel_io.dart';

/// Decides which TCP flows the terminator should claim.
///
/// A tunnel that can only forward the flows its gateway publishes for raw L3
/// transport needs this: everything else is relayed as a byte stream instead
/// of being dropped as unrouted.
typedef SangforTcpTerminationFilter = bool Function(
    String destinationAddress, int destinationPort);

/// Maps an IP destination back to the host name the tunnel should dial.
///
/// Raw packets only carry addresses, while gateways commonly publish
/// resources as domain names; without this mapping a domain-published resource
/// cannot be matched once the client has resolved it.
typedef SangforTcpDialHostResolver = String? Function(
    String destinationAddress, int destinationPort);

/// Terminates TCP connections that arrive as raw IP packets and relays their
/// payload through a byte-stream dialer (RFC 793, server role).
///
/// This is what makes a packet device useful against a tunnel that only
/// accepts some flows as raw IP: the local stack completes a handshake with
/// the terminator, which dials the real destination through the tunnel and
/// copies bytes in both directions. Only the client-facing side is synthesized;
/// the upstream side is a plain [SangforTcpStream].
///
/// Deliberately minimal: no window scaling, no SACK, no timestamps, and
/// out-of-order segments are answered with a duplicate ACK so the peer
/// retransmits. That covers HTTP-shaped traffic and keeps the state machine
/// small enough to audit.
class SangforTcpTerminator {
  SangforTcpTerminator({
    required SangforTcpDialer dialer,
    required SangforTcpTerminationFilter shouldTerminate,
    SangforTcpDialHostResolver? dialHostResolver,
    this.maximumSegmentSize = 1400,
    this.advertisedWindow = 65535,
    this.dialTimeout = const Duration(seconds: 20),
    this.idleTimeout = const Duration(minutes: 5),
    this.initialRetransmitTimeout = const Duration(milliseconds: 300),
    this.maximumRetransmitTimeout = const Duration(seconds: 8),
    this.maximumRetransmits = 8,
    this.pauseUpstreamAt = 512 * 1024,
    this.resumeUpstreamAt = 128 * 1024,
    Random? random,
    void Function(Object error)? onError,
  })  : assert(maximumSegmentSize > 0 && maximumSegmentSize <= 65495),
        assert(advertisedWindow > 0 && advertisedWindow <= 65535),
        assert(resumeUpstreamAt < pauseUpstreamAt),
        _dialer = dialer,
        _shouldTerminate = shouldTerminate,
        _dialHostResolver = dialHostResolver,
        _random = random ?? Random(),
        _onError = onError,
        _outgoing = StreamController<Uint8List>.broadcast() {
    _identifier = _random.nextInt(0xffff);
  }

  /// Largest TCP payload the terminator sends. A peer offering a smaller MSS
  /// in its SYN clamps it further.
  final int maximumSegmentSize;

  /// Receive window advertised to the local stack. Without window scaling this
  /// also caps a single connection's throughput.
  final int advertisedWindow;

  final Duration dialTimeout;
  final Duration idleTimeout;
  final Duration initialRetransmitTimeout;
  final Duration maximumRetransmitTimeout;
  final int maximumRetransmits;

  /// Upstream queue depth at which reading is paused, and the depth it must
  /// fall back to before reading resumes.
  final int pauseUpstreamAt;
  final int resumeUpstreamAt;

  final SangforTcpDialer _dialer;
  final SangforTcpTerminationFilter _shouldTerminate;
  final SangforTcpDialHostResolver? _dialHostResolver;
  final Random _random;
  final void Function(Object error)? _onError;
  final StreamController<Uint8List> _outgoing;
  final Map<String, _TerminatedConnection> _connections =
      <String, _TerminatedConnection>{};
  final SangforTcpPacketBuilder _builder = const SangforTcpPacketBuilder();

  int _identifier = 0;
  bool _closed = false;

  /// Packets the terminator synthesized, to be injected into the packet
  /// device. Broadcast; listen before the first [accept].
  Stream<Uint8List> get outgoing => _outgoing.stream;

  bool get isClosed => _closed;

  /// Number of live terminated connections.
  int get connectionCount => _connections.length;

  /// Consumes one raw IP packet. Returns true when the terminator claimed it,
  /// which covers both packets it answers itself and packets of a flow it
  /// already owns. Returning false leaves the packet with the caller, which
  /// forwards it to the tunnel as usual.
  bool accept(Uint8List packet) {
    if (_closed) return false;
    final segment = SangforTcpSegment.parse(packet);
    if (segment == null) return false;
    final key = segment.flowKey;
    final existing = _connections[key];
    if (existing != null) {
      existing.handle(segment);
      return true;
    }
    if (_connections.containsKey(segment.reversedFlowKey)) {
      // An echo of a packet we synthesized; never hand it back to the tunnel.
      return true;
    }
    if (!segment.isSyn || segment.isAck) return false;
    if (!_shouldTerminate(
        segment.destinationAddress, segment.destinationPort)) {
      return false;
    }
    final connection = _TerminatedConnection(
      terminator: this,
      key: key,
      clientAddress: segment.sourceAddress,
      clientPort: segment.sourcePort,
      serverAddress: segment.destinationAddress,
      serverPort: segment.destinationPort,
    );
    _connections[key] = connection;
    connection.start(segment);
    return true;
  }

  /// Tears every connection down and stops accepting.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    final connections = List<_TerminatedConnection>.of(_connections.values);
    _connections.clear();
    for (final connection in connections) {
      await connection.abort();
    }
    if (!_outgoing.isClosed) {
      await _outgoing.close();
    }
  }

  void _remove(_TerminatedConnection connection) {
    if (_connections[connection.key] == connection) {
      _connections.remove(connection.key);
    }
  }

  void _emit(Uint8List packet) {
    if (_closed || _outgoing.isClosed) return;
    _outgoing.add(packet);
  }

  void _report(Object error) {
    if (_closed) return;
    _onError?.call(error);
  }

  int _nextIdentification() {
    _identifier = (_identifier + 1) & 0xffff;
    return _identifier;
  }
}

enum _TerminationState {
  synReceived,
  established,
  inboundClosed,
  outboundClosed,
  closed,
}

/// One built-but-unacknowledged segment, kept for retransmission.
class _UnacknowledgedSegment {
  _UnacknowledgedSegment(this.packet, this.sequenceNumber, this.length);

  final Uint8List packet;
  final int sequenceNumber;

  /// Sequence space this segment occupies: one for a bare SYN or FIN, the
  /// payload length otherwise.
  final int length;
}

/// A chunk list with cheap front removal, so relaying a large response does
/// not degrade into quadratic copying.
class _ChunkQueue {
  final Queue<Uint8List> _chunks = Queue<Uint8List>();
  int _headOffset = 0;
  int _length = 0;

  int get length => _length;

  bool get isEmpty => _length == 0;

  void add(List<int> bytes) {
    if (bytes.isEmpty) return;
    _chunks.add(Uint8List.fromList(bytes));
    _length += bytes.length;
  }

  /// Removes and returns up to [limit] bytes from the front, or null when the
  /// queue is empty.
  Uint8List? take(int limit) {
    if (_length == 0 || limit <= 0) return null;
    final result = BytesBuilder();
    var remaining = limit;
    while (remaining > 0 && _chunks.isNotEmpty) {
      final first = _chunks.first;
      final available = first.length - _headOffset;
      if (available <= remaining) {
        result.add(Uint8List.sublistView(first, _headOffset));
        _length -= available;
        remaining -= available;
        _chunks.removeFirst();
        _headOffset = 0;
      } else {
        result.add(
          Uint8List.sublistView(first, _headOffset, _headOffset + remaining),
        );
        _headOffset += remaining;
        _length -= remaining;
        remaining = 0;
      }
    }
    if (result.isEmpty) return null;
    return result.toBytes();
  }

  void clear() {
    _chunks.clear();
    _headOffset = 0;
    _length = 0;
  }
}

class _TerminatedConnection {
  _TerminatedConnection({
    required SangforTcpTerminator terminator,
    required this.key,
    required this.clientAddress,
    required this.clientPort,
    required this.serverAddress,
    required this.serverPort,
  }) : _terminator = terminator;

  final SangforTcpTerminator _terminator;
  final String key;
  final String clientAddress;
  final int clientPort;
  final String serverAddress;
  final int serverPort;

  final Queue<_UnacknowledgedSegment> _unacknowledged =
      Queue<_UnacknowledgedSegment>();
  final _ChunkQueue _sendQueue = _ChunkQueue();
  final List<int> _pendingForUpstream = <int>[];

  SangforTcpStream? _upstream;
  StreamSubscription<Uint8List>? _upstreamSubscription;
  Timer? _retransmitTimer;
  Timer? _idleTimer;
  Duration _retransmitTimeout = const Duration(milliseconds: 300);
  int _retransmits = 0;

  int _clientInitialSequence = 0;
  int _ourInitialSequence = 0;
  int _receiveNext = 0;
  int _sendNext = 0;
  int _sendUnacknowledged = 0;
  int _peerWindow = 0;
  int _maximumSegmentSize = 1400;
  bool _handshakeComplete = false;
  bool _upstreamDone = false;
  bool _upstreamPaused = false;
  bool _finSent = false;
  bool _disposed = false;

  _TerminationState _state = _TerminationState.synReceived;

  /// Bytes queued for the local stack but not sent yet.
  int get queuedBytes => _sendQueue.length;

  void start(SangforTcpSegment syn) {
    _clientInitialSequence = syn.sequenceNumber;
    _receiveNext = tcpSequenceAdd(_clientInitialSequence, 1);
    _ourInitialSequence = _terminator._random.nextInt(0x7fffffff);
    _sendNext = tcpSequenceAdd(_ourInitialSequence, 1);
    _sendUnacknowledged = _ourInitialSequence;
    _peerWindow = syn.window;
    final offeredMss = syn.maximumSegmentSize;
    _maximumSegmentSize = offeredMss == 0
        ? _terminator.maximumSegmentSize
        : (offeredMss < _terminator.maximumSegmentSize
            ? offeredMss
            : _terminator.maximumSegmentSize);
    _retransmitTimeout = _terminator.initialRetransmitTimeout;
    _transmit(
      flags: tcpFlagSyn | tcpFlagAck,
      mss: _maximumSegmentSize,
      sequenceLength: 1,
      sequenceOverride: _ourInitialSequence,
    );
    _armIdleTimer();
    // Dial while the handshake completes: the tunnel round trip dominates
    // setup latency, and a half-open connection is released by [abort].
    unawaited(_openUpstream());
  }

  void handle(SangforTcpSegment segment) {
    if (_disposed) return;
    _armIdleTimer();
    if (segment.isRst) {
      unawaited(_dispose(reset: false));
      return;
    }
    _peerWindow = segment.window;
    if (segment.isAck) {
      _acknowledge(segment.acknowledgmentNumber);
    }
    if (_state == _TerminationState.synReceived) {
      if (!_handshakeComplete) {
        // The SYN-ACK is still in flight; nothing else is meaningful yet.
        return;
      }
      _state = _TerminationState.established;
    }
    if (segment.isSyn) {
      // A retransmitted SYN: answer with the current state, keep the flow.
      _sendAck();
      return;
    }
    final payload = segment.payload;
    if (payload.isNotEmpty) {
      _acceptPayload(segment.sequenceNumber, payload);
    }
    if (segment.isFin) {
      _receiveNext = tcpSequenceAdd(_receiveNext, 1);
      _sendAck();
      if (_state == _TerminationState.established) {
        _state = _TerminationState.inboundClosed;
        unawaited(_closeUpstreamWrite());
      }
    }
    _flush();
    _maybeFinish();
  }

  void _acceptPayload(int sequence, Uint8List payload) {
    final gap = tcpSequenceDifference(sequence, _receiveNext);
    if (gap > 0) {
      // A hole in the stream: drop it and repeat the ACK so the peer
      // retransmits the missing segment.
      _sendAck();
      return;
    }
    final overlap = -gap;
    if (overlap >= payload.length) {
      // Data we already relayed.
      _sendAck();
      return;
    }
    final fresh =
        overlap == 0 ? payload : Uint8List.sublistView(payload, overlap);
    _receiveNext = tcpSequenceAdd(_receiveNext, fresh.length);
    _sendAck();
    final upstream = _upstream;
    if (upstream == null || upstream.isClosed) {
      // The dial is still in flight. Only the first flight of a connection can
      // land here, so this buffer stays small.
      _pendingForUpstream.addAll(fresh);
      return;
    }
    unawaited(
      upstream.send(Uint8List.fromList(fresh)).catchError((Object error) {
        _terminator._report(error);
        unawaited(_dispose(reset: true));
      }),
    );
  }

  Future<void> _closeUpstreamWrite() async {
    final upstream = _upstream;
    if (upstream == null) return;
    try {
      await upstream.closeWrite();
    } on Object catch (error) {
      _terminator._report(error);
    }
  }

  Future<void> _openUpstream() async {
    try {
      final host =
          _terminator._dialHostResolver?.call(serverAddress, serverPort) ??
              serverAddress;
      final stream = await _terminator
          ._dialer(
            host,
            serverPort,
          )
          .timeout(_terminator.dialTimeout);
      if (_disposed) {
        await stream.close();
        return;
      }
      _upstream = stream;
      _listenUpstream(stream);
      if (_pendingForUpstream.isNotEmpty) {
        final buffered = Uint8List.fromList(_pendingForUpstream);
        _pendingForUpstream.clear();
        await stream.send(buffered);
      }
      if (_state == _TerminationState.inboundClosed) {
        await stream.closeWrite();
      }
      _flush();
    } on Object catch (error) {
      _terminator._report(error);
      if (_disposed) return;
      // Nothing can be relayed, so the local stack must be told the connection
      // is gone instead of being left to time out.
      await _dispose(reset: true);
    }
  }

  void _listenUpstream(SangforTcpStream stream) {
    _upstreamSubscription = stream.incoming.listen(
      (chunk) {
        if (_disposed) return;
        _sendQueue.add(chunk);
        _flush();
        if (_sendQueue.length >= _terminator.pauseUpstreamAt &&
            !_upstreamPaused) {
          _upstreamPaused = true;
          _upstreamSubscription?.pause();
        }
      },
      onDone: () {
        _upstreamDone = true;
        if (_disposed) return;
        _flush();
        _maybeFinish();
      },
      onError: (Object error) {
        _terminator._report(error);
        if (_disposed) return;
        unawaited(_dispose(reset: true));
      },
      cancelOnError: true,
    );
  }

  /// Sends our FIN once the upstream is done and every queued byte has been
  /// acknowledged, then retires the connection when that FIN is acknowledged.
  void _maybeFinish() {
    if (_disposed || _finSent) return;
    if (!_upstreamDone) return;
    if (!_sendQueue.isEmpty || _unacknowledged.isNotEmpty) return;
    if (_state == _TerminationState.closed) return;
    _transmit(flags: tcpFlagFin | tcpFlagAck, sequenceLength: 1);
    _finSent = true;
    _state = _TerminationState.outboundClosed;
  }

  void _maybeDisposeAfterFin() {
    if (_disposed || !_finSent) return;
    if (_unacknowledged.isNotEmpty) return;
    unawaited(_dispose(reset: false));
  }

  /// Pushes queued upstream bytes out as segments the peer's window allows.
  void _flush() {
    if (_disposed || !_handshakeComplete) return;
    while (!_sendQueue.isEmpty) {
      final inFlight = tcpSequenceDifference(_sendUnacknowledged, _sendNext);
      final available = _peerWindow - inFlight;
      if (available <= 0) break;
      final limit =
          available < _maximumSegmentSize ? available : _maximumSegmentSize;
      final payload = _sendQueue.take(limit);
      if (payload == null || payload.isEmpty) break;
      _transmit(
        flags: tcpFlagAck | tcpFlagPsh,
        payload: payload,
        sequenceLength: payload.length,
      );
    }
    if (_sendQueue.length < _terminator.resumeUpstreamAt && _upstreamPaused) {
      _upstreamPaused = false;
      _upstreamSubscription?.resume();
    }
    _armRetransmitTimer();
    if (_upstreamDone) {
      _maybeFinish();
    }
  }

  void _sendAck() {
    if (_disposed || !_handshakeComplete) return;
    _terminator._emit(
      _terminator._builder.build(
        sourceAddress: serverAddress,
        destinationAddress: clientAddress,
        sourcePort: serverPort,
        destinationPort: clientPort,
        sequenceNumber: _sendNext,
        acknowledgmentNumber: _receiveNext,
        flags: tcpFlagAck,
        window: _terminator.advertisedWindow,
        identification: _terminator._nextIdentification(),
      ),
    );
  }

  void _transmit({
    required int flags,
    required int sequenceLength,
    Uint8List? payload,
    int? mss,
    int? sequenceOverride,
  }) {
    final sequence = sequenceOverride ?? _sendNext;
    final packet = _terminator._builder.build(
      sourceAddress: serverAddress,
      destinationAddress: clientAddress,
      sourcePort: serverPort,
      destinationPort: clientPort,
      sequenceNumber: sequence,
      acknowledgmentNumber: _receiveNext,
      flags: flags,
      window: _terminator.advertisedWindow,
      payload: payload,
      mss: mss,
      identification: _terminator._nextIdentification(),
    );
    if (sequenceOverride == null) {
      _sendNext = tcpSequenceAdd(_sendNext, sequenceLength);
    }
    _unacknowledged.add(
      _UnacknowledgedSegment(packet, sequence, sequenceLength),
    );
    _terminator._emit(packet);
    _armRetransmitTimer();
  }

  void _acknowledge(int acknowledgment) {
    if (tcpSequenceDifference(_sendUnacknowledged, acknowledgment) < 0) {
      // Already acknowledged, or a duplicate ACK.
      _maybeFinish();
      return;
    }
    if (tcpSequenceDifference(_sendNext, acknowledgment) > 0) {
      // Beyond anything we sent: ignore instead of trusting a bogus ACK.
      return;
    }
    var advanced = false;
    while (_unacknowledged.isNotEmpty) {
      final oldest = _unacknowledged.first;
      final end = tcpSequenceAdd(oldest.sequenceNumber, oldest.length);
      // Stop at the first segment the ACK does not fully cover. A cumulative
      // ACK spans several segments, so this must compare end against ack and
      // not the other way round.
      if (tcpSequenceDifference(acknowledgment, end) > 0) break;
      _unacknowledged.removeFirst();
      _sendUnacknowledged = end;
      advanced = true;
    }
    if (advanced) {
      _retransmits = 0;
      _retransmitTimeout = _terminator.initialRetransmitTimeout;
    }
    if (!_handshakeComplete &&
        tcpSequenceDifference(
              _sendUnacknowledged,
              tcpSequenceAdd(_ourInitialSequence, 1),
            ) >=
            0) {
      _handshakeComplete = true;
    }
    _maybeDisposeAfterFin();
    _flush();
  }

  void _armRetransmitTimer() {
    if (_disposed) return;
    if (_unacknowledged.isEmpty) {
      _retransmitTimer?.cancel();
      _retransmitTimer = null;
      return;
    }
    if (_retransmitTimer?.isActive ?? false) return;
    _retransmitTimer = Timer(_retransmitTimeout, _onRetransmitTimeout);
  }

  void _onRetransmitTimeout() {
    if (_disposed || _unacknowledged.isEmpty) return;
    if (_retransmits >= _terminator.maximumRetransmits) {
      _terminator._report(
        TimeoutException(
          'terminated TCP flow to $serverAddress:$serverPort gave up after '
          '${_terminator.maximumRetransmits} retransmits',
        ),
      );
      unawaited(_dispose(reset: true));
      return;
    }
    _retransmits++;
    _terminator._emit(_unacknowledged.first.packet);
    final doubled = _retransmitTimeout * 2;
    _retransmitTimeout = doubled > _terminator.maximumRetransmitTimeout
        ? _terminator.maximumRetransmitTimeout
        : doubled;
    _retransmitTimer = Timer(_retransmitTimeout, _onRetransmitTimeout);
  }

  void _armIdleTimer() {
    _idleTimer?.cancel();
    if (_disposed) return;
    _idleTimer = Timer(_terminator.idleTimeout, () {
      unawaited(_dispose(reset: true));
    });
  }

  /// Optionally resets the peer, then releases every resource.
  Future<void> _dispose({required bool reset}) async {
    if (_disposed) return;
    _disposed = true;
    _state = _TerminationState.closed;
    if (reset) {
      _terminator._emit(
        _terminator._builder.build(
          sourceAddress: serverAddress,
          destinationAddress: clientAddress,
          sourcePort: serverPort,
          destinationPort: clientPort,
          sequenceNumber: _sendNext,
          acknowledgmentNumber: 0,
          flags: tcpFlagRst,
          window: 0,
          identification: _terminator._nextIdentification(),
        ),
      );
    }
    _retransmitTimer?.cancel();
    _retransmitTimer = null;
    _idleTimer?.cancel();
    _idleTimer = null;
    _unacknowledged.clear();
    _sendQueue.clear();
    _pendingForUpstream.clear();
    final subscription = _upstreamSubscription;
    _upstreamSubscription = null;
    try {
      await subscription?.cancel();
    } on Object {
      // The stream is already gone.
    }
    final upstream = _upstream;
    _upstream = null;
    try {
      await upstream?.close();
    } on Object {
      // The tunnel already tore the stream down.
    }
    _terminator._remove(this);
  }

  Future<void> abort() => _dispose(reset: false);
}

/// Presents a [SangforTcpTerminator] and a raw-IP tunnel as one tunnel.
///
/// Packets the terminator claims never reach [inner]; the packets it
/// synthesizes are merged into [incoming], so a [SangforTunnelRouter] injects
/// them into the packet device exactly like tunnel traffic.
class SangforTerminatingTunnel implements SangforPacketTunnel {
  SangforTerminatingTunnel({
    required SangforPacketTunnel inner,
    required SangforTcpTerminator terminator,
  })  : _inner = inner,
        _terminator = terminator,
        _merged = StreamController<Uint8List>.broadcast() {
    _innerSubscription = _inner.incoming.listen(
      _forward,
      onError: _addError,
      onDone: _sourceDone,
    );
    _terminatorSubscription = _terminator.outgoing.listen(
      _forward,
      onError: _addError,
      onDone: _sourceDone,
    );
  }

  final SangforPacketTunnel _inner;
  final SangforTcpTerminator _terminator;
  final StreamController<Uint8List> _merged;
  StreamSubscription<Uint8List>? _innerSubscription;
  StreamSubscription<Uint8List>? _terminatorSubscription;
  int _finishedSources = 0;
  bool _closed = false;

  @override
  Stream<Uint8List> get incoming => _merged.stream;

  @override
  bool get isClosed => _closed || _inner.isClosed;

  @override
  Future<bool> sendPacket(Uint8List packet) async {
    if (_closed) return false;
    if (_terminator.accept(packet)) return true;
    return _inner.sendPacket(packet);
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    final inner = _innerSubscription;
    final terminator = _terminatorSubscription;
    _innerSubscription = null;
    _terminatorSubscription = null;
    await inner?.cancel();
    await terminator?.cancel();
    await _terminator.close();
    await _inner.close();
    if (!_merged.isClosed) {
      await _merged.close();
    }
  }

  void _forward(Uint8List packet) {
    if (_merged.isClosed) return;
    _merged.add(packet);
  }

  void _addError(Object error, StackTrace stackTrace) {
    if (_merged.isClosed) return;
    _merged.addError(error, stackTrace);
  }

  void _sourceDone() {
    if (_merged.isClosed) return;
    _finishedSources++;
    // Both halves must be finished before the merged stream ends, otherwise a
    // router would stop while the other half can still deliver packets.
    if (_finishedSources < 2) return;
    unawaited(_merged.close());
  }
}
