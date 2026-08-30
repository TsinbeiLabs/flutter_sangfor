import 'dart:typed_data';

import 'packet.dart';

enum ATrustTcpConntrackState {
  reset,
  inboundSyn,
  outboundSyn,
  synAck,
  established,
  inboundFin,
  inboundFirstClosed,
  outboundFin,
  outboundFirstClosed,
}

const Duration _tcpResetTTL = Duration(seconds: 90);
const Duration _tcpInboundSynTTL = Duration(seconds: 120);
const Duration _tcpOutboundSynTTL = Duration(seconds: 60);
const Duration _tcpSynAckTTL = Duration(seconds: 60);
const Duration _tcpInboundFirstClosedTTL = Duration(seconds: 120);
const Duration _tcpOutboundFirstClosedTTL = Duration(seconds: 30);
const Duration _tcpEstablishedTTL = Duration(hours: 6);
const Duration _udpConntrackTTL = Duration(seconds: 120);
const Duration _icmpConntrackTTL = Duration(seconds: 30);
const Duration _defaultConntrackTTL = Duration(seconds: 60);

class ATrustTcpConntrack {
  ATrustTcpConntrackState state = ATrustTcpConntrackState.reset;
  int? sequenceNumber;
  Duration ttl = _defaultConntrackTTL;

  void observeTcp(ATrustTCPPacket packet, bool incoming) {
    final flags = packet.flags;
    if ((flags & tcpRstFlag) != 0) {
      state = ATrustTcpConntrackState.reset;
      ttl = _tcpResetTTL;
      return;
    }
    if (ttl == Duration.zero) {
      ttl = _defaultConntrackTTL;
    }
    final sequence = packet.sequenceNumber;
    final acknowledgment = packet.acknowledgmentNumber;
    final direction = incoming ? 1 : 0;

    switch (state) {
      case ATrustTcpConntrackState.reset:
        if ((flags & tcpSynFlag) == 0) return;
        sequenceNumber = sequence;
        if (direction == 1) {
          state = ATrustTcpConntrackState.inboundSyn;
          ttl = _tcpInboundSynTTL;
        } else {
          state = ATrustTcpConntrackState.outboundSyn;
          ttl = _tcpOutboundSynTTL;
        }
      case ATrustTcpConntrackState.inboundSyn:
        if (direction != 0 || (flags & tcpSynFlag) == 0) return;
        if ((flags & tcpAckFlag) != 0 &&
            acknowledgment == ((sequenceNumber! + 1) & 0xffffffff)) {
          state = ATrustTcpConntrackState.established;
          ttl = _tcpEstablishedTTL;
          return;
        }
        state = ATrustTcpConntrackState.synAck;
        sequenceNumber = sequence;
        ttl = _tcpSynAckTTL;
      case ATrustTcpConntrackState.outboundSyn:
        if (direction == 1 &&
            (flags & (tcpSynFlag | tcpAckFlag)) == (tcpSynFlag | tcpAckFlag) &&
            acknowledgment == ((sequenceNumber! + 1) & 0xffffffff)) {
          state = ATrustTcpConntrackState.synAck;
          sequenceNumber = sequence;
          ttl = _tcpSynAckTTL;
        }
      case ATrustTcpConntrackState.synAck:
        if (direction == 0 &&
            (flags & tcpAckFlag) != 0 &&
            acknowledgment == ((sequenceNumber! + 1) & 0xffffffff)) {
          state = ATrustTcpConntrackState.established;
          ttl = _tcpEstablishedTTL;
          return;
        }
        _observeTcpFin(flags, direction);
      case ATrustTcpConntrackState.established:
        _observeTcpFin(flags, direction);
      case ATrustTcpConntrackState.inboundFin:
        if (direction == 0 && (flags & tcpFinFlag) != 0) {
          state = ATrustTcpConntrackState.inboundFirstClosed;
          ttl = _tcpInboundFirstClosedTTL;
        }
      case ATrustTcpConntrackState.outboundFin:
        if (direction == 1 && (flags & tcpFinFlag) != 0) {
          state = ATrustTcpConntrackState.outboundFirstClosed;
          ttl = _tcpOutboundFirstClosedTTL;
        }
      case ATrustTcpConntrackState.inboundFirstClosed:
      case ATrustTcpConntrackState.outboundFirstClosed:
        break;
    }
  }

  void _observeTcpFin(int flags, int direction) {
    if ((flags & tcpFinFlag) == 0) return;
    if (direction == 1) {
      state = ATrustTcpConntrackState.inboundFin;
    } else {
      state = ATrustTcpConntrackState.outboundFin;
    }
  }
}

Duration protocolTtl(int protocol, ATrustTcpConntrack? tcp) {
  switch (protocol) {
    case tcpProtocol:
      return tcp?.ttl ?? _defaultConntrackTTL;
    case udpProtocol:
      return _udpConntrackTTL;
    case icmpProtocol:
      return _icmpConntrackTTL;
    default:
      return _defaultConntrackTTL;
  }
}

void observeConntrackPacket(
  ATrustTcpConntrack? conntrack,
  Uint8List packet,
  bool incoming,
) {
  if (conntrack == null) return;
  final ip = ATrustIPv4Packet(packet);
  if (!ip.valid) return;

  switch (ip.protocol) {
    case tcpProtocol:
      final tcp = ATrustTCPPacket(ip.payload);
      if (tcp.valid) {
        conntrack.observeTcp(tcp, incoming);
      }
    case udpProtocol:
    case icmpProtocol:
      break;
  }
}
