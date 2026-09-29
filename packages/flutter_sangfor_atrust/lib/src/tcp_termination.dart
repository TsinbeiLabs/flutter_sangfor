import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_sangfor/flutter_sangfor.dart';

import 'atrust_tunnel.dart';
import 'resource.dart';
import 'tcp_tunnel_client.dart';

/// Chooses the TCP flows an aTrust gateway will not forward as raw IP and
/// relays them through the TCP tunnel instead.
///
/// Gateways publish most resources for the TCP tunnel only, and
/// [matchL3Route] mirrors the upstream client by refusing those as raw IP. On
/// a packet device that is a black hole: the local stack's SYNs are dropped as
/// unrouted, so connections hang without a reply. Terminating them locally and
/// dialing through [ATrustTunnel.dialTcp] keeps a raw-IP data plane usable
/// without a system proxy, which is what the desktop adapters need.
///
/// Flows the L3 plane can carry are left alone, so nothing is double-routed.
class ATrustTcpTermination {
  ATrustTcpTermination({
    required this.resource,
    this.dialHosts = const <String, String>{},
    this.includeL3Preferred = true,
    this.maximumSegmentSize = 1400,
  });

  final ATrustResource resource;

  /// Reverse map from a resolved IPv4 address to the host name the gateway
  /// published. Raw packets only carry addresses, and a domain-published
  /// resource cannot be matched by IP; callers that resolved those domains for
  /// their routing table should pass the mapping so the dial keeps the
  /// resource identity (and therefore the right `appId`).
  final Map<String, String> dialHosts;

  /// Also accept resources the gateway marks as L3-preferred when nothing else
  /// matches, mirroring [ATrustTunnel.dialTcp].
  final bool includeL3Preferred;

  /// Largest segment the terminator sends to the local stack.
  final int maximumSegmentSize;

  /// True when a TCP flow to `destinationAddress:destinationPort` must be
  /// terminated locally: the L3 plane refuses it, but the TCP tunnel can serve
  /// it.
  bool shouldTerminate(String destinationAddress, int destinationPort) {
    if (matchL3Route(
          resource.routes,
          destinationAddress,
          'tcp',
          destinationPort,
        ) !=
        null) {
      return false;
    }
    return matchTcpRoute(
          resource.routes,
          dialHost(destinationAddress, destinationPort) ?? destinationAddress,
          destinationPort,
          includeL3Preferred: includeL3Preferred,
        ) !=
        null;
  }

  /// The host name to dial for a destination address, or null to dial the
  /// address itself.
  String? dialHost(String destinationAddress, int destinationPort) =>
      dialHosts[destinationAddress];

  /// Opens one relayed connection through the aTrust TCP tunnel.
  Future<SangforTcpStream> dial(
    ATrustTunnel tunnel,
    String host,
    int port,
  ) async =>
      ATrustTcpTunnelStream(
        await tunnel.dialTcp(host, port,
            includeL3Preferred: includeL3Preferred),
      );

  /// Builds the terminator for [tunnel].
  SangforTcpTerminator terminator(
    ATrustTunnel tunnel, {
    void Function(Object error)? onError,
  }) =>
      SangforTcpTerminator(
        dialer: (String host, int port) => dial(tunnel, host, port),
        shouldTerminate: shouldTerminate,
        dialHostResolver: dialHost,
        maximumSegmentSize: maximumSegmentSize,
        onError: onError,
      );

  /// Wraps [tunnel] so a [SangforTunnelRouter] sees one packet tunnel:
  /// terminated flows are relayed, everything else is forwarded as raw IP, and
  /// the packets the terminator synthesizes are merged back into the incoming
  /// stream.
  SangforPacketTunnel wrap(
    ATrustTunnel tunnel, {
    void Function(Object error)? onError,
  }) =>
      SangforTerminatingTunnel(
        inner: ATrustPacketTunnel(tunnel),
        terminator: terminator(tunnel, onError: onError),
      );

  /// Builds [dialHosts] from resolved host names: every address a name
  /// resolved to maps back to that name.
  static Map<String, String> reverseHosts(
    Map<String, Iterable<String>> resolved,
  ) {
    final hosts = <String, String>{};
    resolved.forEach((String host, Iterable<String> addresses) {
      for (final address in addresses) {
        hosts.putIfAbsent(address, () => host);
      }
    });
    return hosts;
  }
}

/// Presents an [ATrustTunnel] as a product-neutral [SangforPacketTunnel].
class ATrustPacketTunnel implements SangforPacketTunnel {
  ATrustPacketTunnel(this.tunnel);

  final ATrustTunnel tunnel;

  @override
  Stream<Uint8List> get incoming => tunnel.incoming;

  @override
  bool get isClosed => tunnel.isClosed;

  @override
  Future<bool> sendPacket(Uint8List packet) => tunnel.sendPacket(packet);

  @override
  Future<void> close() => tunnel.close();
}
