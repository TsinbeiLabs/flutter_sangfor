import 'dart:async';
import 'dart:io';

import 'resource.dart';

/// Result of probing one node address.
class ATrustNodeProbe {
  const ATrustNodeProbe({
    required this.node,
    required this.successes,
    required this.failures,
    required this.totalLatency,
  });

  final String node;
  final int successes;
  final int failures;
  final Duration totalLatency;

  /// Upstream score: average latency plus a penalty per failed probe.
  Duration score(Duration penalty) {
    if (successes == 0) return Duration.zero;
    final average = totalLatency ~/ successes;
    return average + penalty * failures;
  }

  bool get reachable => successes > 0;
}

/// Measures the connect latency of a node, or null when unreachable.
typedef ATrustNodeDialer = Future<Duration?> Function(
  String host,
  int port,
  Duration timeout,
);

/// Probes node groups and remembers the best (lowest-score) address per group,
/// WAN first with LAN fallback, mirroring the upstream selection behavior.
class ATrustNodeSelector {
  ATrustNodeSelector({
    this.probeCount = 3,
    this.probeTimeout = const Duration(seconds: 1),
    this.probeInterval = const Duration(milliseconds: 500),
    this.penalty = const Duration(seconds: 1),
  });

  final int probeCount;
  final Duration probeTimeout;
  final Duration probeInterval;
  final Duration penalty;

  Future<Map<String, String>> select(
    Map<String, ATrustNodeGroup> nodeGroups, {
    required ATrustNodeDialer dialer,
  }) async {
    final best = <String, String>{};
    final wanGroups = <String, List<String>>{
      for (final entry in nodeGroups.entries)
        if (entry.value.wan.isNotEmpty) entry.key: entry.value.wan,
    };
    final wanResults = await _probeGroups(wanGroups, dialer);
    best.addAll(wanResults);

    final lanGroups = <String, List<String>>{
      for (final entry in nodeGroups.entries)
        if (best[entry.key] == null && entry.value.lan.isNotEmpty)
          entry.key: entry.value.lan,
    };
    if (lanGroups.isNotEmpty) {
      best.addAll(await _probeGroups(lanGroups, dialer));
    }
    return best;
  }

  Future<Map<String, String>> _probeGroups(
    Map<String, List<String>> groups,
    ATrustNodeDialer dialer,
  ) async {
    final best = <String, String>{};
    for (final entry in groups.entries) {
      final probes = await Future.wait(
        entry.value.map((node) => _probeNode(node, dialer)),
      );
      ATrustNodeProbe? bestProbe;
      for (final probe in probes) {
        if (!probe.reachable) continue;
        final score = probe.score(penalty);
        if (bestProbe == null || score < bestProbe.score(penalty)) {
          bestProbe = probe;
        }
      }
      if (bestProbe != null) {
        best[entry.key] = bestProbe.node;
      }
    }
    return best;
  }

  Future<ATrustNodeProbe> _probeNode(
    String node,
    ATrustNodeDialer dialer,
  ) async {
    final (host, port) = _splitNode(node);
    var successes = 0;
    var failures = 0;
    var total = Duration.zero;
    if (host == null || port == null) {
      return ATrustNodeProbe(
        node: node,
        successes: 0,
        failures: probeCount,
        totalLatency: Duration.zero,
      );
    }
    for (var attempt = 0; attempt < probeCount; attempt++) {
      if (attempt > 0) {
        await Future<void>.delayed(probeInterval);
      }
      final latency = await dialer(host, port, probeTimeout);
      if (latency == null) {
        failures++;
      } else {
        successes++;
        total += latency;
      }
    }
    return ATrustNodeProbe(
      node: node,
      successes: successes,
      failures: failures,
      totalLatency: total,
    );
  }

  (String?, int?) _splitNode(String node) {
    if (node.startsWith('[')) {
      final close = node.indexOf(']');
      if (close < 0) return (null, null);
      final host = node.substring(1, close);
      final rest = node.substring(close + 1);
      if (rest.isEmpty) return (host, 441);
      if (!rest.startsWith(':')) return (null, null);
      return (host, int.tryParse(rest.substring(1)));
    }
    final colon = node.lastIndexOf(':');
    if (colon < 0) return (node, 441);
    if (node.substring(0, colon).contains(':')) return (null, null);
    return (node.substring(0, colon), int.tryParse(node.substring(colon + 1)));
  }
}

/// Default dialer that performs a plain TCP connect and measures the latency.
Future<Duration?> atrustTcpProbeDialer(
  String host,
  int port,
  Duration timeout,
) async {
  final stopwatch = Stopwatch()..start();
  try {
    final socket = await Socket.connect(host, port, timeout: timeout);
    stopwatch.stop();
    socket.destroy();
    return stopwatch.elapsed;
  } on Object {
    return null;
  }
}
