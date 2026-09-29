import 'dart:convert';
import 'dart:typed_data';

import 'resource.dart';

/// The hand-off payload for an out-of-process data plane.
///
/// The iOS packet tunnel extension cannot log in: it has no UI for secondary
/// challenges and no access to the credential store. The Runner therefore
/// resolves everything the tunnel needs — node choice, virtual IP, resource
/// routes, signing key — and writes this plan into the App Group container
/// before starting the tunnel. From then on the extension carries traffic on
/// its own and the app may be suspended or killed.
///
/// The JSON keys are a contract with `ATrustSessionPlan` on the Swift side;
/// `test/native_fixtures_test.dart` pins a golden document that the native
/// decoder must accept.
class ATrustSessionPlan {
  ATrustSessionPlan({
    required this.sid,
    required this.deviceId,
    required this.connectionId,
    required this.username,
    required this.signKey,
    required this.nodes,
    required this.majorNodeGroup,
    required this.routes,
    this.lang = 'en-US',
    this.processName = 'flutter_sangfor',
    this.processPath = '/usr/bin/flutter_sangfor',
    this.processPlatform = 'iOS',
    this.dnsServers = const <String>[],
    this.virtualAddress,
    this.certificateDigests = const <String>[],
    this.acceptAnyCertificate = true,
    this.dialHosts = const <String, String>{},
    this.heartbeatSeconds = 5,
    this.mtu = 1400,
    this.schemaVersion = currentSchemaVersion,
  });

  /// Bumped when a field is added that an older extension could not ignore.
  static const int currentSchemaVersion = 1;

  final int schemaVersion;
  final String sid;
  final String deviceId;
  final String connectionId;
  final String username;

  /// The 32-byte request signing key. Traveling through the App Group
  /// container keeps it inside the two processes that declare the group.
  final Uint8List signKey;
  final String lang;
  final String processName;
  final String processPath;
  final String processPlatform;

  /// Node endpoints per group, best candidate first (`host:port`).
  final Map<String, List<String>> nodes;
  final String majorNodeGroup;
  final List<ATrustRoute> routes;
  final List<String> dnsServers;
  final String? virtualAddress;

  /// Hex SHA-256 digests of the certificates the gateway presented during
  /// login (anti-MITM pins). Empty means "no pins available".
  final List<String> certificateDigests;
  final bool acceptAnyCertificate;

  /// Resolved IPv4 address to the host name the gateway published, so the
  /// extension can dial a domain-published resource by name.
  final Map<String, String> dialHosts;
  final double heartbeatSeconds;
  final int mtu;

  /// The wire representation; keys match the Swift `Codable` model.
  Map<String, Object?> toJson() => <String, Object?>{
        'schemaVersion': schemaVersion,
        'sid': sid,
        'deviceId': deviceId,
        'connectionId': connectionId,
        'username': username,
        'signKeyBase64': base64Encode(signKey),
        'lang': lang,
        'processName': processName,
        'processPath': processPath,
        'processPlatform': processPlatform,
        'nodes': nodes,
        'majorNodeGroup': majorNodeGroup,
        'routes': <Map<String, Object?>>[
          for (final route in routes)
            <String, Object?>{
              'host': route.host,
              'protocol': route.protocol,
              'portMin': route.portMin,
              'portMax': route.portMax,
              'appId': route.appId,
              'nodeGroupId': route.nodeGroupId,
              'addrPretend': route.addrPretend,
              'enableTcpPrefL3': route.enableTcpPrefL3,
            },
        ],
        'dnsServers': dnsServers,
        'virtualAddress': virtualAddress,
        'certificateDigests': certificateDigests,
        'acceptAnyCertificate': acceptAnyCertificate,
        'dialHosts': dialHosts,
        'heartbeatSeconds': heartbeatSeconds,
        'mtu': mtu,
      };

  /// The document to store in the App Group container.
  String encode() => jsonEncode(toJson());

  /// Rebuilds a plan from [encode]'s output; used by tests and by any caller
  /// that has to inspect what it handed over.
  static ATrustSessionPlan decode(String document) {
    final map = jsonDecode(document) as Map<String, Object?>;
    final routes = <ATrustRoute>[
      for (final entry
          in (map['routes'] as List<Object?>? ?? const <Object?>[]))
        if (entry is Map)
          ATrustRoute(
            host: '${entry['host'] ?? ''}',
            protocol: '${entry['protocol'] ?? 'all'}',
            portMin: (entry['portMin'] as num?)?.toInt() ?? 0,
            portMax: (entry['portMax'] as num?)?.toInt() ?? 65535,
            appId: '${entry['appId'] ?? ''}',
            nodeGroupId: '${entry['nodeGroupId'] ?? ''}',
            addrPretend: entry['addrPretend'] as bool? ?? false,
            enableTcpPrefL3: entry['enableTcpPrefL3'] as bool? ?? false,
          ),
    ];
    return ATrustSessionPlan(
      schemaVersion: (map['schemaVersion'] as num?)?.toInt() ?? 1,
      sid: '${map['sid'] ?? ''}',
      deviceId: '${map['deviceId'] ?? ''}',
      connectionId: '${map['connectionId'] ?? ''}',
      username: '${map['username'] ?? ''}',
      signKey: base64Decode('${map['signKeyBase64'] ?? ''}'),
      lang: '${map['lang'] ?? 'en-US'}',
      processName: '${map['processName'] ?? ''}',
      processPath: '${map['processPath'] ?? ''}',
      processPlatform: '${map['processPlatform'] ?? 'iOS'}',
      nodes: <String, List<String>>{
        for (final entry in (map['nodes'] as Map<String, Object?>? ??
                const <String, Object?>{})
            .entries)
          entry.key: <String>[
            for (final value
                in entry.value as List<Object?>? ?? const <Object?>[])
              '$value',
          ],
      },
      majorNodeGroup: '${map['majorNodeGroup'] ?? ''}',
      routes: routes,
      dnsServers: <String>[
        for (final value
            in map['dnsServers'] as List<Object?>? ?? const <Object?>[])
          '$value',
      ],
      virtualAddress: map['virtualAddress'] as String?,
      certificateDigests: <String>[
        for (final value
            in map['certificateDigests'] as List<Object?>? ?? const <Object?>[])
          '$value',
      ],
      acceptAnyCertificate: map['acceptAnyCertificate'] as bool? ?? true,
      dialHosts: <String, String>{
        for (final entry in (map['dialHosts'] as Map<String, Object?>? ??
                const <String, Object?>{})
            .entries)
          entry.key: '${entry.value}',
      },
      heartbeatSeconds: (map['heartbeatSeconds'] as num?)?.toDouble() ?? 5,
      mtu: (map['mtu'] as num?)?.toInt() ?? 1400,
    );
  }
}

/// The resolved node topology and virtual IP, without a live tunnel.
///
/// A Runner that hands the data plane to an extension needs these but must not
/// keep its own L3 connection open: two connections with the same session make
/// the gateway drop one.
class ATrustTunnelPlan {
  const ATrustTunnelPlan({
    required this.bestNodes,
    required this.virtualAddress,
  });

  final Map<String, String> bestNodes;
  final String? virtualAddress;
}
