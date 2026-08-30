/// A routed application resource advertised by aTrust.
class ATrustRoute {
  const ATrustRoute({
    required this.host,
    required this.protocol,
    required this.portMin,
    required this.portMax,
    required this.appId,
    required this.nodeGroupId,
    required this.addrPretend,
    this.enableTcpPrefL3 = false,
  });

  final String host;
  final String protocol;
  final int portMin;
  final int portMax;
  final String appId;
  final String nodeGroupId;
  final bool addrPretend;
  final bool enableTcpPrefL3;
}

class ATrustResource {
  const ATrustResource({
    required this.routes,
    required this.dnsServers,
    required this.majorNodeGroup,
    this.nodeGroups = const <String, ATrustNodeGroup>{},
  });

  final List<ATrustRoute> routes;
  final List<String> dnsServers;
  final String majorNodeGroup;
  final Map<String, ATrustNodeGroup> nodeGroups;
}

class ATrustNodeGroup {
  const ATrustNodeGroup({
    this.wan = const <String>[],
    this.lan = const <String>[],
  });

  final List<String> wan;
  final List<String> lan;
}

/// Parses only the documented L3VPN resource shape; unsupported entries are ignored.
class ATrustResourceParser {
  const ATrustResourceParser();

  ATrustResource parse(
    Map<String, Object?> root, {
    String? serverHost,
  }) {
    final data = _map(root['data']);
    final appList = _map(_map(data['appList'])['data']);
    final routes = <ATrustRoute>[];
    final appInfo = _list(appList['appInfo']);
    for (final info in appInfo.whereType<Map>()) {
      for (final app in _list(_map(info)['apps']).whereType<Map>()) {
        final appMap = _map(app);
        if (appMap['accessModel'] != 'L3VPN') continue;
        final appId = _string(appMap['id']) ?? '';
        final nodeGroupId = _string(appMap['nodeGroupId']) ?? '';
        final pretend = appMap['addrPretend'] is bool
            ? appMap['addrPretend'] as bool
            : true;
        final tcpPrefL3 = appMap['enableTCPPrefL3'] is bool
            ? appMap['enableTCPPrefL3'] as bool
            : false;
        for (final address in _list(appMap['addressList']).whereType<Map>()) {
          final addressMap = _map(address);
          final protocol =
              (_string(addressMap['protocol']) ?? '').toLowerCase();
          if (!{'tcp', 'udp', 'all'}.contains(protocol)) continue;
          final ports = _ports(_string(addressMap['port']) ?? '');
          final host = _string(addressMap['host']) ?? '';
          if (ports == null || host.isEmpty) continue;
          routes.add(ATrustRoute(
            host: host,
            protocol: protocol,
            portMin: ports.$1,
            portMax: ports.$2,
            appId: appId,
            nodeGroupId: nodeGroupId,
            addrPretend: pretend,
            enableTcpPrefL3: tcpPrefL3,
          ));
        }
      }
    }
    final policy = _map(_map(data['sdpPolicy'])['data']);
    final options = _map(_map(policy['clientOption'])['dnsOption']);
    final fallback = _map(_map(policy['clientOption'])['dnsOptionV2']);
    final dns = <String>[
      _string(options['firstDNS']) ?? _string(fallback['firstDNS']) ?? '',
      _string(options['secondDNS']) ?? _string(fallback['secondDNS']) ?? '',
    ]..removeWhere((value) => value.isEmpty);
    final config = _map(_map(appList['config'])['nodeGroupConf']);
    final major = _string(_map(config['majorNodeGroup'])['id']) ?? '';
    final nodeGroups = <String, ATrustNodeGroup>{};
    for (final item in _list(config['nodeGroupList']).whereType<Map>()) {
      final group = _map(item);
      final id = _string(group['id']) ?? '';
      if (id.isEmpty) continue;
      final wan = <String>[];
      final lan = <String>[];
      for (final entry in _list(group['addressInfo']).whereType<Map>()) {
        final address = _nodeAddress(
          _string(_map(entry)['address']),
          serverHost: serverHost,
        );
        final type = (_string(_map(entry)['type']) ?? '').toLowerCase();
        if (address == null) continue;
        if (type == 'wan') wan.add(address);
        if (type == 'lan') lan.add(address);
      }
      nodeGroups[id] = ATrustNodeGroup(wan: wan, lan: lan);
    }
    return ATrustResource(
      routes: routes,
      dnsServers: dns,
      majorNodeGroup: major,
      nodeGroups: nodeGroups,
    );
  }
}

String? _nodeAddress(String? value, {String? serverHost}) {
  if (value == '{{sdpcHost}}') value = serverHost;
  if (value == null || value.isEmpty) return null;
  if (value.startsWith('[')) return value.contains(']:') ? value : '$value:441';
  final colonCount = ':'.allMatches(value).length;
  if (colonCount == 0) return '$value:441';
  if (colonCount == 1) return value;
  return '[$value]:441';
}

int? _ipv4ToLong(String address) {
  final parts = address.split('.');
  if (parts.length != 4) return null;
  var value = 0;
  for (final part in parts) {
    final octet = int.tryParse(part);
    if (octet == null || octet < 0 || octet > 255) return null;
    value = (value << 8) | octet;
  }
  return value;
}

bool _isIPv4(String value) => _ipv4ToLong(value) != null;

/// True when [host] (a single address, CIDR, or `min~max` range) covers [destIP].
bool atrustRouteHostCovers(String host, String destIP) {
  if (host.contains('/')) {
    final cidrParts = host.split('/');
    final base = _ipv4ToLong(cidrParts.first);
    final prefix = int.tryParse(cidrParts.length == 2 ? cidrParts.last : '');
    final dest = _ipv4ToLong(destIP);
    if (base == null || prefix == null || dest == null) return false;
    if (prefix < 0 || prefix > 32) return false;
    if (prefix == 0) return true;
    final mask = prefix == 32
        ? 0xffffffff
        : (0xffffffff << (32 - prefix)) & 0xffffffff;
    return (base & mask) == (dest & mask);
  }
  if (host.contains('~')) {
    final bounds = host.split('~');
    if (bounds.length != 2) return false;
    final low = _ipv4ToLong(bounds.first.trim());
    final high = _ipv4ToLong(bounds.last.trim());
    final dest = _ipv4ToLong(destIP);
    if (low == null || high == null || dest == null) return false;
    return dest >= low && dest <= high;
  }
  if (_isIPv4(host)) return host == destIP;
  return false;
}

/// True when [host] (a literal or wildcard domain) matches [destHost].
bool atrustRouteDomainCovers(String host, String destHost) {
  var pattern = host.trim();
  if (pattern.startsWith('*.')) pattern = pattern.substring(1);
  if (pattern.contains('*')) return false;
  if (pattern.isEmpty) return false;
  if (pattern.startsWith('.')) return destHost.endsWith(pattern);
  return destHost == pattern;
}

/// Finds the route for an L3 destination. TCP traffic only routes through the
/// L3 tunnel when the application prefers it, mirroring the upstream behavior.
ATrustRoute? matchL3Route(
  List<ATrustRoute> routes,
  String destIP,
  String protocol,
  int port,
) {
  for (final route in routes) {
    if (route.protocol != 'all' && route.protocol != protocol) continue;
    if (port < route.portMin || port > route.portMax) continue;
    if (protocol == 'tcp' && !route.enableTcpPrefL3) continue;
    if (atrustRouteHostCovers(route.host, destIP)) return route;
  }
  return null;
}

/// Finds the route for a TCP-tunnel destination, preferring apps that do NOT
/// prefer L3, mirroring the upstream MatchLastWhere behavior.
ATrustRoute? matchTcpRoute(
  List<ATrustRoute> routes,
  String destHost,
  int port,
) {
  if (_isIPv4(destHost)) {
    for (final route in routes) {
      if (route.protocol != 'all' && route.protocol != 'tcp') continue;
      if (port < route.portMin || port > route.portMax) continue;
      if (route.enableTcpPrefL3) continue;
      if (atrustRouteHostCovers(route.host, destHost)) return route;
    }
    return null;
  }
  for (final route in routes) {
    if (route.protocol != 'all' && route.protocol != 'tcp') continue;
    if (port < route.portMin || port > route.portMax) continue;
    if (route.enableTcpPrefL3) continue;
    if (atrustRouteDomainCovers(route.host, destHost)) return route;
  }
  return null;
}

Map<String, Object?> _map(Object? value) =>
    value is Map ? Map<String, Object?>.from(value) : <String, Object?>{};

List<Object?> _list(Object? value) => value is List ? value : const <Object?>[];

String? _string(Object? value) => value is String ? value : null;

(int, int)? _ports(String value) {
  final parts = value.split('-');
  if (parts.length > 2) return null;
  final first = int.tryParse(parts.first);
  final last = parts.length == 1 ? first : int.tryParse(parts.last);
  if (first == null ||
      last == null ||
      first < 0 ||
      last < first ||
      last > 65535) {
    return null;
  }
  return (first, last);
}
