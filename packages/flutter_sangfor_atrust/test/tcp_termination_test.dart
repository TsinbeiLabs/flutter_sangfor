import 'dart:typed_data';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_sangfor_atrust/flutter_sangfor_atrust.dart';
import 'package:test/test.dart';

ATrustResource _resource(List<ATrustRoute> routes) => ATrustResource(
      routes: routes,
      dnsServers: const <String>['202.114.64.7'],
      majorNodeGroup: 'group-1',
      nodeGroups: const <String, ATrustNodeGroup>{
        'group-1': ATrustNodeGroup(wan: <String>['203.0.113.9:441']),
      },
    );

ATrustRoute _route(
  String host, {
  String protocol = 'tcp',
  int portMin = 0,
  int portMax = 65535,
  bool enableTcpPrefL3 = false,
}) =>
    ATrustRoute(
      host: host,
      protocol: protocol,
      portMin: portMin,
      portMax: portMax,
      appId: 'app-$host',
      nodeGroupId: 'group-1',
      addrPretend: false,
      enableTcpPrefL3: enableTcpPrefL3,
    );

void main() {
  group('ATrustTcpTermination.shouldTerminate', () {
    test('leaves L3-forwardable TCP flows alone', () {
      final termination = ATrustTcpTermination(
        resource: _resource(<ATrustRoute>[
          _route('10.1.0.0/16', enableTcpPrefL3: true),
        ]),
      );
      expect(termination.shouldTerminate('10.1.2.3', 443), isFalse);
    });

    test('claims an IP-published TCP-tunnel resource', () {
      final termination = ATrustTcpTermination(
        resource: _resource(<ATrustRoute>[_route('10.9.0.0/16')]),
      );
      expect(termination.shouldTerminate('10.9.1.2', 443), isTrue);
      expect(termination.shouldTerminate('10.9.1.2', 80), isTrue);
      expect(termination.shouldTerminate('10.8.1.2', 443), isFalse);
    });

    test('claims a domain-published resource through its alias', () {
      final routes = <ATrustRoute>[
        _route('portal.whu.edu.cn', portMin: 443, portMax: 443)
      ];
      final withoutAlias = ATrustTcpTermination(resource: _resource(routes));
      // A raw packet only carries the resolved address, which cannot match a
      // domain-published resource.
      expect(withoutAlias.shouldTerminate('202.114.64.7', 443), isFalse);

      final withAlias = ATrustTcpTermination(
        resource: _resource(routes),
        dialHosts: const <String, String>{'202.114.64.7': 'portal.whu.edu.cn'},
      );
      expect(withAlias.shouldTerminate('202.114.64.7', 443), isTrue);
      expect(withAlias.dialHost('202.114.64.7', 443), 'portal.whu.edu.cn');
      // The port range still applies.
      expect(withAlias.shouldTerminate('202.114.64.7', 80), isFalse);
    });

    test('ignores destinations no resource covers', () {
      final termination = ATrustTcpTermination(
        resource: _resource(<ATrustRoute>[_route('10.9.0.0/16')]),
      );
      expect(termination.shouldTerminate('8.8.8.8', 443), isFalse);
    });

    test('an L3-preferred resource is still relayed when L3 refuses it', () {
      // The route is L3-preferred, but only for port 8443; a 443 flow is
      // refused by the L3 matcher and must fall back to the TCP tunnel.
      final termination = ATrustTcpTermination(
        resource: _resource(<ATrustRoute>[
          _route('10.2.0.0/16',
              portMin: 8443, portMax: 8443, enableTcpPrefL3: true),
          _route('10.2.0.0/16'),
        ]),
      );
      expect(termination.shouldTerminate('10.2.3.4', 443), isTrue);
      expect(termination.shouldTerminate('10.2.3.4', 8443), isFalse);
    });
  });

  test('reverseHosts maps every resolved address back to its name', () {
    final hosts = ATrustTcpTermination.reverseHosts(<String, Iterable<String>>{
      'portal.whu.edu.cn': <String>['202.114.64.7', '202.114.64.8'],
      'ids.whu.edu.cn': <String>['202.114.64.7'],
    });
    expect(hosts['202.114.64.8'], 'portal.whu.edu.cn');
    // The first name wins, so a shared address stays deterministic.
    expect(hosts['202.114.64.7'], 'portal.whu.edu.cn');
  });

  group('ATrustPacketTunnel', () {
    test('forwards the packet-tunnel contract to the aTrust tunnel', () async {
      final tunnel = ATrustTunnel(
        resource: _resource(<ATrustRoute>[]),
        info: const ATrustL3ClientInfo(
          sid: 'sid',
          deviceId: 'device',
          connectionId: 'connection',
          username: 'alice',
        ),
        signKey: Uint8List(32),
      );
      addTearDown(tunnel.close);
      final adapter = ATrustPacketTunnel(tunnel);
      expect(adapter.isClosed, isFalse);
      // No routes: nothing is forwardable and no node is dialed.
      expect(await adapter.sendPacket(Uint8List(40)), isFalse);
      await adapter.close();
      expect(adapter.isClosed, isTrue);
    });
  });

  test('wrap exposes a packet tunnel', () {
    final tunnel = ATrustTunnel(
      resource: _resource(<ATrustRoute>[_route('10.9.0.0/16')]),
      info: const ATrustL3ClientInfo(
        sid: 'sid',
        deviceId: 'device',
        connectionId: 'connection',
        username: 'alice',
      ),
      signKey: Uint8List(32),
    );
    addTearDown(tunnel.close);
    final termination = ATrustTcpTermination(
      resource: _resource(<ATrustRoute>[_route('10.9.0.0/16')]),
    );
    expect(termination.wrap(tunnel), isA<SangforPacketTunnel>());
    expect(termination.terminator(tunnel), isA<SangforTcpTerminator>());
  });
}
