// Example for package:flutter_sangfor_atrust.
//
// Run with `dart run` after configuring a reachable aTrust deployment.
// The connector performs the manifest/password login, node selection,
// Query-IP, and the L3 tunnel bring-up, then dials one TCP connection
// through the SOCKS5-like aTrust TCP tunnel.
//
// For a userspace SOCKS5 frontend instead of per-connection dials, see
// the root package's `SangforSocks5Server`.
// ignore_for_file: avoid_print
import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_sangfor_atrust/flutter_sangfor_atrust.dart';

Future<void> main() async {
  final connector = ATrustConnector(
    loginSession: ATrustLoginSession(),
    authMethod: ATrustAuthMethod.password,
  );

  final session = await connector.connect(
    SangforConnectOptions(
      server: Uri.parse('https://vpn.example.com'),
      username: 'user',
      password: 'password',
      loginDomain: 'default',
      deviceId: 'device-id',
    ),
  );

  if (session.state != SangforConnectionState.connected) {
    print('Connect failed: ${session.state}');
    return;
  }
  print('Connected. Virtual IP: ${session.virtualAddress}');
  print('VPN DNS servers: ${session.dnsServers}');

  // Dial one TCP connection through the aTrust TCP tunnel. The gateway
  // resolves domains, so pass the hostname directly.
  final stream = await connector.dialTcp('internal.example.com', 443);
  print('Dialed internal.example.com:443');

  await stream.close();
  await connector.disconnect();
}
