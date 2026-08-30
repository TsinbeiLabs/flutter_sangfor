// Example for package:flutter_sangfor_easy_connect.
//
// Run with `dart run` after configuring a reachable EasyConnect
// deployment. The connector performs the XML login, conf parsing, minimal
// TLS data-channel bring-up, Query-IP, and RX/TX streams, then dials one
// TCP connection over the userspace TCP-over-L3 proxy.
//
// For a userspace SOCKS5 frontend instead of per-connection dials, see
// the root package's `SangforSocks5Server`.
// ignore_for_file: avoid_print
import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_sangfor_easy_connect/flutter_sangfor_easy_connect.dart';

Future<void> main() async {
  final connector = EasyConnectConnector(
    loginSession: EasyConnectLoginSession(),
    // The minimal TLS client fails closed: provide a validator that pins
    // or verifies the server certificate.
    certificateValidator: (certificateDer) => true,
  );

  final session = await connector.connect(
    SangforConnectOptions(
      server: Uri.parse('https://vpn.example.com'),
      username: 'user',
      password: 'password',
    ),
  );

  if (session.state != SangforConnectionState.connected) {
    print('Connect failed: ${session.state}');
    return;
  }
  print('Connected. Virtual IP: ${session.virtualAddress}');
  print('VPN DNS servers: ${session.dnsServers}');

  // Dial one TCP connection. Domains are resolved via the VPN DNS
  // servers over the tunnel.
  final stream = await connector.dialTcp('internal.example.com', 443);
  print('Dialed internal.example.com:443');

  await stream.close();
  await connector.disconnect();
}
