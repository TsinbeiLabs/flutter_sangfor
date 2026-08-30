# flutter_sangfor_easy_connect

Easy Connect-specific connector for the `flutter_sangfor` package family.
Implements the full EasyConnect protocol core in pure Dart.

## Features

- XML control plane: `login_auth.csp`, `login_psw.csp` (RSA password
  encryption), `login_sms.csp`, `login_sms1.csp`, `login_token.csp`,
  `conf.csp`, and `rclist.csp` (DNS servers, backup DNS, multi-line server
  lists, routed resources with host/port ranges).
- Login state carried by a `TWFID` cookie with SMS and TOTP continuation.
- Minimal TLS 1.1/1.2 client (`EasyConnectTlsClient`, RFC 4346/5246) for
  the L3IP data channels: RSA key exchange with RC4-SHA and
  AES128-CBC-SHA record protection, both PRFs, per-record explicit CBC
  IVs, and Finished verification. Fails closed: a certificate validator is
  required unless `allowUnverifiedCertificates` is explicitly enabled.
- 48-byte tunnel token derivation from the TLS session id and TWFID.
- 64-byte Query-IP / TX / RX / command-heartbeat handshake messages,
  Query-IP reply parsing, native `AABB` control-frame parsing.
- 76-byte ICMP TX heartbeat with verified IP/ICMP checksums.
- `update_session.csp` HTTP keepalive.
- TCP-over-L3 synthesis (`EasyConnectTcpProxy`): an RFC 793 client-role
  stack with retransmission, zero-window probing, and out-of-order
  reassembly, plus UDP flows and an RFC 1035 DNS resolver over the
  tunnel.
- `dialTcp(host, port)` for per-connection TCP tunneling (domains are
  resolved via the VPN DNS servers).
- `dryRun` connections that validate options without network I/O.

## Status

Protocol cores are complete and covered by unit tests, but have not been
exercised against authorized production deployments yet. See
[protocol evidence](../../docs/protocol-evidence.md) for details.

## Usage

```dart
final connector = EasyConnectConnector(
  loginSession: EasyConnectLoginSession(client: apiClient),
  certificateValidator: (certificateDer) {
    // Verify the server certificate against a pinned digest or platform
    // trust store.
    return true;
  },
);

final session = await connector.connect(
  SangforConnectOptions(
    server: Uri.parse('https://vpn.example.com'),
    username: 'user',
    password: 'password',
  ),
);

if (session.state == SangforConnectionState.connected) {
  print('Virtual IP: ${session.virtualAddress}');
  // Dial TCP connections; domains resolve via the VPN DNS servers.
  final stream = await connector.dialTcp('internal.example.com', 443);
}
```

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgments

The EasyConnect protocol implementation is an independent clean-room
reimplementation of publicly observed wire behavior; no source code is copied
from the following projects, which were used as behavior references:

- [GayStudio/EasierConnect](https://github.com/GayStudio/EasierConnect)
  — EasyConnect XML control plane reference.
- [lyc8503/NJUConnect](https://github.com/lyc8503/NJUConnect)
  — EasyConnect control plane reference.
- [Yan233th/SHIEP-Pipeline](https://github.com/Yan233th/SHIEP-Pipeline) (AGPL-3.0, Rust)
  — EasyConnect token, Query-IP, RX/TX stream, heartbeat.
