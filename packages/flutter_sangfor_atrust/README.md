# flutter_sangfor_atrust

aTrust-specific connector and protocol implementation for the
`flutter_sangfor` package family. Implements the full aTrust protocol core
in pure Dart.

## Features

- HTTPS manifest and authentication-method discovery (`/public/manifest`,
  `/passport/v1/public/authConfig`).
- Primary password exchange with server-provided RSA parameters.
- SMS, TOTP, RADIUS, and generic code-challenge support via caller-provided
  callbacks.
- Cookie/SID persistence, environment reporting, and online-user lookup.
- Access checks, enhanced-auth continuation, and device binding.
- Credential-free session snapshots (`ATrustSessionSnapshot`).
- WAN/LAN node-group parsing with normalized tunnel endpoints.
- Best-node selection (3x TCP latency probe, WAN-then-LAN fallback).
- Query-IP acquisition of the client virtual IP.
- L3 tunnel handshake (`0x05 0xD0` / `0x53` envelope), VIP parsing,
  per-flow authenticated data frames with `xRequestSig` HMAC-SHA256 signing,
  conntrack TCP state machine with protocol-specific TTLs, heartbeat miss
  detection, and VIP updates.
- SOCKS5-like TCP tunnel with `dialTcp` (raw + reuse modes, EOF signaling).
- Anti-MITM challenge verification, response signature verification, and
  certificate identity pinning via `SecurityContext`.
- `dryRun` connections that validate options without network I/O.

## Status

Protocol cores are complete and covered by unit tests, but have not been
exercised against authorized production deployments yet. See
[protocol evidence](../../docs/protocol-evidence.md) for details.

## Usage

```dart
final connector = ATrustConnector(
  loginSession: ATrustLoginSession(client: apiClient),
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

if (session.state == SangforConnectionState.connected) {
  print('Virtual IP: ${session.virtualAddress}');
  // Dial TCP connections through the aTrust TCP tunnel.
  final stream = await connector.dialTcp('internal.example.com', 443);
}
```

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgments

The aTrust protocol implementation is an independent clean-room
reimplementation of publicly observed wire behavior; no source code is
copied from [Mythologyli/zju-connect](https://github.com/Mythologyli/zju-connect)
(AGPL-3.0), which was used as a behavior reference for the L3 tunnel,
per-flow auth, conntrack, and TCP tunnel.
