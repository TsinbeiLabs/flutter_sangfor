## 0.0.1

* Wire `getState` and `disconnect` across all declared platforms.
* Validate connection arguments in the Dart method-channel adapter.
* Return an explicit unsupported error until the protocol transport is ready.
* Add the platform-neutral `SangforAuthRequest` transport boundary.
* Add `flutter_sangfor_atrust` and `flutter_sangfor_easy_connect` package boundaries.
* Add aTrust manifest and authentication-method discovery over HTTPS.
* Add aTrust primary password exchange with server-provided RSA parameters.
* Add aTrust MFA-step normalization and L3VPN resource parsing.
* Add aTrust SMS verification and client-resource retrieval requests.
* Add aTrust Cookie/SID persistence, environment reporting, and online info.
* Add an end-to-end aTrust password and SMS login coordinator.
* Add explicit TOTP, RADIUS, and generic code challenge callbacks.
* Add access checks, enhanced-auth continuation, and current-device binding.
* Add credential-free session snapshots and WAN/LAN node-group parsing.
* Add a bounded incremental tunnel-frame boundary and node ordering.
* Add the aTrust L3 tunnel with keep-alives and dual packet-stream demux.
* Add the aTrust TCP tunnel channels with `dialTcp` for user-space sockets.
* Add the EasyConnect login, conf parsing, TLS 1.1/1.2, token, RX/TX streams,
  and heartbeat keep-alive.
* Add the userspace data plane: `SangforTcpStream`, `SangforPacketTunnel`,
  `SangforPacketDevice`, and the `SangforTunnelRouter` bidirectional pump
  with egress/ingress filters and cancellation-token support.
* Add `SangforSocks5Server` (RFC 1928 no-auth CONNECT) with pipelined-request
  buffering, serialized sends, and cancellation-token support.
* Add EasyConnect TCP-over-L3 synthesis: IPv4/TCP/UDP packet building,
  DNS query/parse over the tunnel, a retransmitting client TCP state machine
  with zero-window probing, and a `dialTcp` connector API.
* Add platform TUN adapters: `WintunDevice` (Windows), `TunDevice` (Linux),
  `AndroidVpnDevice` (VpnService), `UtunDevice` (macOS), and `IosVpnDevice`
  (NetworkExtension packet tunnel with loopback IPC).
