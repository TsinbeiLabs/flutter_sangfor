## 0.0.7

* Add the iOS extension-native data plane: `IosVpnRuntimeMode.extensionNative`,
  `IosVpnDevice.startNative`, and `writeSessionPlan`/`clearSessionPlan` hand a
  session plan to the packet tunnel extension through the App Group, and the
  extension then runs the tunnel itself — L3 handshake, per-flow auth,
  heartbeats, reconnect, TCP-tunnel dials, and local TCP termination. The VPN
  keeps carrying traffic when iOS suspends the app, which the loopback bridge
  could never do. The bridge stays the default.
* The native core is pure Swift and verified off-device: SHA-256/HMAC, a JSON
  writer that reproduces Dart's `jsonEncode` byte for byte, the L3 and TCP
  tunnel frame codecs, the IPv4/TCP builder with full checksums, route
  matching, the flow tracker, the userspace TCP terminator, and the L3
  connection driver. `tool/run_swift_tests.sh` (or `.ps1`) checks all of it
  against golden fixtures emitted by the Dart reference implementation.
* Fix a TCP terminator stall: the ACK comparison was inverted, so a cumulative
  ACK covering more than one segment never advanced the send window and the
  flow hung after its first window of data.
* Pin node certificates with the gateway's salted digest
  (`SangforCertificateDigest`) instead of a plain SHA-256 of the DER.
* Advertise the system proxy only in loopback-bridge mode; the native plane
  terminates those flows itself and must not point apps at a proxy that only
  exists while the Runner is awake.
## 0.0.7

* Add the iOS extension-native data plane: the packet tunnel extension can run
  the tunnel itself (`IosVpnRuntimeMode.extensionNative`,
  `IosVpnDevice.startNative`) from a session plan handed over through the App
  Group (`IosVpnDevice.writeSessionPlan` / `clearSessionPlan`), so the VPN
  survives the Runner being suspended. The loopback bridge stays the default.
* Add the pure-Swift core that plane runs on: SHA-256/HMAC, a canonical JSON
  writer that matches Dart's `jsonEncode` byte for byte, the L3 and TCP-tunnel
  frame codecs, the IPv4/TCP packet builder with full checksums, route
  matching, the userspace TCP terminator, and the L3 connection driver with
  per-flow auth, heartbeats, and reconnect. `tool/run_swift_tests.sh` compiles
  and checks all of it against golden fixtures emitted by the Dart reference
  implementation, on Linux, Windows, and macOS.
* Fix a TCP terminator stall: the acknowledgement comparison was inverted, so a
  cumulative ACK covering more than one segment never advanced the send window
  and the connection hung after its first window of data.
* Pin node certificates with the gateway's salted digest
  (`SangforCertificateDigest`) rather than a plain SHA-256 of the DER.
## 0.0.6

* Add the userspace TCP terminator (`SangforTcpTerminator`,
  `SangforTerminatingTunnel`): a packet device can now serve TCP flows the
  tunnel refuses to forward as raw IP by completing the handshake locally and
  relaying bytes through a `SangforTcpDialer`. Ships an IPv4/TCP codec with
  full checksums, MSS clamping, retransmission with exponential backoff, peer
  window flow control, and upstream backpressure.
* Add `SangforSystemProxy`, which publishes a loopback HTTP proxy as the
  OS-wide proxy on Windows (WinINET keys under `HKCU`, no elevation needed) and
  macOS (`networksetup`, administrator rights), capturing and restoring
  whatever the user had configured before.
* Advertise a system proxy from the iOS packet tunnel:
  `IosVpnDevice.start(proxyHost:, proxyPort:)` now reaches `NEProxySettings`
  with an all-hosts match domain, the counterpart of Android's
  `VpnService.Builder.setHttpProxy`.
## 0.0.5

* Fix the ohos ArkTS build: NetAddress.family is a plain number in the
  OpenHarmony SDK (no connection.NetFamily enum), RouteInfo.gateway is
  mandatory, and Index.ets imports must precede exports.

## 0.0.4

* Add the HarmonyOS VpnExtensionAbility adapter (ohos module, SCM_RIGHTS
  TUN fd hand-off) and the OhosVpnDevice Dart adapter.
## 0.0.3

* Fix an Android ANR: establish the tunnel from a background executor instead
  of blocking the platform thread while the service comes up.
* Fall back to the underlying network's DNS resolvers when the server
  publishes none, and keep those resolvers outside the TUN routes.
* Advertise the caller's loopback HTTP proxy as the VPN system proxy on
  Android 13+ so domain-published resources work in system mode.
* Add a persistent notification with live speed, uptime, and a disconnect
  action; dismissed notifications recover via the delete intent.
* Add `AndroidVpnDevice.updateStats` and `disconnectRequests` plumbing.
* BREAKING CHANGE: rename the Android namespace from
  `com.tsinbeilabs.flutter_sangfor` to `com.tsinbei.flutter_sangfor`.
## 0.0.2

* Add library-level dartdoc for the public API surface.
* Update the package description to cover aTrust and Easy Connect.

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
