## Unreleased

* iOS packet tunnel extension: an in-extension HTTP proxy, published to the
  system with `NEProxySettings`, so apps that honor the system proxy reach the
  gateway's resources by host name -- wildcard and domain-published ones the
  routing table cannot express -- while the tunnel keeps running after iOS
  suspends the app. It is opt-in: the session plan's new `domainRouting` key
  carries the route policy (`followServer` / `custom`), the custom entries and
  the hosts that must stay direct; a plan without the key gets no proxy.
* `SangforRouteMatcher` ports the app's `VpnRouteMatcher` (the Android loopback
  proxy's rule) to Swift, driven by the same `route_matcher_cases.json` as the
  Dart tests. `SangforProxyPolicy` and `SangforHttpProxyParser` are pure and
  covered by `tool/run_swift_tests.sh`.
* The proxy dials the TCP tunnel without claiming a resolved address, as the
  Dart in-app proxy does.
* A start the system initiates (Settings, Control Center, iOS restarting the
  provider after a network change) used to fall back to the loopback bridge
  with a placeholder address and no routes: a tunnel that reported connected and
  carried nothing. The extension now rebuilds its settings from the session
  plan's new `tunnelSettings` key, or fails with error 200 and a reason.
* The plan's `tunnelSettings.excludedRoutes` are applied as
  `NEIPv4Settings.excludedRoutes`, together with the gateway nodes' addresses,
  so the destinations the app lists (the VPN gateway) and the tunnel's own
  transport can never enter the tunnel.
* When the gateway assigns an interface address other than the one the tunnel
  was configured with, the extension re-applies its settings with the assigned
  one instead of leaving replies addressed to a stranger.
* A TCP tunnel dial to a host known by name no longer carries a `destIP`. The
  terminator sent the *host name* as `destIP` when the resource was published
  without `addrPretend`, and the gateway closed the connection during the
  handshake; that is what broke `datarepo.whu.edu.cn`-style hosts (100 of the 772
  routes on the WHU gateway). Probed against the live gateway: a request naming
  the host with no `destIP` is accepted for resources with and without
  `addrPretend`, while any `destIP` is refused (`tcp tunnel connection not
  allowed` for the address the name resolves to). A flow to a bare address, with
  no name behind it, still carries that address when the resource is not
  `addrPretend`.
* Flows to an address the plan pre-resolved from a published host name are now
  decided by the host name they turn out to want, not by the address alone.
  Several names often sit behind one address (a shared front end) and only some
  are published -- `user-serv.whu.edu.cn` shares an address with
  `ehall.whu.edu.cn` -- so the address could only say "ehall" and the flow was
  dialed through the tunnel as `ehall`, where nothing serves the other name. The
  terminator now holds the dial until the client's first bytes arrive and reads
  the host from them (`SangforFlowSniffer`: the SNI of a TLS ClientHello, the
  `Host` of an HTTP request). A name a resource covers on that port goes through
  the tunnel, dialed by that name; any other is carried out directly
  (`SangforDirectStream`, `Configuration.directDialer`), as it would have gone
  without the tunnel. When nothing names a host (the server speaks first, ECH, no
  SNI) a short wait ends and the address's own name decides, as before. Nothing
  unpublished is carried by the tunnel, and an address no name resolved to is
  still dropped. The plan's optional `dialHostAliases` lists every name behind an
  address so a flow is matched to the name that covers its port.
* Switching the VPN off in Settings and on again works. A stop the user made
  wiped the session plan, so the start that followed (which arrives with no
  options and can only run from the plan) found nothing and failed with "no
  tunnel settings in the session plan". A plan may now carry `keepOnUserStop`:
  the extension then keeps it across a user stop. The app still clears it itself
  when it disconnects, and `providerDisabled` / `appUpdate` still wipe it.
* A session the gateway has dropped is now reported as one. A refused L3
  handshake (`status` or `code` not zero) was an ordinary protocol error, so an
  extension whose session had expired reconnected every five seconds forever
  while the system showed it as connected. It is now `tunnelAuthFailed`: a start
  that hits it fails with "The VPN session is no longer valid" (error 201); on
  a reconnect the first refusal is retried (a node can be busy) and the second in
  a row stops the tunnel, wipes the plan and cancels with the same error. An
  error on a connection that never finished its handshake is now reported once,
  through its start completion, instead of also through the connection's error
  callback.
* Connections carried outside the tunnel refuse the tunnel's own interface (a
  utun is an `.other` interface), so they cannot be routed back into it. Each
  sniffed flow's decision and the first direct connections (with the interface
  they used) are logged, and `direct` joins the data plane statistics.
* The proxy's direct connections now go through `SangforDirectStream` like the
  terminator's, instead of a second hand-written `NWConnection` relay, so there
  is one direct path to reason about. A direct dial that is refused or has no
  route fails at once (the framework would otherwise sit in `waiting` until the
  timeout). `swift-tests/network` exercises both against real loopback sockets,
  including the proxy's direct, tunnel, refused and malformed-request paths.
* Failed tunnel dials, and the first forty successful ones, log the destination,
  the `destIP` sent, the resource's `addrPretend` and its app.
* The extension logs how node certificates are checked (pinned, or not verified
  because the gateway advertised no pins).
* `SangforTunnelManager.load` reports the tunnel's status without creating a
  configuration (`.invalid` when none is saved), so an app can find at launch a
  tunnel that outlived it, or that the user switched on in Settings, without
  raising the VPN permission prompt.
* The extension's `getStats` reply carries a `session` summary (interface
  address, DNS servers, user name) for an app taking over a tunnel it did not
  start in this process.
* The terminator resets a segment of a TCP flow it does not hold. After the VPN
  is switched off and on again the client's old connections retransmitted into
  nothing until their own timeout (`packet not routed`); they now reconnect at
  once.
* `keepOnUserStop` covers a stop the app makes too: the app that sets it owns the
  plan's lifetime. A removed configuration wipes the plan like a disabled
  provider does, and stop reasons 9-13 are logged by name.

## 0.0.12

* `VpnTunnelService` overrides `onRevoke()` and reports it to Dart as
  `AndroidVpnDevice.revocations`. Until now the system taking the tunnel away
  -- the user switching the VPN off in system settings or from the
  quick-settings tile, or another `VpnService` taking over -- was invisible to
  the app: no event fired, the packet loop kept reading a descriptor the kernel
  had already closed, and `getState()` kept answering `connected`.
* The revocation is reported from `onRevoke()` rather than `onDestroy()`,
  because `onDestroy` also runs on an ordinary in-app `vpnStop` and would
  announce a revocation on every normal disconnect. For the same reason it
  clears the cached state behind `getState()`: unlike a disconnect the app
  asked for, nothing follows a revocation with a `vpnStop`.
* Both `flutter_sangfor/service` streams install the single native handler they
  share, so `revocations` works on its own instead of depending on something
  having subscribed to `disconnectRequests` first.

## 0.0.11

* Fix iOS builds by distinguishing manager and data plane errors and converting
  the TLS trust wrapper to `SecTrust` for certificate pinning. Keep IPv6 parsing compatible
  with the package's iOS 15 deployment target.

## 0.0.10

* `SangforTunnelInstalledDaemon.diagnoseUnavailable()` explains *why* there is
  no daemon, instead of the bare `null` that `connect()` returns so callers can
  fall back quietly. The causes need different fixes and look identical from the
  outside: nothing installed, a configuration written by another version, an app
  update that moved the executable out from under the logon task, and a task
  that has not run since it was installed. Returns `null` when a daemon *is*
  reachable, so it is safe to call unconditionally.
* `SangforTunnelHostConfig.installedFrom` carries the path the daemon's
  `--install` recorded. The daemon warns at startup when it is running from
  somewhere else, which is what makes a relocated install visible rather than a
  tunnel that silently stops working at the next logon.
## 0.0.9

* Add a client for `sangfor-tunneld`, the process that runs the Rust data plane
  outside the app: `SangforTunnelDaemon`, with two ways to get one.
  `SangforTunnelInstalledDaemon.connect()` finds a daemon installed as an
  elevated logon task by reading the configuration in the user's profile, which
  is what removes the elevation requirement on Windows — creating a wintun
  adapter needs an elevated process, and an app that runs `asInvoker` cannot do
  it at all. `SangforTunnelDaemonProcess.start()` launches the binary as a
  child, which inherits the app's privileges and so is for `loopback` and
  `--dry-run` work.
* Both drive the same control protocol — `start`, `status`, `stopSession`,
  `stop` — over a token-gated loopback socket. The daemon outlives its
  sessions, so one elevated process serves repeated connect/disconnect cycles.
* `SangforTunnelHostConfig` and `SangforTunnelSnapshot` model the daemon's two
  documents. Decoding is lenient where the daemon's own parsing is strict, so a
  newer daemon that adds a field does not break an older app.
* A session plan is handed over by **path**, never inline: it carries the
  request signing key, and the control channel is reachable by any local process
  that has the token.
## 0.0.8

* Keep the extension-native tunnel alive across a restart: the session plan is
  written with "complete until first user authentication" protection (iOS may
  bring the tunnel back after a reboot or a network change with the device
  still locked) and is only wiped on a user-initiated, provider-disabled, or
  app-update stop instead of every stop.
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
