# Architecture

The project has two deliberately separate layers:

1. A pure aTrust-compatible protocol core. It owns HTTPS authentication,
   challenge handling, session data, resource parsing, and tunnel framing.
2. Flutter platform adapters. They own lifecycle, secure credential storage,
   Android `VpnService`, iOS `NetworkExtension`, and desktop tunnel devices.

The repository is organized as a package family. `flutter_sangfor` contains the
product-neutral client, models, and connector contract. `flutter_sangfor_atrust`
and `flutter_sangfor_easy_connect` contain product-specific authentication and
tunnel implementations and depend only on the root package.

The protocol core will be implemented from observed wire behavior and public
documentation. Code from GPL/AGPL projects is used only as reference; it is
not copied into this repository.

No Sangfor SDK, client binary, credentials, or server-specific configuration is
part of this project.

## Milestones

- [x] Multi-platform Flutter plugin scaffold
- [x] Structured Dart connection API
- [x] Cross-platform connection control plane
- [x] Platform-neutral authentication transport boundary
- [x] Product connector package boundaries
- [x] aTrust server manifest and auth discovery
- [x] aTrust primary password exchange
- [x] aTrust MFA step and resource parsers
- [x] aTrust SMS verification and resource retrieval
- [x] aTrust Cookie/SID session continuity
- [x] aTrust environment report and online info
- [x] aTrust password and SMS login coordinator
- [x] aTrust TOTP, RADIUS, and code challenge requests
- [x] aTrust enhanced auth, access check, and device binding
- [x] aTrust session snapshots and node-group parsing
- [x] Bounded incremental tunnel frame boundary
- [x] aTrust Dart authentication connector
- [x] Tunnel lifecycle, heartbeat, reconnect, and bounded queue primitives
- [x] Abstract packet-to-tunnel I/O bridge
- [x] aTrust L3 tunnel handshake, VIP, and data-frame protocol (zju-connect reference implementation)
- [x] aTrust conntrack TCP state machine with protocol TTLs
- [x] aTrust IPv4/TCP/UDP packet parsing and inbound stream splitting
- [x] aTrust SOCKS5-like TCP tunnel protocol with signed auth and data framing
- [x] aTrust Anti-MITM certificate pinning via `SecureSocket`
- [x] aTrust node selection, Query-IP, and the full tunnel driver
- [x] aTrust connector returns `connected` sessions with a live packet stream
- [x] Easy Connect XML control plane (password, SMS, TOTP)
- [x] Easy Connect conf.csp/rclist.csp resource and DNS parsers
- [x] Easy Connect tunnel token derivation and handshake/heartbeat messages
- [x] Easy Connect update_session.csp keepalive
- [x] Minimal TLS 1.1/1.2 client (RFC 4346/5246) for the L3IP data channels
- [x] Easy Connect tunnel driver: token, Query-IP, RX/TX streams, keepalives
- [x] Easy Connect connector returns `connected` sessions with a live packet stream
- [x] Userspace TCP/UDP synthesis over the Easy Connect L3 plane (RFC 793/768 client role)
- [x] Tunnel DNS resolver for the Easy Connect userspace plane (RFC 1035)
- [x] Product-neutral SOCKS5 frontend (RFC 1928 no-auth CONNECT) and `dialTcp` on both connectors
- [x] Windows Wintun adapter (official signed DLL, FFI) and Linux TUN adapter (FFI ioctl)
- [x] Android `VpnService` adapter (foreground service + Dart FFI fd)
- [x] Dry-run connectors without network I/O
- [ ] Verified aTrust on-wire tunnel protocol against an authorized deployment
- [ ] Minimal-TLS interop with a real EasyConnect server and third-party TLS stacks
- [ ] Verified Wintun/Linux TUN adapters against real interfaces (needs elevation)
- [ ] Android on-device VPN runtime test (APK build verified)
- [x] iOS `NetworkExtension` adapter (compiled; needs a Mac to runtime-test)
- [x] macOS utun adapter (compiled; needs macOS to runtime-test)
