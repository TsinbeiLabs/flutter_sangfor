# Architecture

The project has two deliberately separate layers:

1. A pure aTrust-compatible protocol core. It owns HTTPS authentication,
   challenge handling, session data, resource parsing, and tunnel framing.
2. Flutter platform adapters. They own lifecycle, secure credential storage,
   Android `VpnService`, iOS `NetworkExtension`, and desktop tunnel devices.

The protocol core will be implemented from observed wire behavior and public
documentation. Code from GPL/AGPL projects is used only as reference; it is
not copied into this repository.

No Sangfor SDK, client binary, credentials, or server-specific configuration is
part of this project.

## Milestones

- [x] Multi-platform Flutter plugin scaffold
- [x] Structured Dart connection API
- [ ] aTrust authentication transport
- [ ] Challenge and MFA flow
- [ ] Resource and route parsing
- [ ] TCP tunnel implementation
- [ ] Desktop SOCKS/TUN adapters
- [ ] Android `VpnService` adapter
- [ ] iOS `NetworkExtension` adapter
