# flutter_sangfor

A Flutter package family for Sangfor remote-access VPNs (aTrust and Easy
Connect) with an independently implemented protocol core. No vendor SDK binaries.

## Packages

| Package | Path | Description |
| --- | --- | --- |
| [`flutter_sangfor`](packages/flutter_sangfor/) | `packages/flutter_sangfor` | Common lifecycle, errors, events, userspace data plane (SOCKS5 frontend, TUN adapters) |
| [`flutter_sangfor_atrust`](packages/flutter_sangfor_atrust/) | `packages/flutter_sangfor_atrust` | aTrust connector: login, node selection, L3 tunnel, TCP tunnel |
| [`flutter_sangfor_easy_connect`](packages/flutter_sangfor_easy_connect/) | `packages/flutter_sangfor_easy_connect` | Easy Connect connector: login, minimal TLS client, L3 tunnel, TCP-over-L3 synthesis |

The product packages depend on the root package and never on each other.

## Documentation

- [Architecture](docs/architecture.md)
- [Protocol evidence](docs/protocol-evidence.md)
- [Tasks](tasks/todo)

## Status

Protocol cores are complete and covered by unit tests, but have not been
exercised against authorized production deployments yet. See the package
READMEs for details and usage.

## Releasing

All three packages are published from this repository to pub.dev via
[automated publishing](https://dart.dev/tools/pub/automated-publishing)
(OIDC, no long-lived secrets). CI runs analyze/test for each package in
parallel, builds the Windows example, and then publishes.

Lockstep release process:

1. Bump `version:` in all three `packages/*/pubspec.yaml` files, and bump
   the connectors' `flutter_sangfor:` dependency to the new version.
2. Update each package's `CHANGELOG.md`.
3. Commit and push to `main`.
4. Tag and push: `git tag v0.0.2 && git push origin v0.0.2`.

The tag `vX.Y.Z` publishes every package whose pubspec version matches; the
root package is published first and the workflow waits for it to become
resolvable on pub.dev before publishing the connectors. A manual
`workflow_dispatch` run publishes every package whose pubspec version is
not yet on pub.dev.

## License

MIT. This project does not grant rights to Sangfor trademarks, proprietary
SDKs, binaries, or service-side intellectual property.

## Acknowledgments

This project is an independent clean-room reimplementation of publicly
observed wire behavior; no source code is copied from the following
projects, which were used as behavior references:

- [Mythologyli/zju-connect](https://github.com/Mythologyli/zju-connect) (AGPL-3.0)
  — aTrust L3 tunnel, per-flow auth, conntrack, TCP tunnel.
- [GayStudio/EasierConnect](https://github.com/GayStudio/EasierConnect)
  — EasyConnect XML control plane reference.
- [lyc8503/NJUConnect](https://github.com/lyc8503/NJUConnect)
  — EasyConnect control plane reference.
- [Yan233th/SHIEP-Pipeline](https://github.com/Yan233th/SHIEP-Pipeline) (AGPL-3.0, Rust)
  — EasyConnect token, Query-IP, RX/TX stream, heartbeat.
- [WireGuard/wintun](https://www.wintun.net/)
  — Windows TUN adapter (official signed DLL loaded at runtime).
