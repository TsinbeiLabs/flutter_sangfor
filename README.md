# flutter_sangfor

A Flutter package family for Sangfor remote-access VPNs (aTrust and Easy
Connect) with an independently ported protocol core. No vendor SDK binaries.

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

## License

MIT. This project does not grant rights to Sangfor trademarks, proprietary
SDKs, binaries, or service-side intellectual property.
