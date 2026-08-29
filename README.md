# flutter_sangfor

Flutter integration for Sangfor aTrust-compatible VPN deployments.

## Status

This repository is an independent implementation. It does not include or
redistribute Sangfor SDK binaries. The public API and platform adapters are
being built incrementally, with protocol behavior tested against authorized
deployments only.

The package scaffold declares Android, iOS, Windows, macOS, and Linux targets.
Platform tunnel integration is not production-ready yet.

## API direction

The Dart API exposes structured connection state and authentication types. The
protocol core is kept separate from Flutter platform glue so it can be tested
independently and reused by desktop and mobile adapters.

## License

The original Flutter integration is MIT licensed. This project does not grant
rights to Sangfor/Atrust trademarks, proprietary SDKs, binaries, or
service-side intellectual property.
