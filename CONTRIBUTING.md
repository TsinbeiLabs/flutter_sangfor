# Contributing

Thanks for your interest in improving this package family.

## Getting started

```bash
git clone https://github.com/TsinbeiLabs/flutter_sangfor.git
cd flutter_sangfor/packages/flutter_sangfor
flutter pub get
flutter test
```

Each package under `packages/` is an independent pub package with its own
tests; run `flutter pub get` and `dart test` inside each before submitting
changes. The CI workflow runs analyze, format, and test for every package
plus a Windows example build.

## Ground rules

- **Protocol behavior must be verified against authorized deployments
  before being labeled compatible.** Mark new protocol evidence as
  `synthetic` until verified (see `docs/protocol-evidence.md`).
- **No copying from AGPL/GPL references.** This is a clean-room
  reimplementation. If a change requires reading upstream source code,
  stop and open an issue describing the behavior instead.
- **Never store or log passwords, cookies, SIDs, tokens, or challenge
  codes.** Session snapshots must remain credential-free.
- **Keep aTrust and Easy Connect implementations independent.** Product
  code belongs in `flutter_sangfor_atrust` or `flutter_sangfor_easy_connect`,
  never in the product-neutral root package.
- **No Sangfor SDK binaries, proprietary code, or credentials** may be
  committed.

## Pull requests

1. Fork and branch from `main`.
2. Add or update tests for the behavior you are changing.
3. Run the analyzer and formatter in every affected package:
   `dart analyze && dart format --set-exit-if-changed .`
4. Update the relevant `CHANGELOG.md` under `packages/*/`.
5. Keep commits focused; the repo follows conventional commit style
   (`feat:`, `fix:`, `docs:`, `ci:`, `chore:`).

## Releasing

Releases are published to pub.dev automatically via OIDC when a `vX.Y.Z`
tag is pushed. See the [README](README.md#releasing) for the lockstep
release process.
