# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.0.x | security fixes only |

## Reporting a Vulnerability

Report vulnerabilities privately to `team@tsinbei.com`. Include a
description of the issue, affected code paths, and reproduction steps or
a proof of concept if available.

Please do not open public issues for security problems. We will respond
within 72 hours and credit reporters in the fix's changelog entry unless
anonymity is requested.

## Scope

This project is a clean-room reimplementation of publicly observed wire
behavior for Sangfor remote-access VPNs (aTrust and Easy Connect). It
contains no Sangfor SDK binaries, proprietary code, or credentials.

In scope:

- Anything in this repository (Dart, Kotlin, Swift, CI workflow).

Out of scope:

- Vulnerabilities in Sangfor server software (report to Sangfor).
- Vulnerabilities in dependencies (report upstream; we will track and
  bump versions).
- Active attacks against production VPN deployments you do not own or
  are not authorized to test.

## Assessed dependency advisories

Dependabot alerts are triaged before being dismissed, and a dismissal is
recorded here with the reasoning that supports it. Re-open the assessment
when the reason stops holding.

### `rustls-webpki` 0.102.8 — four advisories, vulnerable code unreachable

Dismissed 2026-10-02 as *vulnerable code not in execute path*:

| Advisory | Severity | Subject |
| --- | --- | --- |
| GHSA-82j2-j2ch-gfr8 / RUSTSEC-2026-0104 | high | denial of service via panic on a malformed CRL `BIT STRING` |
| GHSA-pwjx-qhcg-rvj4 / RUSTSEC-2026-0049 | medium | CRLs not treated as authoritative by Distribution Point |
| GHSA-965h-392x-2mh5 / RUSTSEC-2026-0098 | low | name constraints for URI names incorrectly accepted |
| GHSA-xgp8-3hg3-c2mh / RUSTSEC-2026-0099 | low | name constraints accepted for wildcard names |

All four are in CRL parsing or name-constraint checking. Neither is reachable
from this workspace:

1. **The 0.102 copy is here only as a dependency of `rustls-rustcrypto`
   0.0.2-alpha**, the pure-Rust provider `sangfor-tls` needs so the OHOS and
   Android cross-builds stay free of a C toolchain. `rustls` 0.23 resolves its
   own, already-patched `rustls-webpki` 0.103.x separately — which is why
   `Cargo.lock` carries two copies of the crate.
2. **`rustls-rustcrypto` uses exactly one symbol from it**: `webpki::alg_id`,
   imported in `src/verify/{ecdsa,eddsa,rsa}.rs`. That module is a table of
   `pub const AlgorithmIdentifier` values built with
   `include_bytes!("data/alg-*.der")` — DER-encoded OIDs resolved at compile
   time. It parses nothing at run time and never sees attacker-controlled
   input.
3. **No certificate path validation runs through it.** `sangfor-tls` installs
   its own `ServerCertVerifier` (`sangfor-tls/src/trust.rs`, `PinVerifier`,
   wired via `.dangerous()`), which pins the leaf certificate digest and
   deliberately ignores intermediates, the server name, OCSP and time: aTrust
   gateways advertise the identity of the leaf the node presents, and commonly
   present self-signed leaves with no chain at all. With no chain there are no
   name constraints to apply and no distribution point to fetch, so neither
   vulnerable code path is entered.
4. A search for `crl`, `revocation` and `name_constraint` across `rust/`
   matches nothing outside this file.

There is no patched `rustls-webpki` 0.102.x — every fix landed in 0.103, which
`rustls-rustcrypto` 0.0.2-alpha cannot accept — so there is no version
Dependabot can propose. This resolves itself when `RustCrypto/rustls-rustcrypto`
publishes a release from its current `main`, which has dropped the `webpki`
dependency altogether and moved to the `digest` 0.11 generation. The same
release unblocks the `hmac` 0.13 bump in PR #13, which would otherwise
duplicate SHA-256/HMAC in a binary size-tuned for an iOS packet-tunnel
extension.

**Re-open this assessment if** `sangfor-tls` ever validates a chain through
rustls's WebPKI verifier, enables revocation checking, or if
`rustls-rustcrypto` starts using `webpki` for anything beyond `alg_id`.

