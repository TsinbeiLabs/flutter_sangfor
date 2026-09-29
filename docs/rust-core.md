# `sangfor-core`: one Rust data plane for five platforms

Status: Phase 1 landed. `rust/` builds and is tested on Linux/Windows CI;
Phases 2–6 are open. Supersedes the per-language data planes
(`flutter_sangfor_atrust` Dart, `SangforTunnelCore/Native` Swift) as the
production path; both stay as reference implementations and fallbacks until
each platform is verified against an authorized gateway.

### What exists today

| Crate | Contents | Verification |
|---|---|---|
| `sangfor-core` | canonical JSON, SHA-256/HMAC + the salted certificate digest, L3 frames/handshake/VIP, flow auth signing, TCP-tunnel dial protocol, IPv4/TCP codec with checksums, route table, flow tracker, userspace TCP terminator, session plan, data-plane orchestration | 44 tests: 15 golden (against the Dart fixtures), 18 terminator, 11 plane |
| `sangfor-ffi` | the C ABI (`include/sangfor.h`), one runtime thread, effect dispatch | 3 tests driving a whole session through `extern "C"` |
| `sangfor-tun` | scaffolding only — wintun/tun/fd devices are Phase 2 | — |

`sangfor-core` cross-compiles with no C toolchain to `x86_64-pc-windows-msvc`,
`x86_64-unknown-linux-gnu`, `aarch64-linux-android`, and
`aarch64-unknown-linux-ohos`. The Windows release `cdylib` is ~320 KB, which is
the number that matters for the extension budget (the 25 MB `.a` files are
unlinked static archives, not what ships). Linking a `cdylib` for Android/OHOS
still needs the NDK linker, exactly as `key_obfuscator` does today.

Run it locally:

```bash
cd rust && cargo test --workspace        # 47 tests
cargo clippy --workspace --all-targets -- -D warnings
```


## 1. Problem

The data plane exists twice today and neither copy can serve every platform:

| Layer | Dart (app process) | Swift (iOS extension only) |
|---|---|---|
| L3 protocol/frames | `l3_connection.dart`, `packet.dart` | `ATrustL3Protocol.swift`, `ATrustL3Connection.swift` |
| TCP termination / codec | `tcp_terminator.dart`, `tcp_packet_codec.dart` | `ATrustTcpTerminator.swift`, `ATrustPacketCodec.swift` |
| Transport / routing / crypto | `tunnel.dart`, `socks5.dart`, `wintun.dart`, `system_proxy.dart` | `SangforTlsChannel.swift`, `ATrustRouteTable.swift`, `SangforSha256.swift` |

The Swift copy exists for one reason: a `NEPacketTunnelProvider` cannot host a
Dart isolate. Everywhere else the native code is thin — Android 490 lines,
OHOS 622, Windows 98, Linux 25 — because each of them hands a TUN file
descriptor back to Dart. That has a consequence users feel:

**Killing the app kills the VPN on Android, OHOS, Windows, and Linux.** The
tunnel lives in the Flutter process, so an OS memory reclaim, a swipe-away, or
a normal app exit drops every connection. iOS is the only platform where the
data plane already runs outside the app, and it got there by duplicating the
protocol in a second language.

A single Rust core, loaded *inside each platform's own tunnel process*, fixes
both problems at once: one implementation to audit, and a tunnel whose lifetime
is the platform service's, not the UI's.

## 2. Goals / non-goals

Goals:

1. One implementation of the aTrust data plane: L3 framing, per-flow auth and
   signing, heartbeats, reconnect, the TCP-tunnel dial protocol, conntrack,
   route matching, the userspace TCP terminator, and the IPv4/TCP codec.
2. Run inside the platform's tunnel process on all five platforms
   (`.appex`, `VpnService`, `VpnExtensionAbility`, a Windows service/daemon, a
   Linux daemon).
3. Byte-identical wire behaviour with the Dart reference, proven by the
   existing golden fixtures rather than by re-reading a gateway.
4. No C toolchain requirement per target: crypto and TLS are pure Rust so the
   OHOS NDK cross-build stays a `cargo build`.

Non-goals:

- The control plane stays in Dart. Login, MFA challenges, resource parsing, and
  credential storage need UI and platform keystores; they are not duplicated.
- No utun ownership on iOS (see §4).
- No IPv6 data plane yet, matching the current implementations.

## 3. Crate layout

```
rust/
  Cargo.toml                 # workspace
  sangfor-core/              # protocol only, no I/O, no platform code
    src/
      json.rs                # canonical encoder: byte-identical to Dart jsonEncode
      crypto.rs              # sha256/hmac (RustCrypto) + the salted cert digest
      l3_protocol.rs         # frames, streaming decoder, handshake parser, VIP
      l3_connection.rs       # handshake, flow auth, heartbeats, reconnect
      flow.rs                # flow key, tracker, TTLs, pending-packet cache
      tcp_tunnel.rs          # SOCKS5-like dial protocol + stream state machine
      packet.rs              # IPv4/TCP parse+build, checksums, stream splitter
      route.rs               # route table: CIDR / range / domain matching
      terminator.rs          # userspace TCP, server role (RFC 793 subset)
      plan.rs                # session hand-off document (serde)
      plane.rs               # orchestration: egress routing, ingress fan-out
      transport.rs           # ByteStream/Connector traits (no implementation)
  sangfor-tun/               # platform devices, feature-gated
    src/wintun.rs            # windows
    src/tun.rs               # linux /dev/net/tun
    src/fd.rs                # android + ohos: an fd handed over by the service
  sangfor-ffi/               # the only crate with a C ABI
    src/lib.rs               # extern "C" surface + opaque handle
    include/sangfor.h
```

`sangfor-core` depends on nothing platform-specific and performs no I/O: it
receives bytes and emits bytes through traits. That is what makes it testable
on a laptop and safe to embed in a 50 MB extension.

`rustls` is wired in `sangfor-tun` (or a thin `sangfor-tls` crate), never in
`-core`, so the protocol core can be exercised without a TLS stack.

### Crypto and TLS choices

- `sha2` + `hmac` (RustCrypto): pure Rust, cross-compiles to
  `aarch64-unknown-linux-ohos` without the NDK's clang, which `ring` and
  `aws-lc-rs` both complicate.
- `rustls` with the RustCrypto provider (`rustls-rustcrypto`) for the same
  reason. If a target later needs FIPS or better throughput, swap the provider
  behind `transport.rs`; nothing else changes.
- The anti-MITM pin is the gateway's salted digest,
  `upper_hex(sha256(base64(der) + "@~*&!()-"))`, implemented once in
  `crypto.rs` and checked against the golden fixture.

## 4. The C ABI

One surface, five callers. Deliberately tiny and synchronous-looking: the
extension, the VpnService, and the daemon all have the same shape — feed
packets in, get packets out, ask for stats, stop.

```c
typedef struct SangforHandle SangforHandle;

/* plan_json: the ATrustSessionPlan document. Returns NULL on failure and
 * writes a heap string to *error (caller frees it with sangfor_free). */
SangforHandle *sangfor_start(const char *plan_json, char **error);

/* Ingress callback: invoked from the core's runtime thread with one raw IP
 * packet. The buffer is only valid for the duration of the call. */
typedef void (*SangforIngressFn)(void *ctx, const uint8_t *packet, size_t len);
void sangfor_set_ingress(SangforHandle *h, SangforIngressFn cb, void *ctx);

/* One egress packet from the TUN / packet flow. Returns 0 when the core
 * handled it (forwarded or terminated), non-zero when it declined. */
int sangfor_write_packet(SangforHandle *h, const uint8_t *packet, size_t len);

/* JSON counters, heap-allocated; free with sangfor_free. */
char *sangfor_stats(SangforHandle *h);

void sangfor_stop(SangforHandle *h);   /* idempotent, joins the runtime */
void sangfor_free(void *ptr);
```

Rules:

- No Flutter Rust Bridge here. The `.appex` has no Flutter, so a generated Dart
  layer would still leave a second hand-written surface for Swift. Dart calls
  the same `extern "C"` symbols through `dart:ffi`, which the package already
  does for wintun and utun.
- All string ownership crosses the boundary explicitly (`sangfor_free`), so
  there is no ambiguity about who frees what.
- The core owns exactly one thread (see §5). Callers may call from any thread;
  the handle serializes internally.

## 5. Concurrency and the extension budget

A packet tunnel extension gets roughly 50 MB and counts thread stacks against
it. So:

- One current-thread `tokio` runtime inside `sangfor-ffi`, one worker thread,
  everything (TLS, timers, the terminator, heartbeats) on it.
- The TUN read loop runs on the *caller's* thread where the platform gives us
  one (`NEPacketTunnelFlow.readPackets`, a blocking `read` on an fd, wintun's
  read-wait event) and hands packets to the runtime over a bounded channel.
  Bounded, with a drop counter: an unbounded queue turns a stalled tunnel into
  an OOM kill, which on iOS takes the VPN down silently.
- Ingress packets are copied once into the caller's buffer inside the callback;
  no shared ownership across the FFI boundary.

## 6. Per-platform process model

| Platform | Who owns the TUN | Where the core runs | Survives app death |
|---|---|---|---|
| iOS | `NEPacketTunnelFlow` (Swift pumps bytes; the core never sees the utun) | `.appex` | already yes |
| Android | `VpnService` fd | a dedicated `android:process=":vpn"` service | yes (new) |
| OHOS | `VpnExtensionAbility` fd | the extension ability process, which already exists | yes (new) |
| Windows | wintun, owned by `sangfor-tun` | a small daemon/service, or in-process until that lands | yes (new) |
| Linux | `/dev/net/tun` | daemon or in-process | yes (new) |

iOS keeps `NEPacketTunnelFlow` on purpose. `wireguard-go` creates its own utun
inside the extension, but that means re-implementing what
`setTunnelNetworkSettings` already provides: routes, DNS, `NEProxySettings`,
reasserting, and the system's own interface bookkeeping. Pumping bytes across
the ABI keeps Apple's plumbing and confines Rust to protocol work.

Android's `:vpn` process is the piece that actually changes user experience:
today a swipe-away or an OEM memory reclaim kills the tunnel even though the
foreground service was supposed to prevent it, because the fd consumer is the
Dart isolate in the UI process.

## 7. The session plan is the contract

`ATrustSessionPlan` already crosses a process boundary (Runner → extension) as
a JSON document, and `test/fixtures/native_atrust.json` already pins its exact
bytes. Rust deserializes the same document with `serde`, so:

- the Dart control plane does not change at all;
- the same golden file that validates the Swift core validates the Rust core;
- adding a field is a schema-version bump in one place.

That file is the single oracle. `packages/flutter_sangfor_atrust/test/native_fixtures_test.dart`
regenerates it from the Dart implementation and fails if Dart drifts;
`swift-tests/main.swift` and `rust/sangfor-core/tests/golden.rs` both consume
it. Three languages, one source of truth, no re-derivation of the protocol
from a live gateway.

## 8. Build and distribution

Follow the pattern the app already runs for `key_obfuscator`:

1. `rust/` builds `staticlib` (Apple) and `cdylib` (everything else) with
   `opt-level="z"`, `lto`, `codegen-units=1`, `panic="abort"`, `strip`.
2. CI publishes per-target artifacts to a GitHub release; consumers fetch them
   with a sha256-pinned lock file (`prebuilts.lock.json` in the app today).
3. Apple targets build on a macOS runner; `aarch64-unknown-linux-ohos` uses
   the NDK clang already configured in `.cargo/config.toml`.
4. Xcode links the static lib into **both** `Runner` and
   `SangforPacketTunnel.appex` with `-force_load`, exactly as
   `libkey_obfuscator.a` is linked today.

cargokit (as `fjs` uses) is the alternative for source builds during
`flutter build`. Not adopted here: it forces a Rust toolchain plus every target
on all contributors, and it does not cover OHOS. Revisit if the prebuilt
pipeline becomes a bottleneck.

## 9. Migration and rollback

Each platform moves independently, behind a flag, with the existing
implementation intact:

1. **Phase 1 — core + golden tests.** No behaviour change anywhere. Verified on
   Linux/Windows CI against the fixtures.
2. **Phase 2 — platform devices.** wintun, `/dev/net/tun`, fd hand-off.
3. **Phase 3 — iOS.** `SangforNativeTunnelRuntime` keeps its shape and calls
   the ABI instead of `SangforNativeDataPlane`. `runtimeMode` gains
   `extensionRust`; `extensionNative` (Swift) stays selectable, so a bad build
   is a flag flip, not a revert.
4. **Phase 4 — Windows.** Daemon owning wintun; the app becomes a client. This
   is the biggest user-visible win: no elevation for the data plane, and the
   tunnel outlives the app.
5. **Phase 5 — Android/OHOS.** Move the fd consumer into the service process.
   Dart keeps `VpnTunnelMode.system` on the old path until on-device verified.
6. **Phase 6 — delete.** The Swift `Native/` core and the Dart data plane go
   away; Dart keeps login/resources/UI, and the golden fixtures stay as the
   contract test for whatever comes next.

Rollback is per platform and per phase: the Dart path is untouched until
Phase 6, and iOS has two native modes side by side until then.

## 10. Risks

- **Canonical JSON.** The signature covers `jsonEncode`'s exact bytes: key
  insertion order, no whitespace, `"`/`\`/the five short escapes, other
  control characters as lowercase `\u00xx`, U+007F and non-ASCII passed
  through raw. A serializer that sorts keys or escapes differently produces a
  valid request the gateway rejects. Mitigated by making `json.rs` a
  fixture-driven test target before anything else is written.
- **rustls with a non-default provider** is less travelled than ring. The
  `transport.rs` seam exists so the provider can be swapped per target without
  touching the protocol.
- **Verification still needs a real gateway.** Fixtures prove the two
  implementations agree; only an authorized deployment proves the protocol
  itself is right. Every phase ships behind a flag for that reason.
- **Binary size.** rustls + RustCrypto is on the order of 1–2 MB per arch
  static-linked. Acceptable for the `.appex`; measure before Phase 3.
