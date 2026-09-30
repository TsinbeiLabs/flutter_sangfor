# `sangfor-core`: one Rust data plane for five platforms

Status: Phases 1, 2, and most of 4 landed. `rust/` builds and is tested on
Linux/Windows CI, the whole stack runs end to end against a fake gateway, and
there is a tunnel process binary that starts, configures itself, serves a
control protocol, and exits cleanly. Phase 3 (iOS) and Phase 5 (Android/OHOS
service processes) are open, and Phase 4 still needs its Windows service wrapper
and its app-side client. Supersedes the per-language data planes
(`flutter_sangfor_atrust` Dart, `SangforTunnelCore/Native` Swift) as the
production path; both stay as reference implementations and fallbacks until each
platform is verified against an authorized gateway.

### What exists today

| Crate | Contents | Verification |
|---|---|---|
| `sangfor-core` | canonical JSON, SHA-256/HMAC + the salted certificate digest, L3 frames/handshake/VIP, flow auth signing, TCP-tunnel dial protocol, **the relay session that actually uses it**, IPv4/TCP codec with checksums, route table, flow tracker, userspace TCP terminator, session plan, data-plane orchestration | 55 tests: 10 relay, 16 golden (against the Dart fixtures), 18 terminator, 11 plane |
| `sangfor-tls` | `rustls` on the pure-Rust RustCrypto provider, the anti-MITM pin verifier, a blocking channel and a split handshake for poll-driven hosts | 7 tests over a real loopback handshake |
| `sangfor-tun` | the `PacketDevice` seam, wintun (Windows), `/dev/net/tun` (Linux), handed-over descriptors (Android/OHOS), and an in-memory device | 12 tests, including the concurrent reader/writer contract |
| `sangfor-host` | the event loop: `mio` readiness, bounded queues, the channel registry, effect application | 6 tests, 4 of them end to end against a fake gateway |
| `sangfor-tunneld` | the tunnel process binary: two documents in, a device open, a running tunnel, a control protocol | 50 tests: routes and node exclusion, config validation, the protocol, argument parsing, process startup |
| `sangfor-ffi` | the C ABI (`include/sangfor.h`), one runtime thread, effect dispatch | 3 tests driving a whole session through `extern "C"` |

133 tests, `cargo fmt` and `cargo clippy -D warnings` clean.

`rustls-rustcrypto` and `mio` are both pure Rust, so the whole stack
cross-compiles with no C toolchain to `x86_64-pc-windows-msvc`,
`x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`, `aarch64-linux-android`,
and `aarch64-unknown-linux-ohos`. That is a property CI enforces, not an
intention: adding `ring` or `aws-lc-rs` anywhere in the graph breaks the OHOS
build.

Measured, with the workspace release profile (`opt-level="z"`, `lto`,
`codegen-units=1`, `panic="abort"`, `strip`):

- **`sangfor-tunneld.exe` is 1.23 MB** on `x86_64-pc-windows-msvc` — a complete
  tunnel process: protocol, TLS, devices, event loop, control channel. That
  answers the size question §10 raised; the `.appex` budget is ~50 MB.
- `sangfor-ffi`'s `cdylib` is 346 KB. It does not link TLS, because at that
  level the host owns the transport.

Run it locally:

```bash
cd rust && cargo test --workspace        # 221 tests
cargo clippy --workspace --all-targets --features sangfor-tun/wintun -- -D warnings
cargo build --release -p sangfor-tunneld
```

The daemon runs with no driver and no privileges, which is what makes it
testable on a laptop and on a CI runner:

```bash
sangfor-tunneld --dry-run --check --plan plan.json --interface Luotopia
sangfor-tunneld --dry-run --config host.json    # then, on stdin or the socket:
                                                #   {"cmd":"start","planPath":"plan.json"}
                                                #   {"cmd":"status"}
```

`--plan -` is gone. stdin is the control channel, and a daemon that read its plan
from there would have nothing left to receive commands on.

### The relay gap the end-to-end test found

Phase 1 ported `tcp_tunnel.rs` — the signed auth handshake, the server hello,
length-prefixed framing — and golden-tested every function in it. Nothing in the
data path called any of them. The terminator emitted `Dial`, the host opened a
socket, and the plane started relaying **raw TCP payload with no authentication
handshake at all**. Against a real gateway every TCP-tunnel-only resource would
have failed, which is most of them on the deployment this was built for.

`sangfor-core/src/relay.rs` is the missing layer, and `DataPlane` now drives it:
the opening message goes out before the terminator's first flight, that flight
is held until the hello arrives, a refused hello fails the dial with the
gateway's own reason, and framing follows `zeroRtt && response.reuse` exactly as
`ATrustTcpTunnelConn` does. `Effect::Dial` gained the resolved destination
because the gateway signs both `destAddr` (the name) and `destIP` (the address),
and the terminator only knew the alias it dialled.

The Dart and Swift planes were never affected — both perform the handshake. This
was a gap in the new port, and only an end-to-end test could have caught it:
every unit test of every piece passed while the composition was broken.


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
  Cargo.toml                 # workspace, shared deps, the size-tuned release profile
  sangfor-core/              # protocol only: no I/O, no platform code, forbid(unsafe_code)
    src/
      json.rs                # canonical encoder: byte-identical to Dart jsonEncode
      crypto.rs              # sha256/hmac (RustCrypto) + the salted cert digest
      l3.rs                  # frames, streaming decoder, handshake parser, VIP
      flow.rs                # flow key, tracker, TTLs, pending-packet cache
      tcp_tunnel.rs          # the dial protocol: signed hello, framing, decoders
      relay.rs               # one relay's session: hello, hold-before-open, framing
      packet.rs              # IPv4/TCP parse+build, checksums, stream splitter
      route.rs               # route table: CIDR / range / domain matching
      terminator.rs          # userspace TCP, server role (RFC 793 subset)
      plan.rs                # session hand-off document (serde)
      plane.rs               # orchestration: egress routing, ingress fan-out
      error.rs
  sangfor-tls/               # rustls + the RustCrypto provider + the pin verifier
    src/trust.rs             # TrustPolicy / PinVerifier: leaf digest, signatures still checked
    src/channel.rs           # blocking channel, and `handshake()` for poll-driven hosts
  sangfor-tun/               # the PacketDevice seam, devices feature-gated
    src/device.rs            # the trait + LoopbackDevice (forbid(unsafe_code))
    src/wintun.rs            # windows: wintun.dll loaded at runtime, netsh config
    src/tun.rs               # linux /dev/net/tun
    src/fd.rs                # android + ohos: a descriptor handed over by the service
    src/unix_io.rs           # the poll/read/write loop `tun` and `fd` share
  sangfor-host/              # the event loop
    src/channel.rs           # ByteChannel, mio registration, the Connector seam
    src/host.rs              # device pump + readiness loop + effect application
    tests/end_to_end.rs      # the whole stack against a fixture-replaying gateway
  sangfor-tunneld/           # the tunnel process binary (see §6.1)
    src/cli.rs               # argument parsing + usage
    src/config.rs            # the host configuration document, validated
    src/netconfig.rs         # route math: node exclusion, block splitting
    src/device.rs            # device selection + the interface configurator
    src/control.rs           # the JSON-lines control protocol
    src/runtime.rs           # logging, the configurator thread, the run loop
    src/main.rs              # two documents in, an exit code out
  sangfor-ffi/               # the only crate with a C ABI
    src/lib.rs               # extern "C" surface + opaque handle
    include/sangfor.h
```

`sangfor-core` depends on nothing platform-specific and performs no I/O: bytes go
in and bytes come out. That is what makes it testable on a laptop and safe to
embed in a 50 MB extension.

The transport seam the earlier draft called `transport.rs` is
`sangfor_host::Connector` instead. It lives in the host rather than the core
because the only thing that needs to substitute a transport is a test, and a
trait in the core that nothing in the core calls is a trait nobody implements
correctly.

`rustls` is wired in `sangfor-tls`, never in `-core`, so the protocol can be
exercised with no TLS stack present — which is how 55 of the 83 tests run.

### Crypto and TLS choices

- `sha2` + `hmac` (RustCrypto): pure Rust, cross-compiles to
  `aarch64-unknown-linux-ohos` without the NDK's clang, which `ring` and
  `aws-lc-rs` both complicate.
- `rustls` with the RustCrypto provider (`rustls-rustcrypto`) for the same
  reason. It is an alpha crate, so it is pinned and CI compiles it for every
  target on every push; if it stalls, `sangfor_host::Connector` is the seam to
  swap a provider behind.
- The pin replaces chain validation but **not** signature verification:
  `PinVerifier` still checks the handshake signature against the pinned leaf's
  own key. Without that, pinning would be a label on an unauthenticated
  connection.
- The anti-MITM pin is the gateway's salted digest,
  `upper_hex(sha256(base64(der) + "@~*&!()-"))`, implemented once in
  `crypto.rs` and checked against the golden fixture.
- No GM/T (SM2/SM4). The gateway may advertise an SM2 certificate as pin
  material and that digest is honoured, but an SM2 handshake is not possible
  here — nor in the Dart or Swift planes, so this is not a regression.


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
- Effects are dispatched **after** the plane's lock is released, so a host that
  reacts to an effect by calling back into the ABI does not deadlock against
  itself.
- The shipped surface is `rust/sangfor-ffi/include/sangfor.h`; the sketch above
  is the shape, not the contract.

## 5. Concurrency and the extension budget

A packet tunnel extension gets roughly 50 MB and counts thread stacks against
it. So:

- **No async runtime.** `mio` for readiness and plain threads elsewhere. The
  plane is a synchronous state machine that returns effects, so an async runtime
  would mean colouring the entire core for no benefit, and `tokio` costs more
  binary and more stacks than the whole protocol does.
- Two threads in `sangfor-host`, and the plane lives on exactly one of them — so
  there is no mutex around it and no lock ordering to reason about:
  - the **device reader** blocks in `PacketDevice::read_packet` and pushes over
    a *bounded* queue with a drop counter. It has to be its own thread because a
    wintun session cannot be registered with `mio`, and a descriptor blocked in
    `read` would otherwise hold up socket readiness.
  - the **host loop** owns the plane, every channel, and the device's write
    side: it polls, drains both queues, applies effects, and drives timers.
- TLS connects run on short-lived worker threads, capped by
  `max_pending_connects`. A handshake is far too slow to do inline — it would
  stall every other flow — but an uncapped burst of them is how a tunnel process
  runs out of threads.
- Both queues shed rather than block: an unbounded queue turns a stalled tunnel
  into an OOM kill, which on iOS takes the VPN down silently.
- A `PacketDevice` must tolerate one concurrent reader and one concurrent
  writer. That is what wintun's ring and a TUN descriptor both provide natively;
  serializing them behind one mutex would let a blocked reader stall the writer
  for a whole poll interval, which presents as a slow tunnel.
- Ingress packets are copied once into the caller's buffer inside the callback;
  no shared ownership across the FFI boundary.


## 6. Per-platform process model

| Platform | Who owns the TUN | Where the core runs | Survives app death |
|---|---|---|---|
| iOS | `NEPacketTunnelFlow` (Swift pumps bytes; the core never sees the utun) | `.appex` | already yes |
| Android | `VpnService` fd | a dedicated `android:process=":vpn"` service | yes (new) |
| OHOS | `VpnExtensionAbility` fd | the extension ability process, which already exists | yes (new) |
| Windows | wintun, owned by `sangfor-tunneld` | `sangfor-tunneld`, elevated; a service wrapper is still to come | yes (new) |
| Linux | `/dev/net/tun` | `sangfor-tunneld` | yes (new) |

iOS keeps `NEPacketTunnelFlow` on purpose. `wireguard-go` creates its own utun
inside the extension, but that means re-implementing what
`setTunnelNetworkSettings` already provides: routes, DNS, `NEProxySettings`,
reasserting, and the system's own interface bookkeeping. Pumping bytes across
the ABI keeps Apple's plumbing and confines Rust to protocol work.

Android's `:vpn` process is the piece that actually changes user experience:
today a swipe-away or an OEM memory reclaim kills the tunnel even though the
foreground service was supposed to prevent it, because the fd consumer is the
Dart isolate in the UI process.

Every row except iOS runs the same `sangfor-host` loop; only the device differs,
which is the point of the `PacketDevice` seam. iOS gets the same loop later if
the extension ends up owning its sockets, but Phase 3 keeps Swift pumping
`NEPacketTunnelFlow` bytes across the ABI so Apple's plumbing stays in charge.

### 6.1 `sangfor-tunneld`

The process that runs that loop on the four non-Apple platforms. Two documents
in, a tunnel out:

| Document | Written by | Carries |
|---|---|---|
| session plan | the Dart control plane | credentials, signing key, node endpoints, published resources, anti-MITM pins |
| host config | whoever launches the process | which device to open, the interface name, which routes and DNS servers to install |

The split is the important part. *Which destinations belong in the tunnel* is a
product decision: the app derives it from the gateway's published resources
**and** from the user's route policy and custom entries. Porting that here would
mean a second implementation of a rule users can change in a settings screen,
and the two would drift. So the app keeps computing CIDRs and hands them over;
`--route` appends to them.

Two things the daemon does own:

- **Node exclusion.** Before applying anything it removes the gateway's own node
  endpoints from every route, splitting a block rather than dropping it: a /8
  with a node at `10.1.2.3` survives as 24 narrower blocks with one hole in it.
  A route that captures a node sends the tunnel's traffic into the tunnel, and
  the deadlock that results presents as a network outage. The control plane
  already excludes them; this is the last place a mistake can still be caught,
  and it is logged when it fires.
- **Ordering.** The interface is configured only after the gateway assigns a
  virtual IP, on its own thread. Configuring early means guessing an address the
  plane will not use, and packets the plane emits carry the assigned one as
  their source — an interface with a different address makes the stack drop them
  as martians. `netsh` is slow enough that running it on the host loop would
  stall every flow.

Control is JSON lines in, JSON lines out, logs on stderr:

| Verb | Effect |
|---|---|
| `{"cmd":"ping"}` | liveness; the only verb that needs no token |
| `{"cmd":"status"}` | counters and state |
| `{"cmd":"start","planPath":…,"configPath":…}` | run a session from a plan |
| `{"cmd":"stopSession"}` | end the session, stay up |
| `{"cmd":"stop"}` | end the session and exit |

Each takes an optional `token`. Exit codes are 0 clean, 1 could not run, 2 the
last session died and the control plane must log in again. The protocol is served
on stdin for a child process and on a token-gated loopback socket for anything
without one; both end at one `dispatch` function, so they cannot drift apart in
what they accept or how they report a refusal.

**The process outlives its sessions.** `--plan` means "run this session first",
not "run this session and exit": afterwards the daemon goes idle and answers
`start` again. That is what lets one elevated process serve repeated
connect/disconnect cycles instead of one prompt per connection. It exits on its
own only when nothing can reach it any more — no socket, stdin closed, no session
running — which is what a child launched with a piped plan expects.

`start` names its documents by **path** rather than carrying them. The plan holds
the request signing key, and a loopback socket is reachable by any local process
that has the token, which is a weaker guarantee than a file's permissions. Routes
arrive with `configPath` rather than at launch because an installed daemon is
configured once while which destinations belong in the tunnel depends on what the
gateway published this session; a per-session document overrides the address,
routes, DNS servers, and MTU, and deliberately *cannot* override
`acceptUnpinnedCertificate`, `controlPort`, or `controlToken`.

Verified by running the shipped binary: `--dry-run --check` decodes a plan,
opens a loopback device, and exits 0 with no driver and no elevation; a live
`--dry-run` daemon starts idle, is given a session, has it stopped, is given
another, and exits 0 on `stop`. Rust subprocess tests, the Dart client test, and
`tool/verify_tunneld.ps1` all run that exchange. CI runs all three.

### 6.2 Removing the elevation prompt: a logon task, not a service

The remaining Phase 4 win is removing elevation from the app: the runner's
manifest is `asInvoker`, so `WintunCreateAdapter` fails outright today and the
whole app has to be run as administrator to use the VPN on Windows.

The obvious design — a loopback socket plus an always-running LocalSystem
service — does not survive contact with the threat model:

- A loopback socket cannot identify its peer. `GetNamedPipeClientProcessId` has no
  TCP equivalent, so any local process that has the token can start, stop, or
  **replace** a session.
- The token cannot be made per-user, because a service is installed once and runs
  as LocalSystem while the app runs as whoever is logged in. Storing it where the
  app can read it means storing it where any local user can read it, which makes
  it a speed bump rather than a control.
- A service binary must call `StartServiceCtrlDispatcher` and report
  `SERVICE_RUNNING`, or the SCM kills it after roughly thirty seconds with error
  1053. That is new platform code whose only test is installing a service.

What is implemented instead is a **logon task with `/RL HIGHEST`**
(`sangfor-tunneld --install`), which sidesteps all three:

- It runs in the *user's* session, elevated. `127.0.0.1` is the loopback the app
  is already on, so the control protocol works unchanged.
- Its configuration lives in `%LOCALAPPDATA%\sangfor-tunneld`, so the token in it
  is readable by that user and by administrators — a real boundary rather than a
  decorative one.
- It needs no new code in the daemon: the task starts the same binary with the
  same flags, and the daemon's stdin is simply closed, which the supervisor
  already handles.

What it does not give you is a tunnel that outlives logoff. For a VPN a single
signed-in user drives, that is the right trade.

The install commands are generated as **data** (`service::Install`), so the task
name, the elevated flag, the quoting of a path with a space in it, and the
document written beside the binary are all unit-tested; only handing them to
`schtasks` is not, because that needs the elevation the module exists to obtain.
`--print-install` prints them for a packager to run by hand.

Quoting is the part worth the tests. `/TR` takes a whole command line as one
argument, and Windows' rule is that a run of backslashes before a quote is
half-consumed escaping it — so a path ending in `\` would otherwise swallow the
closing quote and glue the next argument onto it. A round-trip test parses each
rendered command back into argv and compares.

The task records an absolute path, which is the one thing about it that can rot:
an app update that relocates the executable leaves the task pointing at nothing,
and it then fails at every logon with no window and no log entry a user would
ever see. So `--install` writes `installedFrom` into the configuration, the
daemon warns at startup when it is running from somewhere else, and the Dart
client's `diagnoseUnavailable` checks whether the recorded file still exists
before it concludes anything about the socket. That covers a *replaced* binary;
a *deleted* one leaves no process to warn, so it is the app that reports it.

A named pipe with client-process validation remains the right answer for a true
service, and is roughly sixty lines of Win32 with a `SECURITY_DESCRIPTOR`. It is
still not written, for the reason in the previous revision of this section: none
of it can be exercised without installing a service as administrator, and the
failure mode of getting a pipe DACL wrong is either "the app cannot talk to it"
or "anything can".

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

1. `rust/` builds `staticlib` (Apple) and `cdylib`/binary (everything else) with
   `opt-level="z"`, `lto`, `codegen-units=1`, `panic="abort"`, `strip`.
2. CI publishes per-target artifacts to a GitHub release; consumers fetch them
    with a sha256-pinned lock file (`prebuilts.lock.json` in the app today).
    `.github/workflows/release-tunneld.yml` does this for `sangfor-tunneld` —
    windows x64/arm64 and linux x64/arm64, tag-triggered on `tunneld-v*`, and it
    writes the lock fragment rather than leaving it to be transcribed. Published
    as `tunneld-v0.1.0`; the app fetches the Windows binaries with
    `app/scripts/stage_tunneld.ps1`, which pins the digests and treats a
    mismatch as fatal but a download failure as a warning, so an offline build
    still produces a working app. Apple targets and the `cdylib` for the `.appex`
    are not in it yet.
3. Apple targets build on a macOS runner.
4. Xcode links the static lib into **both** `Runner` and
   `SangforPacketTunnel.appex` with `-force_load`, exactly as
   `libkey_obfuscator.a` is linked today.

Note on linkers: cross-*compiling* these crates needs nothing but `rustup target
add`, which is what CI verifies for OHOS and Android. Cross-*linking* a binary
does need the target's toolchain, and the release workflow installs it
(`gcc-aarch64-linux-gnu` for the driver plus `libc6-dev-arm64-cross` for the
`Scrt1.o`/`crti.o` the link wants — installing only the first gets you as far as
the link and then fails with a message that does not name the missing package).
Cross-linking a `cdylib` for Android or OHOS needs the NDK's linker, configured
the way `key_obfuscator` already configures it — there is deliberately no
`.cargo/config.toml` in this workspace, because the linker belongs to the
consuming app, not to the protocol library.

cargokit (as `fjs` uses) is the alternative for source builds during
`flutter build`. Not adopted here: it forces a Rust toolchain plus every target
on all contributors, and it does not cover OHOS. Revisit if the prebuilt
pipeline becomes a bottleneck.

## 9. Migration and rollback

Each platform moves independently, behind a flag, with the existing
implementation intact:

1. **Phase 1 — core + golden tests.** Done. No behaviour change anywhere.
2. **Phase 2 — devices, TLS, and the event loop.** Done. wintun, `/dev/net/tun`,
   fd hand-off, `sangfor-tls`, and `sangfor-host`, with the whole stack verified
   end to end against a fixture-replaying gateway. Also where the relay gap was
   found and fixed.
3. **Phase 3 — iOS.** `SangforNativeTunnelRuntime` keeps its shape and calls
   the ABI instead of `SangforNativeDataPlane`. `runtimeMode` gains
   `extensionRust`; `extensionNative` (Swift) stays selectable, so a bad build
   is a flag flip, not a revert. Needs a Mac and an authorized gateway.
4. **Phase 4 — Windows.** Mostly done: `sangfor-tunneld` opens wintun, waits
   for the virtual IP, configures the interface with the node endpoints
   excluded, runs the tunnel, and serves the control protocol over stdin *and*
   a token-gated loopback socket. It supervises, so one process serves repeated
   connect/disconnect cycles (§6.1), and `--install` registers it as an elevated
   logon task (§6.2). The Dart client
   (`flutter_sangfor/lib/src/tunnel_daemon.dart`) drives it either installed or
   as a child, and a test runs that exchange against the real binary in CI.
   `VERIFY.md` and `tool/verify_tunneld.ps1` check a build on a real machine.
   The app wires it in `vpn_connection_service.dart` behind
   `--dart-define=LUOTOPIA_VPN_TUNNELD=true`, off by default, and stages the
   binary beside the runner with `app/scripts/stage_tunneld.ps1`. Still open:
   - a **real gateway run**, which needs elevation on the verifying machine;
   - a **true Windows service**, if the tunnel ever has to outlive logoff — see
     §6.2 for why the logon task is not one and what a service would need.
5. **Phase 5 — Android/OHOS.** Move the fd consumer into the service process.
   Dart keeps `VpnTunnelMode.system` on the old path until on-device verified.
   Note the shape differs from the desktops: Android's `VpnService` process *is*
   the out-of-process boundary the platform keeps alive, so the core belongs
   there in-process through the C ABI rather than in a child daemon that would
   have to inherit the descriptor across an `exec`.
6. **Phase 6 — prebuilts, then delete.** The release pipeline from §8, and then
   the Swift `Native/` core and the Dart data plane go away; Dart keeps
   login/resources/UI, and the golden fixtures stay as the contract test for
   whatever comes next.

Rollback is per platform and per phase: the Dart path is untouched until
Phase 6, and iOS has two native modes side by side until then.

## 10. Risks

- **Canonical JSON.** The signature covers `jsonEncode`'s exact bytes: key
  insertion order, no whitespace, `"`/`\`/the five short escapes, other
  control characters as lowercase `\u00xx`, U+007F and non-ASCII passed
  through raw. A serializer that sorts keys or escapes differently produces a
  valid request the gateway rejects. Mitigated by making `json.rs` a
  fixture-driven test target before anything else is written.
- **Composition is where ports break.** Every piece of the relay path had
  passing unit tests while nothing called them. Golden fixtures prove a function
  matches the reference; only an end-to-end test proves the functions are wired
  together. `sangfor-host/tests/end_to_end.rs` exists for that reason, and any
  new protocol layer should land with a case in it.
- **Portable types are only portable if every target compiles them.** Three
  separate bugs in this repo were the same bug: code that was correct on the
  architecture it was written on and wrong on another. `libc::ioctl`'s request
  parameter is `c_ulong` on glibc and `c_int` on musl. `c_char` is `i8` on
  x86-64 Linux and `u8` on aarch64, so `tun.rs` writing an `i8` into
  `ifreq.name` compiled for one and not the other. And an accepted TCP socket
  inherits non-blocking mode from its listener on Windows but not on Linux. Each
  survived because the test matrix compiled the module for only one of the two
  shapes. The rule this argues for: when a `cfg` or a feature gates a module,
  CI has to build that module for *every* target where the underlying C type
  differs — the cross-compile step now builds `sangfor-tun/tun` for an aarch64
  target as well as an x86-64 one, which is what would have caught the second.
- **`rustls-rustcrypto` is an alpha crate.** Less travelled than ring, and its
  API has already moved once. Pinned in `Cargo.lock`, compiled for all five
  targets on every push, and isolated behind `sangfor_host::Connector` so a
  provider swap touches one crate.
- **Verification still needs a real gateway.** Fixtures and a fake gateway prove
  the implementations agree with each other; only an authorized deployment proves
  the protocol itself is right. Every phase ships behind a flag for that reason.
- **Binary size** is measured, not estimated: 1.05 MB for a binary linking all
  four crates, against a ~50 MB `.appex` budget.

