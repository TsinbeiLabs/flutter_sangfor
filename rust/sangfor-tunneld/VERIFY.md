# Verifying `sangfor-tunneld` against a real gateway

Everything in `rust/` is tested without a gateway: 153 Rust tests, including the
whole data plane driven end to end against a fake one that replays the recorded
handshake from the golden fixture. That proves the implementations agree with each
other. It cannot prove the protocol is right — only an authorized deployment can
do that, and only on a machine with elevation and the signed driver.

`tool/verify_tunneld.ps1` is the one-command version of that test.

```powershell
# Stage 1: does this machine have what it needs? No elevation, no gateway.
./tool/verify_tunneld.ps1

# Stage 2: a real tunnel. Elevated shell, an exported plan, routes.
./tool/verify_tunneld.ps1 -Plan plan.json -Routes 10.0.0.0/8 -Dns 10.0.0.53 `
    -Probe https://portal.example.edu/
```

Exit code is 0 when every check passed, 1 when any failed. Warnings do not fail
the run; they mark things worth reading.

## Stage 1 — preflight

Runs by default and needs nothing but the built binary. It checks:

| Check | What a failure means |
|---|---|
| Elevation | A warning only. Preflight and `--dry-run` work unelevated; a real adapter does not. |
| `wintun.dll` | A warning during preflight, a failure with `-Plan`. Stage it with the app's `app/scripts/stage_wintun.ps1`, which pins the archive SHA-256. It must be the signed DLL from wintun.net. |
| `--help` exits 0 | The binary is not runnable on this machine. |
| Dry run | Starts the daemon on an in-memory device, discovers its control port from its log, pings it, reads a snapshot, confirms a tokenless `status` is **refused**, and confirms `stop` exits 0. |

That last block is the same exchange the Rust subprocess tests and the Dart
client test run, so if it passes here the binary, the protocol, and the token gate
are all working on this machine.

`-TestAdapter` additionally creates and removes a throwaway wintun adapter, which
proves the driver installs. It needs elevation and briefly adds a network adapter.

## Stage 2 — a real tunnel

Needs an elevated shell, a session plan, and routes.

### Getting a session plan

The plan is what the Dart control plane produces after login: credentials, signing
key, node endpoints, published resources, anti-MITM pins. `ATrustTunnel
.buildSessionPlan(...)` builds it, and the app already calls that for the iOS
packet tunnel extension (`vpn_connection_service.dart`, around the
`IosVpnDevice.writeSessionPlan` call).

To export one for this script, write that same document to a file — for example
from a debug affordance in the app:

```dart
final plan = tunnel.buildSessionPlan(/* the same arguments the iOS path uses */);
await File(path).writeAsString(plan.encode());
```

A plan is a **credential**. It carries the signing key. Do not commit it, do not
paste it into an issue, and delete it after verifying. The script passes it to the
daemon as a file rather than on the command line for the same reason: an argument
list is visible to every process on the machine.

Plans also expire. If stage 2 reports the session died, log in again and
re-export before concluding anything about the tunnel.

### Routes

The daemon installs the CIDRs it is given and deliberately does not decide for
itself. Which destinations belong in the tunnel is a product decision — the app
derives it from the gateway's published resources *and* from the user's route
policy and custom entries — so `-Routes` should be whatever the app would have
installed. `computeSystemRouteCidrs` in `vpn_connection_service.dart` is the
reference.

Domain-published resources cannot be expressed as routes; the app resolves them to
addresses and passes the reverse mapping to the terminator as `dialHosts` in the
plan. That is already in the plan, so nothing extra is needed here.

### What stage 2 reports

It waits for the gateway to assign a virtual IP, then reports four views of the
same tunnel, because a failure usually shows up in only one of them:

1. **What the daemon says** — the `status` snapshot: `virtualIp`,
   `interfaceConfigured` and `interfaceError`, `connectFailures`, and `fatal`.
2. **What the operating system says** — the adapter's state and address, and the
   routes actually installed through it.
3. **That the tunnel does not capture its own gateway** — every node endpoint in
   the plan is checked against every installed route. A route that covers a node
   sends the tunnel's traffic into the tunnel; the deadlock presents as a network
   outage. The daemon excludes them before installing and logs it when it does, so
   a failure here means the exclusion was wrong, not that the routes were.
4. **Whether traffic moved** — after the optional `-Probe`, the counters:
   `routed` (forwarded as raw IP), `terminated` (through the userspace TCP
   terminator, which is the path for resources the gateway publishes as
   TCP-tunnel-only), `unrouted` (no published resource covers it), `ingress`, and
   `deviceDropped`.

Then it prints the daemon's own log and tears down.

`-Probe` runs **outside** the daemon, so a success means the operating system
really is routing through the adapter rather than the tunnel merely believing it
is. Pass a `host:port` for a TCP connect or an `http(s)://` URL for a request.

### Reading the counters

| Symptom | Likely cause |
|---|---|
| `routed` and `terminated` both 0 | Nothing is using the tunnel. The probe went out another interface, or no route covers it. |
| `terminated` > 0, `routed` 0 | Every destination is TCP-tunnel-only. Expected on deployments like WHU's; this is the path the terminator exists for. |
| `unrouted` climbing | Packets are reaching the tunnel that no published resource covers. Either the route list is too wide or the resource list is stale. |
| `deviceDropped` > 0 | The tunnel is behind the stack and shedding packets. Looks like loss on the far side and is not. |
| `connectFailures` > 0 | The node could not be reached or its certificate did not match a pin. The daemon's log carries the reason, and a pin failure says so explicitly. |
| `fatal` set | The session is dead. Re-login and re-export the plan; restarting with the same plan will not help. |

## Troubleshooting

**`WintunCreateAdapter failed`** — not elevated, or the driver is blocked by
policy. The daemon turns this into a message that says so.

**`no wintun.dll`** — stage it beside the executable. The app's build already
does this for the Flutter runner; the daemon needs the same copy.

**The adapter appears but nothing routes** — check the operating system view in
stage 2's output. An interface configured with an address other than the one the
gateway assigned makes the stack drop the tunnel's packets as martians, which is
why the daemon waits for the assignment instead of guessing.

**A leaked daemon holds the port or locks the executable** — the script kills any
surviving `sangfor-tunneld` in its `finally` block, but a previous manual run may
not have. `Get-Process sangfor-tunneld | Stop-Process -Force`.

## What this does not cover

- **Android and OHOS.** Same binary, `--device fd` with a descriptor from the
  platform service. Those need on-device runs; nothing here exercises them.
- **iOS.** The packet tunnel extension keeps `NEPacketTunnelFlow` and does not run
  this binary at all. See `docs/rust-core.md` §6.
- **Running as a service.** Stage 2 runs the daemon in the foreground of an
  elevated shell. The service wrapper is not written yet; when it is, add a stage
  that installs it, starts it unelevated, and confirms the app can drive it
  without a UAC prompt — which is the actual user-visible win.
