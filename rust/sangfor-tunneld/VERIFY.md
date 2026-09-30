# Verifying `sangfor-tunneld` against a real gateway

Everything in `rust/` is tested without a gateway: 221 Rust tests, including the
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

# Stage 3: an installed daemon, driven from an ordinary shell. The check that
# the elevation prompt is actually gone.
./tool/verify_tunneld.ps1 -Installed -Plan plan.json
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
| `--print-install` | The generated logon task does not ask for elevation (`/RL HIGHEST`), so it would run exactly as unelevated as the app and fail the same way it does today. |
| Dry run | Starts the daemon **idle** on an in-memory device, discovers its control port from its log, then drives a whole session lifecycle over the socket. |

The dry run is launched with no `--plan`, which is the shape an installed daemon
has: it starts at logon with nothing to do and is handed a session later. It then
checks, in order, that the daemon reports no session; that a tokenless `status`
**and** a tokenless `start` are both refused; that `start` runs a session from a
plan it was pointed at; that `stopSession` ends the session **without ending the
process**; and that a *second* session starts on the same process. Finally `stop`
must exit 0.

That second session is the check that matters. One elevated process has to serve
every connect/disconnect cycle, and a second `start` breaks quietly if the device,
the snapshot, or the configurator thread stayed bound to the first one — which
presents as a reconnect that hangs, not as an error.

This is the same exchange the Rust subprocess tests and the Dart client test run,
so if it passes here the binary, the protocol, and the token gate are all working
on this machine.

`-TestAdapter` additionally creates and removes a throwaway wintun adapter, which
proves the driver installs. It needs elevation and briefly adds a network adapter.

## Stage 2 — a real tunnel

Needs an elevated shell, a session plan, and routes.

### Getting a session plan

The plan is what the Dart control plane produces after login: credentials, signing
key, node endpoints, published resources, anti-MITM pins. `ATrustTunnel
.buildSessionPlan(...)` builds it, and the app already calls that for the iOS
packet tunnel extension and for `sangfor-tunneld`.

A **debug build of the app writes one for you**. `_debugExportSessionPlan` in
`vpn_connection_service.dart` runs at the end of a successful system-mode
connect, writes the plan to `<temp>/sangfor-session-plan.json`, and prints the
`verify_tunneld.ps1` command line with the routes it just installed:

```
[vpn] session plan written to C:\Users\you\AppData\Local\Temp\sangfor-session-plan.json
[vpn]   it is a CREDENTIAL -- delete it after verifying, and never commit or paste it
[vpn]   verify with:
[vpn]     ./tool/verify_tunneld.ps1 -Plan "..." -Routes 10.0.0.0/8 -Routes ...
```

So the sequence is: connect in a debug build, copy the printed command, run it
from an elevated shell. It is guarded by `kDebugMode` because the plan *is* a
credential — a release or profile build never writes one.

To export by hand instead, write the same document from anywhere that has a
resolved tunnel:

```dart
final plan = tunnel.buildSessionPlan(/* the same arguments the daemon path uses */);
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
| `sessionRunning` false | The daemon has no session. Either `start` was never sent or the session already ended — look at `fatal` and the log to tell which. Distinct from `active` false, which also covers a session that is still handshaking. |
| `fatal` set | The session is dead. Re-login and re-export the plan; restarting with the same plan will not help. The daemon stays up, so `start` again with a fresh plan rather than relaunching it. |

## Installing it, and stage 3

The reason any of this matters on Windows is that creating a wintun adapter needs
an elevated process, and the app runs `asInvoker`. Stages 1 and 2 both run the
daemon in the foreground of the current shell, so they inherit whatever privilege
that shell has and prove nothing about the app's situation.

Installing puts the daemon in an elevated **logon task**:

```powershell
# Once, from an elevated shell.
sangfor-tunneld --install

# Then either log off and on, or start it now:
schtasks /Run /TN SangforTunnel
```

`--install` writes `%LOCALAPPDATA%\sangfor-tunneld\host.json` — holding a freshly
generated control token, a fixed port (7166), and a log path — and registers the
task with `/RL HIGHEST`. `--print-install` shows both commands without running
them. It is a logon task and not a Windows service on purpose; `docs/rust-core.md`
§6.2 records why, and the short version is that a service runs as LocalSystem in
session 0, where it can neither identify its control client nor hold a per-user
token.

Stage 3 then drives that daemon **from an ordinary shell**:

```powershell
./tool/verify_tunneld.ps1 -Installed
./tool/verify_tunneld.ps1 -Installed -Plan plan.json    # start a real session
```

It warns if the shell happens to be elevated, because then a success proves
nothing. Without `-Plan` it confirms the daemon is reachable and idle, which is
what an app expects to find. With one, it starts a session, waits for the
interface to come up, prints the daemon's log, and ends with `stopSession` — not
`stop`, because the daemon is installed and the next connect wants it.

A session started here, from an unelevated shell, in a daemon that opened a real
adapter, is the user-visible win: it is what the app will do.

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
- **Installing.** `--install` needs an elevated shell, so it is never run here;
  stage 1 prints the command instead and checks that it asks for elevation. The
  quoting of that command *is* tested — in Rust, by rendering it and parsing it
  back into argv — because a path with a space in it is every install path there
  is, and a naive quoting function truncates it at the first one.
- **Running as a Windows service.** Deliberately not built: a service runs as
  LocalSystem in session 0, where the loopback control socket can neither
  identify its peer nor hold a per-user token, and where the binary would need an
  SCM dispatcher that cannot be tested without installing it. The logon task is
  the mechanism that is both sufficient and testable. §6.2 has the full argument.
- **The daemon surviving logoff.** A logon task ends with the session. If the
  tunnel has to outlive that, it needs the service path above, and with it a
  named pipe with `GetNamedPipeClientProcessId` behind it.
