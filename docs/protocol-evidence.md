# Protocol evidence matrix

This document separates observed behavior from implementation assumptions. It
must be updated only from public documentation or captures made against an
authorized deployment.

| Area | Current evidence | Status | Required next evidence |
| --- | --- | --- | --- |
| Manifest discovery | Existing offline HTTP fixtures | synthetic | Authorized response fixture |
| Auth configuration | Existing offline HTTP fixtures | synthetic | Authorized response fixture |
| Password exchange | Existing request/response tests | synthetic | Confirm field names and encryption parameters |
| Secondary authentication | Existing request/response tests | synthetic | Confirm each deployment-specific challenge |
| Client resources | Existing resource parser tests | synthetic | Confirm route, DNS, and node endpoint semantics |
| Cookie/SID continuity | Cookie-jar tests | synthetic | Confirm expiry and invalidation responses |
| Tunnel handshake | zju-connect reference port; unit-tested parser | synthetic | Authorized handshake capture |
| Tunnel frame envelope | zju-connect reference port; unit-tested codec | synthetic | Authorized byte-level capture |
| L3 IP packet parsing | Standard IPv4/TCP/UDP headers (RFC 791/793/768) | standard | N/A — RFC-defined behavior |
| L3 conntrack TCP state machine | zju-connect reference port; unit-tested | synthetic | Authorized conntrack observation |
| L3 data payload framing | zju-connect reference port; unit-tested | synthetic | Authorized byte-level capture |
| TCP tunnel (SOCKS5-like) | zju-connect reference port; unit-tested | synthetic | Authorized tunnel capture |
| Anti-MITM challenge/signature | Unit-tested AES-CBC/HMAC-SHA256 verification | synthetic | Authorized challenge capture |
| Anti-MITM certificate pinning | Unit-tested digest comparison; SecureSocket integration | synthetic | Authorized certificate digest |
| Heartbeat and reconnect | Unit-tested schedulers and policies | synthetic | Authorized lifecycle observation |
| EasyConnect login flow | Unit-tested XML endpoints | synthetic | Authorized response fixture |
| EasyConnect conf.csp/rclist.csp | Reference-guided XML parsers; unit-tested | synthetic | Authorized response fixture |
| EasyConnect tunnel token | Reference-guided derivation; unit-tested | synthetic | Authorized TLS session capture |
| EasyConnect Query-IP/stream handshake | Reference-guided message builders; unit-tested | synthetic | Authorized handshake capture |
| EasyConnect heartbeat | Reference-guided ICMP builder; checksum-verified | synthetic | Authorized heartbeat capture |
| EasyConnect minimal TLS stack | RFC 4346/5246 implementation; verified against an in-test TLS server (RSA fixture) plus tamper/MAC tests | rfc-selfconsistent | Authorized server interop; real TLS stack interop |
| aTrust tunnel driver | Full runtime (nodes, Query-IP, per-flow auth, conntrack, heartbeats) against scripted sockets | synthetic | Authorized lifecycle capture |

## Current conclusion

The aTrust L3 and TCP tunnel wire formats are implemented from behavior
observed in the public `Mythologyli/zju-connect` reference (AGPL-3.0,
reference-only) and covered by unit tests that assert byte-level framing.
The EasyConnect data plane
(token derivation, Query-IP, RX/TX stream handshake, heartbeat, control
frames) follows the public EasierConnect/NJUConnect/SHIEP-Pipeline
references. Both remain labeled `synthetic` until validated against an
authorized deployment: the byte formats are implemented from open source
observations, not from captures of the target servers.

Standard protocol elements (IPv4/TCP/UDP header parsing, internet checksums)
follow their RFC definitions and are not Sangfor-specific.

## Capture requirements

For a future authorized test session, record only:

- request method, path, query names, and redacted body shape;
- response status, headers after secret removal, and redacted body shape;
- byte lengths and direction of tunnel chunks;
- timing of handshake, heartbeat, close, and reconnect events.

Do not record passwords, challenge codes, cookies, SIDs, CSRF values, access
tokens, private keys, production hostnames, or user identifiers.

## aTrust reference notes

The public reference repository is `Mythologyli/zju-connect`, with aTrust
code under `client/atrust`. It is licensed AGPL-3.0 and is reference-only
for this project; no source code is copied here.

Key implemented behaviors:

- L3 tunnel initial handshake: `0x05 0xD0` method response, `0x53` auth
  envelope with SID JSON, VIP header (`0x05 status reserved addrType`), and
  6/18/22-byte VIP payloads.
- L3 per-flow auth: JSON auth requests with `conntrackHash` and uppercase
  hex HMAC-SHA256 `xRequestSig`, pending-packet caching and replay.
- L3 data frames: version/cmd/token-length/token/reserved/count/packets.
- Conntrack TCP state machine: reset → SYN → established → FIN → closed
  with protocol-specific TTLs.
- TCP tunnel: SOCKS5-like `0x05 0x01` handshake with JSON auth and
  `0x01 0x00 len` data framing plus `0x01 0x01` EOF.
- Anti-MITM: AES-CBC challenge verification, HMAC-SHA256 response
  signature, and SHA256 certificate identity digests.

## EasyConnect reference notes

The public reference repositories are `GayStudio/EasierConnect` (mirror of
the original NJUConnect), `lyc8503/NJUConnect`, and `Yan233th/SHIEP-Pipeline`
(Rust). They are reference-only for this project; no source code is copied.

The following behaviors are implemented from those references but are not
yet verified against the target deployments:

- The control plane uses XML endpoints including `login_auth.csp`,
  `login_psw.csp`, `login_sms.csp`, `login_sms1.csp`, `login_token.csp`,
  `conf.csp`, and `rclist.csp`.
- Login state is carried by a `TWFID` cookie. The flow may require password,
  SMS, TOTP, or client-certificate continuation.
- The token is derived from the first 31 hex characters of the TLS
  server session id plus a NUL byte, concatenated with the 16-byte TWFID.
- Query-IP (op 0), TX stream (op 5), RX stream (op 6), and command heartbeat
  (op 3) use 64-byte little-endian handshake messages.
- Data transport uses separate send and receive TLS connections carrying
  raw IPv4 packets with no additional framing; the TLS record layer is
  the only framing.
- The server may answer handshakes with 40-byte native control frames
  starting with the `AABB` magic followed by a little-endian control code.
- The TX heartbeat is a 76-byte ICMP echo request carrying the marker
  string `SANGFORSCSIPCLIENT`, the 16-byte session (TWFID), 8 random bytes,
  and `L3VPN\0`.
- The session is maintained with periodic `update_session.csp` requests.

The data-channel TLS is implemented in this project as a minimal RFC
4346/5246 client (`EasyConnectTlsClient`) because dart:io cannot emit the
required hello shape. It supports TLS 1.1 and 1.2 with RSA key exchange and
the RC4-SHA / AES128-CBC-SHA suites, both PRFs, per-record explicit CBC IVs,
and Finished verification per the RFC text. Correctness is verified against
an in-process TLS server sharing the same primitives plus a real
openssl-generated RSA certificate fixture; interop with production servers
or third-party TLS stacks is not yet verified and is the main remaining
compatibility risk. The client fails closed: connections require a caller
certificate validator unless `allowUnverifiedCertificates` is explicitly
enabled (testing only). The tunnel token is derived from the ServerHello
session id of the token connection, which the minimal client surfaces
directly.

These observations map to `flutter_sangfor_easy_connect` as a separate XML
control plane, token/session model, dual-channel transport, resource parser,
keepalive, and platform packet adapter. They must not be mixed into the
aTrust JSON implementation.

The references contain configurations that disable certificate verification
for reverse-engineering compatibility. This project must not copy that
behavior: production code must use platform certificate validation, with
any exceptional certificate requirement represented as explicit
user-provided client credentials and tested independently.

## Userspace data plane and platform adapters

The userspace layer is implemented against the governing RFCs directly:

- `SangforSocks5Server` implements RFC 1928 no-auth CONNECT (greeting
  negotiation, IPv4/IPv6/domain address types, reply codes) and is verified
  end to end against real local TCP sockets in tests.
- `EasyConnectTcpProxy` synthesizes TCP client-role connections over the
  raw-IP plane per RFC 793: three-way handshake with MSS exchange, cumulative
  ACKs, go-back-N retransmission with exponential backoff, zero-window
  persist probing, out-of-order reassembly, FIN/RST teardown, and 32-bit
  sequence arithmetic. UDP flows (RFC 768) and the DNS resolver (RFC 1035
  A queries with compression-pointer name skipping) run over the same
  plane. Verification is against a scripted in-test TCP peer; real-server
  interoperability is not yet covered.
- `WintunDevice` follows the official Wintun API reference (CreateAdapter /
  StartSession / ReceivePacket + read-wait event / AllocateSendPacket /
  SendPacket / EndSession). Only the official signed `wintun.dll` from
  wintun.net is loaded (per its more permissive bundled license; the GPL
  source must not be rebuilt or redistributed).
- `TunDevice` follows the Linux TUN interface (`/dev/net/tun`, `TUNSETIFF`
  ioctl with `IFF_TUN | IFF_NO_PI`, 16-byte `ifr_name` + `ifr_flags` ifreq
  layout).
- Both adapters need elevation/privileges and have not yet been exercised
  against real network interfaces; their failure paths are covered by unit
  tests only.
