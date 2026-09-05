## 0.0.5

* Lockstep release with `flutter_sangfor` 0.0.5.

## 0.0.4

* Lockstep release with `flutter_sangfor` 0.0.4.

## 0.0.3

* Add `matchTcpRoute(..., includeL3Preferred)` and
  `ATrustTunnel.dialTcp(..., includeL3Preferred)` so callers without an L3
  data plane can still reach L3-preferred resources through TCP tunnels.
* Map "session is invalid" resume errors to `VpnSessionExpiredException`
  so stored snapshots fall back to a password login.
* Carry anti-MITM identity data onto tunnel connections and accept
  self-signed node certificates when no digests are advertised.
* Present the Linux desktop (aTrustTray) platform fingerprint on every
  aTrust HTTP endpoint.
## 0.0.2

* Bump the pointycastle dependency to ^4.0.0.
* Document the packet, conntrack, and anti-MITM APIs.
* Add an example covering the connector and `dialTcp`.

## 0.0.1

* Add the aTrust connector: manifest and authentication-method discovery,
  password exchange with server-provided RSA parameters, SMS verification,
  TOTP/RADIUS/code challenges, Cookie/SID persistence, and an end-to-end
  login coordinator.
* Add node-group parsing (WAN/LAN) and credential-free session snapshots.
* Add the L3 tunnel with keep-alives and dual packet-stream demux.
* Add TCP tunnel channels with `dialTcp` for user-space sockets exposed via
  the shared `SangforTcpStream` boundary.
