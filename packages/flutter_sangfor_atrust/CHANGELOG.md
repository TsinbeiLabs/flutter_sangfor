## 0.0.12

* Depend on flutter_sangfor 0.0.12, which reports Android VPN revocations.

## 0.0.11

* Depend on flutter_sangfor 0.0.11 with the iOS build compatibility fixes.

## 0.0.10

* Lockstep release with `flutter_sangfor` 0.0.10.
## 0.0.9

* Lockstep release with `flutter_sangfor` 0.0.9.
## 0.0.8

* Lockstep release with `flutter_sangfor` 0.0.8.

## 0.0.7

* Add `ATrustTunnel.plan()` and `ATrustTunnel.buildSessionPlan()`: resolve the
  node topology and the client virtual IP without holding an L3 connection
  open, then hand the result to an out-of-process data plane. Two live tunnels
  for one session make the gateway drop one, so a caller that plans must not
  also start.
* Add `ATrustSessionPlan`, the App Group hand-off document, and
  `ATrustAntiMitmData.certificateDigests` so the native transport pins node
  certificates exactly like the Dart one.
* Inherits the TCP terminator ACK fix from `flutter_sangfor` 0.0.7.
## 0.0.7

* Add `ATrustTunnel.plan()` and `ATrustTunnel.buildSessionPlan()`: resolve the
  node topology and the client virtual IP without holding the L3 connection
  open, so an out-of-process data plane (the iOS packet tunnel extension) can
  take over. Two live tunnels for one session make the gateway drop one.
* Add `ATrustSessionPlan`, the App Group hand-off document, and
  `ATrustAntiMitmData.certificateDigests` for the native certificate pin check.
## 0.0.6

* Add `ATrustTcpTermination` and `ATrustPacketTunnel`: TCP flows the gateway
  publishes for the TCP tunnel only (`enableTCPPrefL3` false) are terminated
  locally and relayed through `ATrustTunnel.dialTcp` instead of being dropped
  as unrouted. That drop is what turned system mode into a black hole on every
  platform without a system proxy.
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
