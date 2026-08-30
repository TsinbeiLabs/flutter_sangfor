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
