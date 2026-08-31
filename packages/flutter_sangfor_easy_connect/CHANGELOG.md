## 0.0.3

* Lockstep release with `flutter_sangfor` 0.0.3.
## 0.0.2

* Bump the pointycastle dependency to ^4.0.0.
* Add an example covering the connector and `dialTcp`.

## 0.0.1

* Add the EasyConnect connector: login, conf parsing, a minimal TLS 1.1/1.2
  client, token exchange, RX/TX streams, and heartbeat keep-alive.
* Add TCP-over-L3 synthesis: IPv4/TCP/UDP packet building and parsing,
  DNS query/parse over the tunnel, and a retransmitting client TCP state
  machine with out-of-order reassembly and zero-window probing.
* Add `dialTcp` and a userspace TCP proxy over the L3 tunnel.
