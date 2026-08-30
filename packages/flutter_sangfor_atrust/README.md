# flutter_sangfor_atrust

aTrust-specific connector and protocol implementation for the
`flutter_sangfor` package family.

The package currently provides HTTPS discovery of the server manifest and
advertised authentication methods. It does not include Sangfor SDK binaries,
disable certificate verification, or implement the authentication/tunnel
protocol yet.

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgments

The aTrust protocol implementation is an independent clean-room
reimplementation of publicly observed wire behavior; no source code is
copied from [Mythologyli/zju-connect](https://github.com/Mythologyli/zju-connect)
(AGPL-3.0), which was used as a behavior reference for the L3 tunnel,
per-flow auth, conntrack, and TCP tunnel.
