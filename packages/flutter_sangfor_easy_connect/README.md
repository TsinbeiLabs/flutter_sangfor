# flutter_sangfor_easy_connect

Easy Connect-specific connector for the `flutter_sangfor` package family.

Protocol and platform tunnel implementation will remain isolated here and will
not be added to the product-neutral root package.

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgments

The EasyConnect protocol implementation is an independent clean-room
reimplementation of publicly observed wire behavior; no source code is copied
from the following projects, which were used as behavior references:

- [GayStudio/EasierConnect](https://github.com/GayStudio/EasierConnect)
  — EasyConnect XML control plane reference.
- [lyc8503/NJUConnect](https://github.com/lyc8503/NJUConnect)
  — EasyConnect control plane reference.
- [Yan233th/SHIEP-Pipeline](https://github.com/Yan233th/SHIEP-Pipeline) (AGPL-3.0, Rust)
  — EasyConnect token, Query-IP, RX/TX stream, heartbeat.
