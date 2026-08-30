import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/services.dart';

import 'tunnel_io.dart';

/// A [SangforPacketDevice] backed by a local TCP connection to the
/// Network Extension process. The NEPacketTunnelProvider writes packets
/// from `packetFlow` into the socket, and reads packets from the socket
/// to inject into `packetFlow`.
class IosVpnDevice implements SangforPacketDevice {
  IosVpnDevice._(this._socket);

  static const MethodChannel _channel = MethodChannel('flutter_sangfor');
  static const int _defaultIpcPort = 6400;

  final Socket _socket;
  final StreamController<Uint8List> _incoming =
      StreamController<Uint8List>.broadcast();
  StreamSubscription<Uint8List>? _subscription;
  bool _closed = false;

  @override
  Stream<Uint8List> get incoming => _incoming.stream;

  @override
  bool get isClosed => _closed;

  /// Starts the iOS VPN tunnel via the NetworkExtension framework and
  /// returns a packet device connected to the NE via local TCP.
  ///
  /// [address], [prefixLength], [routes], [dnsServers] configure the
  /// tunnel network settings.
  static Future<IosVpnDevice> start({
    required String address,
    required int prefixLength,
    List<String> routes = const <String>[],
    List<String> dnsServers = const <String>[],
    List<String> searchDomains = const <String>[],
    int mtu = 0,
  }) async {
    if (!Platform.isIOS) {
      throw UnsupportedError('IosVpnDevice requires iOS');
    }
    final started =
        await _channel.invokeMethod<bool>('vpnStart', <String, Object?>{
      'address': address,
      'prefixLength': prefixLength,
      'routes': routes,
      'dnsServers': dnsServers,
      'searchDomains': searchDomains,
      'mtu': mtu,
    });
    if (started != true) {
      throw StateError('Failed to start the iOS VPN tunnel');
    }
    // The NE listens on loopback for the Dart-side connection. Wait briefly
    // for the socket to become available.
    Object? lastError;
    for (var attempt = 0; attempt < 20; attempt++) {
      try {
        final socket = await Socket.connect(
          InternetAddress.loopbackIPv4,
          _defaultIpcPort,
          timeout: const Duration(milliseconds: 500),
        );
        return IosVpnDevice._create(socket);
      } on Object catch (error) {
        lastError = error;
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
    }
    throw StateError('Failed to connect to the NE IPC socket: $lastError');
  }

  static IosVpnDevice _create(Socket socket) {
    final device = IosVpnDevice._(socket);
    device._startListening();
    return device;
  }

  /// Whether the VPN permission has been granted to this app.
  static Future<bool> get isPrepared async {
    if (!Platform.isIOS) return false;
    final prepared = await _channel.invokeMethod<bool>('vpnPrepare');
    return prepared ?? false;
  }

  @override
  Future<void> send(Uint8List packet) async {
    if (_closed) return;
    // 4-byte length prefix + packet.
    final header = ByteData(4)..setUint32(0, packet.length, Endian.big);
    _socket.add(header.buffer.asUint8List());
    _socket.add(packet);
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _subscription?.cancel();
    if (!_incoming.isClosed) {
      unawaited(_incoming.close());
    }
    _socket.destroy();
    await _channel.invokeMethod<void>('vpnStop');
  }

  void _startListening() {
    final buffer = BytesBuilder();
    _subscription = _socket.listen(
      (chunk) {
        buffer.add(chunk);
        final bytes = buffer.toBytes();
        var offset = 0;
        while (offset + 4 <= bytes.length) {
          final length = ByteData.sublistView(bytes, offset, offset + 4)
              .getUint32(0, Endian.big);
          if (offset + 4 + length > bytes.length) break;
          final packet = Uint8List.fromList(
            bytes.sublist(offset + 4, offset + 4 + length),
          );
          if (!_incoming.isClosed) {
            _incoming.add(packet);
          }
          offset += 4 + length;
        }
        buffer.clear();
        if (offset < bytes.length) {
          buffer.add(bytes.sublist(offset));
        }
      },
      onDone: () {
        if (!_incoming.isClosed) {
          unawaited(_incoming.close());
        }
      },
      onError: (Object _) {
        if (!_incoming.isClosed) {
          unawaited(_incoming.close());
        }
      },
    );
  }
}
