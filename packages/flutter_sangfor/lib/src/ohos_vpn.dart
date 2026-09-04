import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'fd_packet_device.dart';
import 'tunnel_io.dart';

/// HarmonyOS NEXT / OpenHarmony system VPN adapter: starts the
/// `SangforVpnExtAbility` (a `VpnExtensionAbility`) declared by the host
/// app, receives the established TUN file descriptor, and surfaces it as a
/// [SangforPacketDevice].
///
/// The VPN extension runs in its own process; the plugin transfers the
/// descriptor to this process over an AF_UNIX socket (SCM_RIGHTS) before
/// this method returns, so the read/write loops can run here directly
/// through FFI — the same shape as [AndroidVpnDevice], where the app
/// process owns the tunnel fd.
class OhosVpnDevice implements SangforPacketDevice {
  OhosVpnDevice._(this._device);

  static const MethodChannel _channel = MethodChannel('flutter_sangfor');

  final FdPacketDevice _device;

  static bool get _isOhos => !kIsWeb && Platform.operatingSystem == 'ohos';

  @override
  Stream<Uint8List> get incoming => _device.incoming;

  @override
  bool get isClosed => _device.isClosed;

  /// Starts the system VPN interface.
  ///
  /// [routes] entries use the `<address>/<prefix>` notation, for example
  /// `10.0.0.0/8`; the system applies them to the `vpn-tun` interface.
  /// Throws a [StateError] when the user declines the VPN authorization
  /// dialog or the extension does not come up.
  static Future<OhosVpnDevice?> start({
    required String address,
    required int prefixLength,
    List<String> routes = const <String>[],
    List<String> dnsServers = const <String>[],
    List<String> searchDomains = const <String>[],
    int mtu = 0,
  }) async {
    if (!_isOhos) {
      throw UnsupportedError('OhosVpnDevice requires OpenHarmony');
    }
    final fd = await _channel.invokeMethod<int>('vpnStart', <String, Object?>{
      'address': address,
      'prefixLength': prefixLength,
      'routes': routes,
      'dnsServers': dnsServers,
      'searchDomains': searchDomains,
      'mtu': mtu,
    });
    if (fd == null || fd < 0) {
      throw StateError('VpnConnection.create returned no descriptor');
    }
    final device = await FdPacketDevice.fromFd(fd);
    return OhosVpnDevice._(device);
  }

  /// Whether the VPN permission has been granted. OpenHarmony has no
  /// pre-grant step — the system shows the authorization dialog when the
  /// VPN extension starts for the first time — so this only reports
  /// platform support.
  static Future<bool> get isPrepared async {
    if (!_isOhos) return false;
    final prepared = await _channel.invokeMethod<bool>('vpnPrepare');
    return prepared ?? true;
  }

  /// Requests the system VPN permission. The authorization dialog appears
  /// as part of the first [start], so this is a no-op that reports platform
  /// support.
  static Future<bool> requestPermission() async {
    if (!_isOhos) return false;
    return await _channel.invokeMethod<bool>('vpnRequestPermission') ?? true;
  }

  @override
  Future<void> send(Uint8List packet) => _device.send(packet);

  @override
  Future<void> close() async {
    await _device.close();
    await _channel.invokeMethod<void>('vpnStop');
  }
}
