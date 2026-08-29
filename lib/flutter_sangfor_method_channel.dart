import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'flutter_sangfor_platform_interface.dart';
import 'src/models.dart';

/// An implementation of [FlutterSangforPlatform] that uses method channels.
class MethodChannelFlutterSangfor extends FlutterSangforPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('flutter_sangfor');

  @override
  Future<SangforSession> connect({
    required Uri server,
    required String username,
    required String password,
    String? loginDomain,
    SangforAuthType authType = SangforAuthType.password,
  }) async {
    final result = await methodChannel.invokeMapMethod<String, Object?>(
      'connect',
      <String, Object?>{
        'server': server.toString(),
        'username': username,
        'password': password,
        'loginDomain': loginDomain,
        'authType': authType.value,
      },
    );
    return SangforSession.fromMap(result ?? const <String, Object?>{});
  }

  @override
  Future<void> disconnect() => methodChannel.invokeMethod<void>('disconnect');

  @override
  Future<SangforConnectionState> getState() async {
    final value = await methodChannel.invokeMethod<String>('getState');
    return SangforConnectionState.fromValue(value);
  }
}
