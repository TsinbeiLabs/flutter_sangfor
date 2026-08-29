import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_sangfor/flutter_sangfor_platform_interface.dart';
import 'package:flutter_sangfor/flutter_sangfor_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockFlutterSangforPlatform
    with MockPlatformInterfaceMixin
    implements FlutterSangforPlatform {
  @override
  Future<SangforSession> connect({
    required Uri server,
    required String username,
    required String password,
    String? loginDomain,
    SangforAuthType authType = SangforAuthType.password,
  }) async =>
      const SangforSession(state: SangforConnectionState.connected);

  @override
  Future<void> disconnect() async {}

  @override
  Future<SangforConnectionState> getState() async =>
      SangforConnectionState.connected;
}

void main() {
  final FlutterSangforPlatform initialPlatform =
      FlutterSangforPlatform.instance;

  test('$MethodChannelFlutterSangfor is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelFlutterSangfor>());
  });

  test('getState', () async {
    FlutterSangfor flutterSangforPlugin = FlutterSangfor();
    MockFlutterSangforPlatform fakePlatform = MockFlutterSangforPlatform();
    FlutterSangforPlatform.instance = fakePlatform;

    expect(await flutterSangforPlugin.getState(),
        SangforConnectionState.connected);
  });
}
