import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_sangfor/flutter_sangfor_method_channel.dart';
import 'package:flutter_sangfor/flutter_sangfor.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  MethodChannelFlutterSangfor platform = MethodChannelFlutterSangfor();
  const MethodChannel channel = MethodChannel('flutter_sangfor');

  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (MethodCall methodCall) async {
      if (methodCall.method == 'getState') {
        return 'disconnected';
      }
      return null;
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('getState', () async {
    expect(await platform.getState(), SangforConnectionState.disconnected);
  });

  test('getCapabilities maps the native response', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (MethodCall methodCall) async {
      if (methodCall.method == 'getCapabilities') {
        return <String, Object?>{
          'platform': 'android',
          'supportsVpn': true,
          'supportsTun': false,
          'supportsSocks5': false,
          'supportedAuthTypes': <String>['auth/psw'],
        };
      }
      return null;
    });

    expect(
      await platform.getCapabilities(),
      const SangforPlatformCapabilities(
        platform: 'android',
        supportsVpn: true,
        supportedAuthTypes: <SangforAuthType>[SangforAuthType.password],
      ),
    );
  });

  test('connect validates the server before invoking the channel', () async {
    expect(
      () => platform.connect(
        server: Uri.parse('not-a-server'),
        username: 'user',
        password: 'password',
      ),
      throwsArgumentError,
    );
  });

  test('connect maps a session returned by the channel', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (MethodCall methodCall) async {
      if (methodCall.method == 'connect') {
        return <String, Object?>{
          'state': 'connected',
          'virtualAddress': '10.0.0.2',
          'dnsServers': <String>['10.0.0.1'],
        };
      }
      return null;
    });

    expect(
      await platform.connect(
        server: Uri.parse('https://vpn.example.test'),
        username: 'user',
        password: 'password',
      ),
      const SangforSession(
        state: SangforConnectionState.connected,
        virtualAddress: '10.0.0.2',
        dnsServers: <String>['10.0.0.1'],
      ),
    );
  });
}
