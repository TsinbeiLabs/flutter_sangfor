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
}
