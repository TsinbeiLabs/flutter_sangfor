import 'dart:io';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('wintun open reports a missing DLL instead of crashing', () async {
    if (!Platform.isWindows) {
      // The guard itself is the test on other platforms.
      await expectLater(
        WintunDevice.open(name: 'test', dllPath: 'missing-wintun.dll'),
        throwsA(isA<UnsupportedError>()),
      );
      return;
    }
    await expectLater(
      WintunDevice.open(name: 'test', dllPath: 'missing-wintun.dll'),
      throwsA(
        isA<StateError>().having(
          (error) => error.message,
          'message',
          contains('wintun.dll not found'),
        ),
      ),
    );
  });
}
