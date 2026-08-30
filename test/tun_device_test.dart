import 'dart:io';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('linux TUN open rejects names outside interface limits', () async {
    if (!Platform.isLinux) {
      await expectLater(
        TunDevice.open(name: 'test'),
        throwsA(isA<UnsupportedError>()),
      );
      return;
    }
    await expectLater(
      TunDevice.open(name: ''),
      throwsA(isA<ArgumentError>()),
    );
    await expectLater(
      TunDevice.open(name: 'this-name-is-way-too-long'),
      throwsA(isA<ArgumentError>()),
    );
  });
}
