import 'dart:io';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('macOS utun device rejects non-macos platforms', () async {
    if (Platform.isMacOS) return;
    await expectLater(
      UtunDevice.open(),
      throwsA(isA<UnsupportedError>()),
    );
  });

  test('iOS vpn device rejects non-ios platforms', () async {
    if (Platform.isIOS) return;
    await expectLater(
      IosVpnDevice.start(address: '10.0.0.2', prefixLength: 32),
      throwsA(isA<UnsupportedError>()),
    );
    expect(await IosVpnDevice.isPrepared, isFalse);
  });
}
