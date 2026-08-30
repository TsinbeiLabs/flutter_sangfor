import 'dart:io';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('android vpn device rejects non-android platforms', () async {
    if (Platform.isAndroid) {
      // On a real device this would start the permission flow; skipped in
      // unit tests to avoid system dialogs.
      return;
    }
    await expectLater(
      AndroidVpnDevice.start(address: '10.0.0.2', prefixLength: 32),
      throwsA(isA<UnsupportedError>()),
    );
    expect(await AndroidVpnDevice.isPrepared, isFalse);
    expect(await AndroidVpnDevice.requestPermission(), isFalse);
  });
}
