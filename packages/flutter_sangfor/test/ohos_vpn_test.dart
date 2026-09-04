import 'dart:io';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('ohos vpn device rejects non-ohos platforms', () async {
    if (Platform.operatingSystem == 'ohos') {
      // On a real device this would trigger the system authorization
      // dialog; skipped in unit tests.
      return;
    }
    await expectLater(
      OhosVpnDevice.start(address: '10.0.0.2', prefixLength: 32),
      throwsA(isA<UnsupportedError>()),
    );
    expect(await OhosVpnDevice.isPrepared, isFalse);
    expect(await OhosVpnDevice.requestPermission(), isFalse);
  });
}
