import 'dart:io';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('ios vpn status maps native names', () {
    expect(IosVpnStatus.fromValue('connected'), IosVpnStatus.connected);
    expect(IosVpnStatus.fromValue('reasserting'), IosVpnStatus.reasserting);
    expect(IosVpnStatus.fromValue('disconnecting'), IosVpnStatus.disconnecting);
    expect(IosVpnStatus.fromValue('invalid'), IosVpnStatus.invalid);
  });

  test('ios vpn status falls back to invalid for unknown names', () {
    expect(IosVpnStatus.fromValue('nonsense'), IosVpnStatus.invalid);
    expect(IosVpnStatus.fromValue(''), IosVpnStatus.invalid);
  });

  test('ios vpn device rejects non-ios platforms', () async {
    if (Platform.isIOS) {
      // On a real device this would prompt for the VPN permission; skipped
      // in unit tests to avoid system dialogs.
      return;
    }
    await expectLater(
      IosVpnDevice.start(address: '10.0.0.2', prefixLength: 32),
      throwsA(isA<UnsupportedError>()),
    );
    expect(await IosVpnDevice.isPrepared, isFalse);
    await expectLater(
      IosVpnDevice.installConfiguration(),
      completes,
    );
  });
}
