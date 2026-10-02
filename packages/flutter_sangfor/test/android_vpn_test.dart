import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  // The service-event streams register a method call handler, which needs a
  // binding; the platform-rejection test below never reaches a channel.
  TestWidgetsFlutterBinding.ensureInitialized();

  const codec = StandardMethodCodec();

  /// Delivers a `flutter_sangfor/service` call the way the native side does.
  /// The plugin owns the sending end of that channel, so a test has to speak
  /// it from there to reach the Dart-side handler.
  Future<void> deliverServiceEvent(String method) async {
    await TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .handlePlatformMessage(
      'flutter_sangfor/service',
      codec.encodeMethodCall(MethodCall(method)),
      (_) {},
    );
    await Future<void>.delayed(Duration.zero);
  }

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

  test('the revocation stream installs the shared handler on its own',
      () async {
    // Nothing has asked for `disconnectRequests` first, so this only passes if
    // `revocations` installs the native handler itself. Both streams arrive on
    // one channel with one handler, and a caller that only cares about the OS
    // taking the tunnel away must not depend on someone else having subscribed
    // to the notification button first.
    final events = <void>[];
    final subscription = AndroidVpnDevice.revocations.listen(events.add);
    addTearDown(subscription.cancel);

    await deliverServiceEvent('vpnRevoked');

    expect(events, hasLength(1));
  });

  test('each service event reaches only its own stream', () async {
    final disconnects = <void>[];
    final revocations = <void>[];
    final disconnectSub = AndroidVpnDevice.disconnectRequests.listen(
      disconnects.add,
    );
    final revokeSub = AndroidVpnDevice.revocations.listen(revocations.add);
    addTearDown(disconnectSub.cancel);
    addTearDown(revokeSub.cancel);

    await deliverServiceEvent('disconnectRequested');
    await deliverServiceEvent('vpnRevoked');
    await deliverServiceEvent('vpnRevoked');
    // An unrecognized method must not be reported as either one.
    await deliverServiceEvent('somethingElse');

    expect(disconnects, hasLength(1));
    expect(revocations, hasLength(2));
  });
}
