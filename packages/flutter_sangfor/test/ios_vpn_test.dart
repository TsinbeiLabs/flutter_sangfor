import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  Uint8List frame(List<int> payload) {
    final header = ByteData(4)..setUint32(0, payload.length, Endian.big);
    return Uint8List.fromList(
      header.buffer.asUint8List().followedBy(payload).toList(),
    );
  }

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

  test('ipc frame decoder handles fragmented headers and payloads', () {
    final decoder = IpcFrameDecoder();
    final payload = List<int>.generate(64, (i) => i);
    final bytes = frame(payload);
    // Feed one byte at a time; nothing should decode until the end.
    for (final byte in bytes) {
      decoder.add([byte]);
    }
    final frames = decoder.drain();
    expect(frames, hasLength(1));
    expect(frames.single, payload);
  });

  test('ipc frame decoder handles multiple frames per chunk', () {
    final decoder = IpcFrameDecoder();
    decoder.add(frame([1, 2, 3]));
    decoder.add(frame([4, 5]));
    final frames = decoder.drain();
    expect(frames, hasLength(2));
    expect(frames[0], [1, 2, 3]);
    expect(frames[1], [4, 5]);
  });

  test('ipc frame decoder keeps a partial trailing frame buffered', () {
    final decoder = IpcFrameDecoder();
    final complete = frame([9, 9, 9]);
    final partial = frame([1, 2, 3, 4, 5]);
    decoder.add(complete);
    decoder.add(partial.sublist(0, 6));
    final frames = decoder.drain();
    expect(frames, hasLength(1));
    expect(frames.single, [9, 9, 9]);
    // Deliver the rest of the partial frame.
    decoder.add(partial.sublist(6));
    final rest = decoder.drain();
    expect(rest, hasLength(1));
    expect(rest.single, [1, 2, 3, 4, 5]);
  });

  test('ipc frame decoder rejects zero length and oversized frames', () {
    final decoder = IpcFrameDecoder();
    final zero = ByteData(4)..setUint32(0, 0, Endian.big);
    final oversized = ByteData(4)
      ..setUint32(0, IosVpnDevice.maxFrameLength + 1, Endian.big);
    decoder.add(zero.buffer.asUint8List());
    decoder.add(oversized.buffer.asUint8List());
    decoder.add(frame([7, 7, 7]));
    final frames = decoder.drain();
    // Malformed frames are skipped, the valid one survives.
    expect(frames, hasLength(1));
    expect(frames.single, [7, 7, 7]);
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
    expect(await IosVpnDevice.stats(), isNull);
    await expectLater(
      IosVpnDevice.installConfiguration(),
      completes,
    );
  });
}
