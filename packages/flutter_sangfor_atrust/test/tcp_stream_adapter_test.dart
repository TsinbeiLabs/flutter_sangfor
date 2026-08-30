import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_sangfor_atrust/flutter_sangfor_atrust.dart';
import 'package:test/test.dart';

class _ScriptedTcpChannel implements ATrustTunnelChannel {
  final _incoming = StreamController<List<int>>();
  final sent = <Uint8List>[];
  bool closed = false;

  @override
  Stream<List<int>> get incoming => _incoming.stream;

  @override
  Future<void> send(Uint8List bytes) async => sent.add(bytes);

  @override
  Future<void> close() async {
    closed = true;
    unawaited(_incoming.close());
  }

  void emit(List<int> data) => _incoming.add(data);
}

Uint8List _serverHandshake() {
  final authJson = utf8.encode(jsonEncode(<String, Object?>{
    'code': 0,
    'message': 'ok',
  }));
  final builder = BytesBuilder();
  builder.add(<int>[0x05, 0x81, 0x53, 0x00]);
  builder.add(<int>[(authJson.length >> 8) & 0xff, authJson.length & 0xff]);
  builder.add(authJson);
  builder.add(<int>[0x05, 0x00, 0x01, 0x01]);
  builder.add(<int>[10, 0, 0, 1]);
  builder.add(<int>[0x01, 0xbb]);
  return builder.toBytes();
}

void main() {
  test('adapter forwards the TCP tunnel connection lifecycle', () async {
    final channel = _ScriptedTcpChannel();
    final request = const ATrustTcpTunnelAuthRequest(
      sid: 'sid',
      appId: 'app',
      url: 'tcp://10.0.0.2:443',
      deviceId: 'device',
      connectionId: 'connection',
      procHash: 'hash',
      userName: 'user',
      lang: 'en-US',
      destAddr: '10.0.0.2:443',
    );

    final connection = ATrustTcpTunnelConn.connect(
      channel: channel,
      request: request,
      signKey: Uint8List.fromList(List<int>.filled(32, 3)),
      host: '10.0.0.2',
      port: 443,
      zeroRtt: true,
    );
    await Future<void>.delayed(Duration.zero);
    channel.emit(_serverHandshake());
    final conn = await connection;
    expect(conn.reuse, isTrue);

    final stream = ATrustTcpTunnelStream(conn);
    expect(stream.isClosed, isFalse);

    await stream.send(Uint8List.fromList('ping'.codeUnits));
    expect(
      channel.sent.last,
      <int>[0x01, 0x00, 0x00, 0x04, ...'ping'.codeUnits],
    );

    channel.emit(<int>[0x01, 0x00, 0x00, 0x04, ...'pong'.codeUnits]);
    final echoed = await stream.incoming.first;
    expect(utf8.decode(echoed), 'pong');

    await stream.closeWrite();
    expect(channel.sent.last, <int>[0x01, 0x01, 0x00, 0x00]);

    await stream.close();
    expect(stream.isClosed, isTrue);
    expect(channel.closed, isTrue);
  });

  test('connector dialTcp refuses without a tunnel', () async {
    final connector = ATrustConnector();
    await expectLater(
      connector.dialTcp('10.0.0.2', 443),
      throwsA(
        isA<SangforException>().having(
          (error) => error.code,
          'code',
          SangforErrorCode.invalidOptions,
        ),
      ),
    );
  });
}
