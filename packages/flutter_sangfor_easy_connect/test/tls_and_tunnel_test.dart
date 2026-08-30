import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_sangfor/flutter_sangfor.dart';
import 'package:flutter_sangfor_easy_connect/flutter_sangfor_easy_connect.dart';
import 'package:http/http.dart' as http;
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

const _expectedModulusHexFile = 'test/fixtures/test-modulus.txt';

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var index = 0; index < a.length; index++) {
    if (a[index] != b[index]) return false;
  }
  return true;
}

Uint8List _pemDer(String pem) {
  final base64Body = pem
      .split('\n')
      .map((line) => line.trim())
      .where((line) => line.isNotEmpty && !line.startsWith('---'))
      .join();
  return Uint8List.fromList(base64Decode(base64Body));
}

class PipedTransport implements TlsTransport {
  final StreamController<Uint8List> _incoming =
      StreamController<Uint8List>();
  PipedTransport? peer;

  @override
  Stream<Uint8List> get incoming => _incoming.stream;

  @override
  Future<void> send(Uint8List bytes) async {
    peer?._incoming.add(bytes);
  }

  @override
  Future<void> close() async {
    if (!_incoming.isClosed) {
      unawaited(_incoming.close());
    }
  }

  void deliver(Uint8List bytes) {
    if (!_incoming.isClosed) {
      _incoming.add(bytes);
    }
  }
}

(PipedTransport, PipedTransport) createPipe() {
  final client = PipedTransport();
  final server = PipedTransport();
  client.peer = server;
  server.peer = client;
  return (client, server);
}

Uint8List _record(int type, int version, Uint8List payload) {
  final record = Uint8List(5 + payload.length);
  record[0] = type;
  record[1] = (version >> 8) & 0xff;
  record[2] = version & 0xff;
  record[3] = (payload.length >> 8) & 0xff;
  record[4] = payload.length & 0xff;
  record.setRange(5, record.length, payload);
  return record;
}

Uint8List _hsMessage(int type, Uint8List body) {
  final message = Uint8List(4 + body.length);
  message[0] = type;
  message[1] = (body.length >> 16) & 0xff;
  message[2] = (body.length >> 8) & 0xff;
  message[3] = body.length & 0xff;
  message.setRange(4, message.length, body);
  return message;
}

/// A minimal in-process TLS server used as a self-consistency oracle for the
/// client handshake. It shares the record/PRF primitives with the client and
/// verifies the client's Finished before echoing application data.
class TestTlsServer {
  TestTlsServer(
    this.transport, {
    required this.certificateDer,
    required this.privateKey,
    this.negotiateRc4 = false,
    this.negotiateTls11 = false,
  });

  final TlsTransport transport;
  final Uint8List certificateDer;
  final RSAPrivateKey privateKey;
  final bool negotiateRc4;
  final bool negotiateTls11;

  final List<int> _recordBuffer = <int>[];
  final List<int> _handshakeBuffer = <int>[];
  final List<int> _handshakeLog = <int>[];
  final List<Uint8List> echoLog = <Uint8List>[];
  final Completer<void> done = Completer<void>();

  int _negotiatedVersion = tlsVersion12;
  TlsCipher _cipher = TlsCipher.rsaAes128CbcSha;
  Uint8List _clientRandom = Uint8List(32);
  Uint8List _serverRandom = Uint8List(32);
  Uint8List _sessionId = Uint8List(0);
  Uint8List? _masterSecret;
  TlsRecordCrypto? _readCrypto;
  TlsRecordCrypto? _writeCrypto;
  bool _clientCcsSeen = false;
  final Random _random = Random(20260830);

  Future<void> run() async {
    transport.incoming.listen(
      (chunk) {
        try {
          _onData(chunk);
        } on Object catch (error, stackTrace) {
          if (!done.isCompleted) {
            done.completeError(error, stackTrace);
          }
        }
      },
      onError: (Object error, StackTrace stackTrace) {
        if (!done.isCompleted) done.completeError(error, stackTrace);
      },
      onDone: () {
        if (!done.isCompleted) done.complete();
      },
    );
    return done.future;
  }

  void _onData(Uint8List chunk) {
    _recordBuffer.addAll(chunk);
    while (_recordBuffer.length >= 5) {
      final type = _recordBuffer[0];
      final length = (_recordBuffer[3] << 8) | _recordBuffer[4];
      if (_recordBuffer.length < 5 + length) break;
      final payload = Uint8List.fromList(_recordBuffer.sublist(5, 5 + length));
      _recordBuffer.removeRange(0, 5 + length);
      _onRecord(type, payload);
    }
  }

  void _onRecord(int type, Uint8List payload) {
    if (type == tlsContentTypeCcs) {
      _clientCcsSeen = true;
      return;
    }
    if (type == tlsContentTypeAppData) {
      final plain = _readCrypto!.open(
        tlsContentTypeAppData,
        _negotiatedVersion,
        payload,
      );
      echoLog.add(plain);
      transport.send(
        _record(
          tlsContentTypeAppData,
          _negotiatedVersion,
          _writeCrypto!.seal(
            tlsContentTypeAppData,
            _negotiatedVersion,
            plain,
          ),
        ),
      );
      return;
    }
    if (type != tlsContentTypeHandshake) return;
    Uint8List plain = payload;
    if (_clientCcsSeen) {
      plain = _readCrypto!.open(
        tlsContentTypeHandshake,
        _negotiatedVersion,
        payload,
      );
    }
    _handshakeBuffer.addAll(plain);
    while (_handshakeBuffer.length >= 4) {
      final hsType = _handshakeBuffer[0];
      final length = (_handshakeBuffer[1] << 16) |
          (_handshakeBuffer[2] << 8) |
          _handshakeBuffer[3];
      if (_handshakeBuffer.length < 4 + length) return;
      final body =
          Uint8List.fromList(_handshakeBuffer.sublist(4, 4 + length));
      _handshakeBuffer.removeRange(0, 4 + length);
      if (hsType == 20 && _clientCcsSeen) {
        // Finished verify data excludes the Finished itself: verify first,
        // then append so the server's own Finished can cover it.
        _verifyClientFinished(body);
        _handshakeLog.addAll(_hsMessage(hsType, body));
        unawaited(_sendServerFinished());
      } else {
        _handshakeLog.addAll(_hsMessage(hsType, body));
        _onHandshakeMessage(hsType, body);
      }
    }
  }

  void _onHandshakeMessage(int type, Uint8List body) {
    if (type == 1) {
      _parseClientHello(body);
      unawaited(_sendServerFlight());
      return;
    }
    if (type == 16 && !_clientCcsSeen) {
      _parseClientKeyExchange(body);
      return;
    }
  }

  void _parseClientHello(Uint8List body) {
    final offered = ByteData.sublistView(body).getUint16(0, Endian.big);
    _negotiatedVersion = negotiateTls11 || offered <= tlsVersion11
        ? tlsVersion11
        : tlsVersion12;
    _clientRandom = Uint8List.sublistView(body, 2, 34);
    final sessionIdLength = body[34];
    _sessionId = Uint8List.sublistView(body, 35, 35 + sessionIdLength);
    var offset = 35 + sessionIdLength;
    final cipherLength = (body[offset] << 8) | body[offset + 1];
    offset += 2;
    final offeredCiphers = <int>[];
    for (var index = 0; index < cipherLength ~/ 2; index++) {
      offeredCiphers.add((body[offset] << 8) | body[offset + 1]);
      offset += 2;
    }
    if (negotiateRc4 && offeredCiphers.contains(0x0005)) {
      _cipher = TlsCipher.rsaRc4128Sha;
    } else if (offeredCiphers.contains(0x002f)) {
      _cipher = TlsCipher.rsaAes128CbcSha;
    } else if (offeredCiphers.contains(0x0005)) {
      _cipher = TlsCipher.rsaRc4128Sha;
    } else {
      throw StateError('no common cipher');
    }
    _serverRandom = Uint8List.fromList(
      List<int>.generate(32, (_) => _random.nextInt(256)),
    );
  }

  Future<void> _sendServerFlight() async {
    final serverHelloBody = BytesBuilder();
    final version = ByteData(2)
      ..setUint16(0, _negotiatedVersion);
    serverHelloBody.add(version.buffer.asUint8List());
    serverHelloBody.add(_serverRandom);
    serverHelloBody.addByte(_sessionId.length);
    serverHelloBody.add(_sessionId);
    serverHelloBody.addByte((_cipher.id >> 8) & 0xff);
    serverHelloBody.addByte(_cipher.id & 0xff);
    serverHelloBody.addByte(0);
    final serverHello = _hsMessage(2, serverHelloBody.toBytes());
    _handshakeLog.addAll(serverHello);
    await transport.send(
      _record(
        tlsContentTypeHandshake,
        _negotiatedVersion,
        serverHello,
      ),
    );

    final certBody = BytesBuilder();
    final listInner = BytesBuilder();
    final certLength = ByteData(3)
      ..setUint8(0, (certificateDer.length >> 16) & 0xff)
      ..setUint8(1, (certificateDer.length >> 8) & 0xff)
      ..setUint8(2, certificateDer.length & 0xff);
    listInner.add(certLength.buffer.asUint8List());
    listInner.add(certificateDer);
    final listBytes = listInner.toBytes();
    certBody.addByte((listBytes.length >> 16) & 0xff);
    certBody.addByte((listBytes.length >> 8) & 0xff);
    certBody.addByte(listBytes.length & 0xff);
    certBody.add(listBytes);
    final certificate = _hsMessage(11, certBody.toBytes());
    _handshakeLog.addAll(certificate);
    await transport.send(
      _record(tlsContentTypeHandshake, _negotiatedVersion, certificate),
    );

    const serverHelloDone = [14, 0, 0, 0];
    _handshakeLog.addAll(serverHelloDone);
    await transport.send(
      _record(
        tlsContentTypeHandshake,
        _negotiatedVersion,
        Uint8List.fromList(serverHelloDone),
      ),
    );
  }

  void _parseClientKeyExchange(Uint8List body) {
    final length = (body[0] << 8) | body[1];
    final encrypted = Uint8List.sublistView(body, 2, 2 + length);
    final rsa = PKCS1Encoding(RSAEngine())
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    final premaster = rsa.process(encrypted);
    final tls12 = _negotiatedVersion == tlsVersion12;
    _masterSecret = tlsMasterSecret(
      premaster,
      _clientRandom,
      _serverRandom,
      tls12: tls12,
    );
    final keyBlock = tlsKeyBlock(
      _masterSecret!,
      _clientRandom,
      _serverRandom,
      tls12: tls12,
    );
    _readCrypto = TlsRecordCrypto(
      cipher: _cipher,
      macKey: Uint8List.sublistView(keyBlock, 0, 20),
      encKey: Uint8List.sublistView(keyBlock, 40, 56),
      random: _random,
    );
    _writeCrypto = TlsRecordCrypto(
      cipher: _cipher,
      macKey: Uint8List.sublistView(keyBlock, 20, 40),
      encKey: Uint8List.sublistView(keyBlock, 56, 72),
      random: _random,
    );
  }

  Uint8List _verifyData(String label) {
    final tls12 = _negotiatedVersion == tlsVersion12;
    final logBytes = Uint8List.fromList(_handshakeLog);
    Uint8List seed;
    if (tls12) {
      seed = SHA256Digest().process(logBytes);
    } else {
      seed = Uint8List.fromList(
        <int>[...MD5Digest().process(logBytes), ...SHA1Digest().process(logBytes)],
      );
    }
    if (tls12) {
      return tls12Prf(_masterSecret!, label, seed, 12);
    }
    return tls11Prf(_masterSecret!, label, seed, 12);
  }

  void _verifyClientFinished(Uint8List body) {
    final expected = _verifyData('client finished');
    if (body.length != 12) {
      throw StateError('client Finished has length ${body.length}');
    }
    for (var index = 0; index < 12; index++) {
      if (body[index] != expected[index]) {
        throw StateError('client Finished mismatch at byte $index');
      }
    }
  }

  Future<void> _sendServerFinished() async {
    await transport.send(
      _record(tlsContentTypeCcs, _negotiatedVersion, Uint8List.fromList([1])),
    );
    final verifyData = _verifyData('server finished');
    final finished = _hsMessage(20, verifyData);
    _handshakeLog.addAll(finished);
    await transport.send(
      _record(
        tlsContentTypeHandshake,
        _negotiatedVersion,
        _writeCrypto!.seal(
          tlsContentTypeHandshake,
          _negotiatedVersion,
          finished,
        ),
      ),
    );
  }
}

class FakeTunnelTlsConnection implements EasyConnectTlsConnection {
  FakeTunnelTlsConnection({Uint8List? sessionId})
      : sessionId = sessionId ??
            Uint8List.fromList(List<int>.generate(32, (index) => index + 1));

  @override
  final Uint8List sessionId;

  final StreamController<Uint8List> _incomingCtrl =
      StreamController<Uint8List>.broadcast();
  final List<Uint8List> sent = <Uint8List>[];
  bool closed = false;

  @override
  Stream<Uint8List> get incoming => _incomingCtrl.stream;

  @override
  Uint8List get peerCertificate => Uint8List(0);

  @override
  bool get isClosed => closed;

  void emit(Uint8List bytes) {
    if (!_incomingCtrl.isClosed) {
      _incomingCtrl.add(bytes);
    }
  }

  void respondToHandshake() {
    if (sent.isEmpty) return;
    final last = sent.last;
    if (last.length != 64) {
      // Token connection: reply with an HTTP response header.
      emit(Uint8List.fromList(utf8.encode('HTTP/1.1 200 OK\r\n\r\n')));
      return;
    }
    final op = ByteData.sublistView(last).getUint32(0, Endian.little);
    switch (op) {
      case EasyConnectTunnelProtocol.queryIpOp:
        final reply = Uint8List(36);
        reply.setRange(4, 8, <int>[10, 166, 80, 12]);
        reply.setRange(12, 16, <int>[10, 166, 64, 3]);
        emit(reply);
      case EasyConnectTunnelProtocol.rxStreamOp:
        final reply = Uint8List(36);
        ByteData.sublistView(reply).setUint32(0, 1, Endian.little);
        emit(reply);
      case EasyConnectTunnelProtocol.txStreamOp:
        final reply = Uint8List(36);
        ByteData.sublistView(reply).setUint32(0, 2, Endian.little);
        emit(reply);
      default:
        break;
    }
  }

  @override
  Future<void> send(Uint8List data) async {
    sent.add(data);
    respondToHandshake();
  }

  @override
  Future<void> close() async {
    closed = true;
    if (!_incomingCtrl.isClosed) {
      await _incomingCtrl.close();
    }
  }
}

Uint8List _ipv4Packet(int totalLength) {
  final packet = Uint8List(totalLength);
  packet[0] = 0x45;
  packet[2] = (totalLength >> 8) & 0xff;
  packet[3] = totalLength & 0xff;
  packet[9] = 17; // UDP
  return packet;
}

void main() {
  late Uint8List certificateDer;
  late RSAPrivateKey privateKey;

  setUpAll(() {
    final certPem = File('test/fixtures/test-cert.pem').readAsStringSync();
    final keyPem = File('test/fixtures/test-key.pem').readAsStringSync();
    certificateDer = _pemDer(certPem);
    final pkcs8 = DerReader(_pemDer(keyPem)).readConstructed();
    pkcs8.readElement(); // version
    pkcs8.readConstructed(); // algorithm
    final (_, privateKeyBytes) = pkcs8.readElement(); // OCTET STRING
    final rsa = DerReader(privateKeyBytes).readConstructed();
    rsa.readElement(); // version
    final (_, modulus) = rsa.readElement();
    rsa.readElement(); // publicExponent
    final (_, d) = rsa.readElement(); // privateExponent
    final (_, p) = rsa.readElement(); // prime1
    final (_, q) = rsa.readElement(); // prime2
    privateKey = RSAPrivateKey(
      _parseBigInt(modulus),
      _parseBigInt(d),
      _parseBigInt(p),
      _parseBigInt(q),
    );
  });

  test('TLS 1.2 PRF derives exact lengths and hashes deterministically', () {
    final secret = Uint8List.fromList(List<int>.generate(48, (i) => i * 7));
    final seed = Uint8List.fromList(<int>[1, 2, 3, 4]);
    final output = tls12Prf(secret, 'master secret', seed, 48);
    expect(output, hasLength(48));
    // Deterministic: same inputs, same output.
    expect(tls12Prf(secret, 'master secret', seed, 48), output);
    // Different labels derive different material.
    expect(
      tls12Prf(secret, 'key expansion', seed, 48),
      isNot(output),
    );
    // Output length is exact even for non-block-aligned sizes.
    expect(tls12Prf(secret, 'x', seed, 33), hasLength(33));
    // Key block for our suites is exactly 72 bytes.
    final keyBlock = tlsKeyBlock(secret, seed, seed);
    expect(keyBlock, hasLength(72));
  });

  test('TLS 1.1 PRF splits the secret with a shared middle byte', () {
    final oddSecret = Uint8List.fromList(<int>[1, 2, 3, 4, 5]);
    final seed = Uint8List.fromList(<int>[9, 9]);
    final output = tls11Prf(oddSecret, 'label', seed, 20);
    expect(output, hasLength(20));
    // ceil(5/2) = 3: S1 = [1,2,3], S2 = [3,4,5] - shared middle byte.
    // Re-derive manually to prove the split semantics.
    final s1 = Uint8List.fromList(<int>[1, 2, 3]);
    final s2 = Uint8List.fromList(<int>[3, 4, 5]);
    final seedWithLabel =
        Uint8List.fromList(<int>[...utf8.encode('label'), ...seed]);
    final md5 = _expand('md5', s1, seedWithLabel, 20);
    final sha1 = _expand('sha1', s2, seedWithLabel, 20);
    for (var index = 0; index < 20; index++) {
      expect(output[index], md5[index] ^ sha1[index]);
    }
  });

  test('record crypto round-trips RC4 and AES and detects tampering', () {
    for (final cipher in TlsCipher.values) {
      final macKey = Uint8List.fromList(List<int>.filled(20, 0x5a));
      final encKey = Uint8List.fromList(List<int>.filled(16, 0xa5));
      TlsRecordCrypto build() => TlsRecordCrypto(
            cipher: cipher,
            macKey: macKey,
            encKey: encKey,
            random: Random(42),
          );
      // Each direction keeps its own sequence counter, so the writer and the
      // reader are separate crypto instances sharing the same key material.
      final writer = build();
      final reader = build();
      final fragment = Uint8List.fromList(List<int>.generate(77, (i) => i));
      final sealed = writer.seal(23, tlsVersion12, fragment);
      final opened = reader.open(23, tlsVersion12, sealed);
      expect(opened, fragment);

      // Tampering flips a bit and must fail the MAC.
      sealed[sealed.length - 1] ^= 0x40;
      expect(
        () => build().open(23, tlsVersion12, sealed),
        throwsA(isA<TlsRecordException>()),
      );
    }
  });

  test('X.509 parser extracts the fixture RSA public key', () {
    final key = parseRsaPublicKey(certificateDer);
    final expectedModulus =
        File(_expectedModulusHexFile).readAsStringSync().trim();
    expect(
      key.modulus.toRadixString(16).toUpperCase(),
      expectedModulus.toUpperCase(),
    );
    expect(key.exponent, BigInt.from(65537));
    expect(key.modulus, privateKey.modulus);
  });

  test('client completes a TLS 1.2 AES handshake and echoes app data',
      () async {
    final (clientTransport, serverTransport) = createPipe();
    final server = TestTlsServer(
      serverTransport,
      certificateDer: certificateDer,
      privateKey: privateKey,
    );
    unawaited(server.run());
    final client = EasyConnectTlsClient(
      certificateValidator: (der) => _bytesEqual(der, certificateDer),
    );
    final socket = await client.connectTransport(clientTransport);
    expect(socket.isClosed, isFalse);

    final received = <Uint8List>[];
    socket.incoming.listen(received.add);
    final payload = Uint8List.fromList(List<int>.generate(300, (i) => i & 0xff));
    await socket.send(payload);
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(server.echoLog, hasLength(1));
    expect(server.echoLog.single, payload);
    expect(received, hasLength(1));
    expect(received.single, payload);
    await socket.close();
  });

  test('client completes a TLS 1.1 RC4 handshake with the L3IP hello',
      () async {
    final (clientTransport, serverTransport) = createPipe();
    final server = TestTlsServer(
      serverTransport,
      certificateDer: certificateDer,
      privateKey: privateKey,
      negotiateRc4: true,
      negotiateTls11: true,
    );
    unawaited(server.run());
    final client = EasyConnectTlsClient(
      certificateValidator: (der) => _bytesEqual(der, certificateDer),
    );
    final socket = await client.connectTransport(
      clientTransport,
      hello: TlsClientHelloSpec.l3Ip(),
    );
    // The server echoes the session id, proving the ServerHello session id
    // is surfaced to callers (the token derivation input).
    expect(socket.sessionId, TlsClientHelloSpec.l3Ip().sessionId);
    final received = <Uint8List>[];
    socket.incoming.listen(received.add);
    await socket.send(Uint8List.fromList(<int>[1, 2, 3]));
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(received, hasLength(1));
    expect(received.single, <int>[1, 2, 3]);
    await socket.close();
  });

  test('client refuses connections without a certificate validator', () async {
    final (clientTransport, serverTransport) = createPipe();
    final server = TestTlsServer(
      serverTransport,
      certificateDer: certificateDer,
      privateKey: privateKey,
    );
    unawaited(server.run());
    final client = EasyConnectTlsClient();
    await expectLater(
      client.connectTransport(clientTransport),
      throwsA(isA<TlsHandshakeException>()),
    );
  });

  test('client rejects certificates the validator denies', () async {
    final (clientTransport, serverTransport) = createPipe();
    final server = TestTlsServer(
      serverTransport,
      certificateDer: certificateDer,
      privateKey: privateKey,
    );
    unawaited(server.run());
    final client = EasyConnectTlsClient(
      certificateValidator: (der) => false,
    );
    await expectLater(
      client.connectTransport(clientTransport),
      throwsA(isA<TlsHandshakeException>()),
    );
  });

  test('tunnel derives the token, queries the IP, and routes packets',
      () async {
    final connections = <FakeTunnelTlsConnection>[];
    final sessionIds = <Uint8List>[
      Uint8List.fromList(List<int>.generate(32, (index) => 0x40 + index)),
    ];
    Future<EasyConnectTlsConnection> factory(TlsClientHelloSpec hello) async {
      final connection = FakeTunnelTlsConnection(
        sessionId: hello.sessionId ?? sessionIds.first,
      );
      connections.add(connection);
      return connection;
    }

    final tunnel = EasyConnectTunnel(
      server: Uri.parse('https://vpn.example.test'),
      twfId: 'twf-0123456789ab',
      connectionFactory: factory,
      commandHeartbeatInterval: const Duration(milliseconds: 30),
      txHeartbeatInterval: const Duration(milliseconds: 30),
    );
    final received = <Uint8List>[];
    tunnel.incoming.listen(received.add);

    final address = await tunnel.start();
    expect(address, '10.166.80.12');
    // Token, command, RX, and TX connections.
    expect(connections, hasLength(4));
    expect(connections.first.sent.single.length, greaterThan(8));

    // RX stream delivers raw IP packets.
    final inbound = _ipv4Packet(60);
    connections[2].emit(inbound);
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(received, hasLength(1));
    expect(received.single, inbound);

    // TX stream forwards raw IP packets.
    final outbound = _ipv4Packet(48);
    await tunnel.sendPacket(outbound);
    expect(connections[3].sent, contains(outbound));

    // Heartbeats flow on the command and TX streams.
    await Future<void>.delayed(const Duration(milliseconds: 120));
    final commandOps = connections[1].sent
        .skip(1)
        .map(
          (message) =>
              ByteData.sublistView(message).getUint32(0, Endian.little),
        )
        .toSet();
    expect(commandOps, contains(EasyConnectTunnelProtocol.commandHeartbeatOp));
    final txHeartbeats = connections[3]
        .sent
        .where((message) => message.length == 76)
        .toList();
    expect(txHeartbeats, isNotEmpty);

    // Fatal control code closes the tunnel.
    final kick = Uint8List(40);
    kick.setRange(0, 4, <int>[0x41, 0x41, 0x42, 0x42]);
    ByteData.sublistView(kick).setUint32(4, 14, Endian.little);
    connections[1].emit(kick);
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(tunnel.isClosed, isTrue);
    expect(connections.every((connection) => connection.closed), isTrue);
  });

  test('connector brings up the EasyConnect tunnel end to end', () async {
    final client = _TunnelLoginHttpClient();
    final connections = <FakeTunnelTlsConnection>[];
    final connector = EasyConnectConnector(
      loginSession: EasyConnectLoginSession(client: client),
      connectionFactory: (hello) async {
        final connection = FakeTunnelTlsConnection(
          sessionId:
              hello.sessionId ?? Uint8List.fromList(List<int>.filled(32, 7)),
        );
        connections.add(connection);
        return connection;
      },
    );
    final session = await connector.connect(
      SangforConnectOptions(
        server: Uri.parse('https://vpn.example.test'),
        username: 'alice',
        password: 'secret',
      ),
    );
    expect(session.state, SangforConnectionState.connected);
    expect(session.virtualAddress, '10.166.80.12');
    expect(session.dnsServers, <String>['10.0.0.53']);
    expect(connector.tunnel, isNotNull);
    expect(connections, hasLength(4));
    await connector.disconnect();
    expect(connector.tunnel, isNull);
    expect(connections.every((connection) => connection.closed), isTrue);
  });

  test('connector refuses tunnels without a certificate policy', () async {
    final client = _TunnelLoginHttpClient();
    final connector = EasyConnectConnector(
      loginSession: EasyConnectLoginSession(client: client),
    );
    await expectLater(
      connector.connect(
        SangforConnectOptions(
          server: Uri.parse('https://vpn.example.test'),
          username: 'alice',
          password: 'secret',
        ),
      ),
      throwsA(
        isA<SangforException>().having(
          (error) => error.code,
          'code',
          SangforErrorCode.invalidOptions,
        ),
      ),
    );
  });

  test('connector skips the tunnel when startTunnel is disabled', () async {
    final client = _TunnelLoginHttpClient();
    final connector = EasyConnectConnector(
      loginSession: EasyConnectLoginSession(client: client),
      startTunnel: false,
    );
    final session = await connector.connect(
      SangforConnectOptions(
        server: Uri.parse('https://vpn.example.test'),
        username: 'alice',
        password: 'secret',
      ),
    );
    expect(session.state, SangforConnectionState.authenticated);
    expect(connector.tunnel, isNull);
    expect(connector.tcpProxy, isNull);
  });

  test('connector exposes a userspace TCP proxy after connecting', () async {
    final client = _TunnelLoginHttpClient();
    final connector = EasyConnectConnector(
      loginSession: EasyConnectLoginSession(client: client),
      connectionFactory: (hello) async => FakeTunnelTlsConnection(
        sessionId: hello.sessionId ?? Uint8List.fromList(List<int>.filled(32, 7)),
      ),
    );
    final session = await connector.connect(
      SangforConnectOptions(
        server: Uri.parse('https://vpn.example.test'),
        username: 'alice',
        password: 'secret',
      ),
    );
    expect(session.state, SangforConnectionState.connected);
    expect(connector.tcpProxy, isNotNull);
    expect(connector.tcpProxy!.sourceIp, <int>[10, 166, 80, 12]);

    // No peer answers the synthesized SYN, so the dial times out.
    await expectLater(
      connector.dialTcp(
        '10.0.0.9',
        80,
        timeout: const Duration(milliseconds: 250),
      ),
      throwsA(isA<TimeoutException>()),
    );

    await connector.disconnect();
    expect(connector.tcpProxy, isNull);
    await expectLater(
      connector.dialTcp('10.0.0.9', 80),
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

BigInt _parseBigInt(Uint8List content) {
  if (content.isEmpty) return BigInt.zero;
  var value = BigInt.zero;
  if (content[0] == 0) {
    for (final byte in content.skip(1)) {
      value = (value << 8) | BigInt.from(byte);
    }
    return value;
  }
  for (final byte in content) {
    value = (value << 8) | BigInt.from(byte);
  }
  return value;
}

Uint8List _expand(String algorithm, Uint8List secret, Uint8List seed, int length) {
  Uint8List hmac(Uint8List key, List<int> data) {
    if (algorithm == 'md5') {
      final h = HMac(MD5Digest(), 64)..init(KeyParameter(key));
      return h.process(Uint8List.fromList(data));
    }
    final h = HMac(SHA1Digest(), 64)..init(KeyParameter(key));
    return h.process(Uint8List.fromList(data));
  }

  final output = <int>[];
  var a = seed;
  while (output.length < length) {
    a = hmac(secret, a);
    output.addAll(hmac(secret, <int>[...a, ...seed]));
  }
  return Uint8List.fromList(output.sublist(0, length));
}

class _TunnelLoginHttpClient extends http.BaseClient {
  final Map<String, String> bodies = <String, String>{
    '/por/login_auth.csp':
        '<Auth><TwfID>twf-0123456789ab</TwfID><RSA_ENCRYPT_KEY>${'F' * 256}'
        '</RSA_ENCRYPT_KEY><RSA_ENCRYPT_EXP>65537</RSA_ENCRYPT_EXP>'
        '<CSRF_RAND_CODE>nonce</CSRF_RAND_CODE></Auth>',
    '/por/login_psw.csp': '<Auth><Result>1</Result></Auth>',
    '/por/conf.csp':
        '<Conf><L3VPN iptunDns="10.0.0.53" iptunDnsBak="10.0.0.54"/>'
        '<Mline enable="1" list="host1:443"/><Htp mtu="1400"/></Conf>',
    '/por/rclist.csp': '<Resource><Rcs></Rcs></Resource>',
    '/por/update_session.csp':
        '<Auth><Message>success</Message><ErrorCode>1</ErrorCode></Auth>',
  };

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final body = bodies[request.url.path] ?? '<Auth><Result>1</Result></Auth>';
    return http.StreamedResponse(
      Stream<List<int>>.value(utf8.encode(body)),
      200,
    );
  }
}
