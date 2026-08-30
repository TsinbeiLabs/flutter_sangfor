import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'tls_prf.dart';
import 'tls_record.dart';
import 'tls_x509.dart';
import '../easy_connect_tunnel.dart' show EasyConnectTlsConnection;

const int tlsContentTypeCcs = 20;
const int tlsContentTypeAlert = 21;
const int tlsContentTypeHandshake = 22;
const int tlsContentTypeAppData = 23;

const int tlsVersion10 = 0x0301;
const int tlsVersion11 = 0x0302;
const int tlsVersion12 = 0x0303;

/// Description of the ClientHello the minimal client should emit.
class TlsClientHelloSpec {
  const TlsClientHelloSpec({
    required this.offeredVersion,
    required this.recordVersion,
    required this.cipherSuites,
    required this.compressionMethods,
    required this.extensions,
    this.sessionId,
  });

  /// The standard hello used for the token connection: TLS 1.2, no session
  /// id, AES/RC4 RSA key-exchange suites with the renegotiation SCSV.
  factory TlsClientHelloSpec.standard() => const TlsClientHelloSpec(
        offeredVersion: tlsVersion12,
        recordVersion: tlsVersion10,
        cipherSuites: <int>[0x002f, 0x0005, 0x00ff],
        compressionMethods: <int>[0],
        extensions: <Uint8List>[],
      );

  /// The EasyConnect data-channel hello: TLS 1.1, the `L3IP` session id the
  /// server demuxes on, RC4-SHA first with an AES fallback, null compression,
  /// and the fake heartbeat extension the official client sends.
  factory TlsClientHelloSpec.l3Ip() => TlsClientHelloSpec(
        offeredVersion: tlsVersion11,
        recordVersion: tlsVersion11,
        cipherSuites: const <int>[0x0005, 0x00ff, 0x002f],
        compressionMethods: const <int>[0],
        extensions: <Uint8List>[
          Uint8List.fromList(<int>[0x00, 0x0f, 0x00, 0x01, 0x01]),
        ],
        sessionId: Uint8List.fromList(
          <int>[0x4c, 0x33, 0x49, 0x50, ...List<int>.filled(28, 0)],
        ),
      );

  final int offeredVersion;
  final int recordVersion;
  final List<int> cipherSuites;
  final List<int> compressionMethods;
  final List<Uint8List> extensions;
  final Uint8List? sessionId;
}

/// Byte transport the TLS layer runs on top of.
abstract class TlsTransport {
  Stream<Uint8List> get incoming;

  Future<void> send(Uint8List bytes);

  Future<void> close();
}

class SocketTlsTransport implements TlsTransport {
  SocketTlsTransport(this._socket);

  final Socket _socket;

  @override
  Stream<Uint8List> get incoming => _socket.cast<Uint8List>();

  @override
  Future<void> send(Uint8List bytes) => _socket.addStream(
        Stream<Uint8List>.value(bytes),
      );

  @override
  Future<void> close() => _socket.close();
}

Uint8List _buildTlsRecord(int type, int version, Uint8List payload) {
  final record = Uint8List(5 + payload.length);
  record[0] = type;
  record[1] = (version >> 8) & 0xff;
  record[2] = version & 0xff;
  record[3] = (payload.length >> 8) & 0xff;
  record[4] = payload.length & 0xff;
  record.setRange(5, record.length, payload);
  return record;
}

Uint8List _handshakeMessage(int type, Uint8List body) {
  final message = Uint8List(4 + body.length);
  message[0] = type;
  message[1] = (body.length >> 16) & 0xff;
  message[2] = (body.length >> 8) & 0xff;
  message[3] = body.length & 0xff;
  message.setRange(4, message.length, body);
  return message;
}

/// A completed TLS connection exposing decrypted application data.
class EasyConnectTlsSocket implements EasyConnectTlsConnection {
  EasyConnectTlsSocket._(
    this._transport,
    this._readCrypto,
    this._negotiatedVersion,
  );

  final TlsTransport _transport;
  final TlsRecordCrypto? _readCrypto;
  final int _negotiatedVersion;
  final StreamController<Uint8List> _appData =
      StreamController<Uint8List>.broadcast();

  TlsRecordCrypto? _writeCrypto;
  Uint8List _sessionId = Uint8List(0);
  Uint8List _peerCertificate = Uint8List(0);
  bool _closed = false;

  @override
  Stream<Uint8List> get incoming => _appData.stream;
  @override
  Uint8List get sessionId => _sessionId;
  @override
  Uint8List get peerCertificate => _peerCertificate;
  @override
  bool get isClosed => _closed;

  void _handleAppData(Uint8List payload) {
    final readCrypto = _readCrypto;
    if (readCrypto == null) return;
    try {
      final fragment = readCrypto.open(
        tlsContentTypeAppData,
        _negotiatedVersion,
        payload,
      );
      if (fragment.isNotEmpty && !_appData.isClosed) {
        _appData.add(fragment);
      }
    } on Object {
      unawaited(close());
    }
  }

  void _handleAlert(Uint8List payload) {
    if (payload.length == 2 && payload[0] == 1 && payload[1] == 0) {
      unawaited(close());
    } else {
      unawaited(close());
    }
  }

  @override
  Future<void> send(Uint8List data) async {
    if (_closed) throw StateError('TLS socket is closed');
    final writeCrypto = _writeCrypto;
    for (var offset = 0; offset < data.length; offset += 16384) {
      final end =
          offset + 16384 > data.length ? data.length : offset + 16384;
      final fragment = Uint8List.sublistView(data, offset, end);
      final payload = writeCrypto == null
          ? fragment
          : writeCrypto.seal(tlsContentTypeAppData, _negotiatedVersion, fragment);
      await _transport.send(
        _buildTlsRecord(tlsContentTypeAppData, _negotiatedVersion, payload),
      );
    }
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    try {
      final writeCrypto = _writeCrypto;
      if (writeCrypto != null) {
        final alert = Uint8List.fromList(<int>[0x01, 0x00]);
        await _transport.send(
          _buildTlsRecord(
            tlsContentTypeAlert,
            _negotiatedVersion,
            writeCrypto.seal(tlsContentTypeAlert, _negotiatedVersion, alert),
          ),
        );
      }
    } on Object {
      // Best-effort close_notify.
    }
    if (!_appData.isClosed) {
      unawaited(_appData.close());
    }
    await _transport.close();
  }
}

/// A minimal TLS 1.1/1.2 client with a fully controllable ClientHello, RSA
/// key exchange, and RC4-SHA / AES128-CBC-SHA record protection, per
/// RFC 4346/5246. Used for the EasyConnect data channels whose servers
/// require the custom `L3IP` hello shape that dart:io cannot emit.
class EasyConnectTlsClient {
  EasyConnectTlsClient({
    this.certificateValidator,
    this.allowUnverifiedCertificates = false,
    Random Function()? randomFactory,
  }) : _randomFactory = randomFactory ?? Random.secure;

  /// Validates the server certificate DER. Required unless
  /// [allowUnverifiedCertificates] is explicitly enabled.
  final bool Function(Uint8List certificateDer)? certificateValidator;
  final bool allowUnverifiedCertificates;
  final Random Function() _randomFactory;

  Future<EasyConnectTlsSocket> connect(
    String host,
    int port, {
    TlsClientHelloSpec? hello,
    Duration timeout = const Duration(seconds: 15),
    TlsTransport? transport,
  }) async {
    final spec = hello ?? TlsClientHelloSpec.standard();
    final tlsTransport =
        transport ?? await _defaultTransport(host, port);
    return connectTransport(
      tlsTransport,
      hello: spec,
      timeout: timeout,
    );
  }

  Future<EasyConnectTlsSocket> connectTransport(
    TlsTransport transport, {
    TlsClientHelloSpec? hello,
    Duration timeout = const Duration(seconds: 15),
  }) {
    return _TlsHandshake(
      transport,
      hello ?? TlsClientHelloSpec.standard(),
      certificateValidator,
      allowUnverifiedCertificates,
      _randomFactory(),
    ).run().timeout(timeout);
  }

  Future<TlsTransport> _defaultTransport(String host, int port) async {
    final socket = await Socket.connect(host, port);
    return SocketTlsTransport(socket);
  }
}

class TlsHandshakeException implements Exception {
  const TlsHandshakeException(this.message);

  final String message;

  @override
  String toString() => 'TlsHandshakeException: $message';
}

class _TlsHandshake {
  _TlsHandshake(
    this._transport,
    this._hello,
    this._certificateValidator,
    this._allowUnverified,
    this._random,
  );

  final TlsTransport _transport;
  final TlsClientHelloSpec _hello;
  final bool Function(Uint8List)? _certificateValidator;
  final bool _allowUnverified;
  final Random _random;

  final List<int> _recordBuffer = <int>[];
  final List<int> _handshakeBuffer = <int>[];
  final List<int> _handshakeLog = <int>[];

  int _negotiatedVersion = tlsVersion12;
  TlsCipher _cipher = TlsCipher.rsaAes128CbcSha;
  Uint8List _clientRandom = Uint8List(32);
  Uint8List _serverRandom = Uint8List(32);
  Uint8List _sessionId = Uint8List(0);
  Uint8List _peerCertificate = Uint8List(0);
  TlsRsaPublicKey? _serverKey;
  Uint8List? _masterSecret;
  TlsRecordCrypto? _readCrypto;
  TlsRecordCrypto? _writeCrypto;
  bool _certificateRequested = false;
  bool _serverCcsReceived = false;
  EasyConnectTlsSocket? _socket;

  final Completer<EasyConnectTlsSocket> _done =
      Completer<EasyConnectTlsSocket>();
  StreamSubscription<Uint8List>? _subscription;

  Future<EasyConnectTlsSocket> run() async {
    _subscription = _transport.incoming.listen(
      _onTransportData,
      onError: (Object error, StackTrace stackTrace) {
        _fail(error, stackTrace);
      },
      onDone: () {
        _fail(
          TlsHandshakeException('transport closed during handshake'),
          StackTrace.current,
        );
      },
    );
    try {
      _clientRandom = _randomBytes(32);
      await _sendClientHello();
      return await _done.future;
    } on Object {
      await _abort();
      rethrow;
    }
  }

  Uint8List _randomBytes(int length) => Uint8List.fromList(
        List<int>.generate(length, (_) => _random.nextInt(256)),
      );

  Future<void> _sendClientHello() async {
    final hello = _hello;
    final body = BytesBuilder();
    final version = ByteData(2)..setUint16(0, hello.offeredVersion);
    body.add(version.buffer.asUint8List());
    body.add(_clientRandom);
    final sessionId = hello.sessionId ?? Uint8List(0);
    if (sessionId.length > 32) {
      throw const TlsHandshakeException('session id too long');
    }
    body.addByte(sessionId.length);
    body.add(sessionId);
    final cipherLength = ByteData(2)
      ..setUint16(0, hello.cipherSuites.length * 2);
    body.add(cipherLength.buffer.asUint8List());
    for (final cipher in hello.cipherSuites) {
      body.addByte((cipher >> 8) & 0xff);
      body.addByte(cipher & 0xff);
    }
    body.addByte(hello.compressionMethods.length);
    body.add(hello.compressionMethods);
    if (hello.extensions.isNotEmpty) {
      var total = 0;
      for (final extension in hello.extensions) {
        total += extension.length;
      }
      final extensionsLength = ByteData(2)..setUint16(0, total);
      body.add(extensionsLength.buffer.asUint8List());
      for (final extension in hello.extensions) {
        body.add(extension);
      }
    }
    final message = _handshakeMessage(1, body.toBytes());
    _handshakeLog.addAll(message);
    await _transport.send(
      _buildTlsRecord(
        tlsContentTypeHandshake,
        hello.recordVersion,
        message,
      ),
    );
  }

  void _onTransportData(Uint8List chunk) {
    _recordBuffer.addAll(chunk);
    while (_recordBuffer.length >= 5) {
      final type = _recordBuffer[0];
      final length = (_recordBuffer[3] << 8) | _recordBuffer[4];
      if (length > 18432) {
        _fail(
          const TlsHandshakeException('record overflow'),
          StackTrace.current,
        );
        return;
      }
      if (_recordBuffer.length < 5 + length) break;
      final payload = Uint8List.fromList(_recordBuffer.sublist(5, 5 + length));
      _recordBuffer.removeRange(0, 5 + length);
      if (!_handleRecord(type, payload)) return;
    }
  }

  bool _handleRecord(int type, Uint8List payload) {
    final socket = _socket;
    if (socket != null) {
      switch (type) {
        case tlsContentTypeAppData:
          socket._handleAppData(payload);
          return true;
        case tlsContentTypeAlert:
          socket._handleAlert(payload);
          return true;
        default:
          return true;
      }
    }
    switch (type) {
      case tlsContentTypeCcs:
        if (payload.length != 1 || payload[0] != 1) {
          _fail(
            const TlsHandshakeException('invalid ChangeCipherSpec'),
            StackTrace.current,
          );
          return false;
        }
        _serverCcsReceived = true;
        return true;
      case tlsContentTypeAlert:
        if (payload.length == 2 && payload[0] == 2) {
          _fail(
            TlsHandshakeException(
              'TLS fatal alert ${_alertName(payload[1])}',
            ),
            StackTrace.current,
          );
          return false;
        }
        return true;
      case tlsContentTypeHandshake:
        Uint8List plain = payload;
        if (_serverCcsReceived) {
          final readCrypto = _readCrypto;
          if (readCrypto == null) {
            _fail(
              const TlsHandshakeException('encrypted record before keys'),
              StackTrace.current,
            );
            return false;
          }
          try {
            plain = readCrypto.open(
              tlsContentTypeHandshake,
              _negotiatedVersion,
              payload,
            );
          } on Object catch (error, stackTrace) {
            _fail(error, stackTrace);
            return false;
          }
        }
        _handshakeBuffer.addAll(plain);
        _drainHandshakeMessages();
        return true;
      case tlsContentTypeAppData:
        _fail(
          const TlsHandshakeException('app data before keys'),
          StackTrace.current,
        );
        return false;
      default:
        _fail(
          TlsHandshakeException('unexpected record type $type'),
          StackTrace.current,
        );
        return false;
    }
  }

  void _drainHandshakeMessages() {
    while (_handshakeBuffer.length >= 4) {
      final type = _handshakeBuffer[0];
      final length = (_handshakeBuffer[1] << 16) |
          (_handshakeBuffer[2] << 8) |
          _handshakeBuffer[3];
      if (_handshakeBuffer.length < 4 + length) return;
      final body =
          Uint8List.fromList(_handshakeBuffer.sublist(4, 4 + length));
      _handshakeBuffer.removeRange(0, 4 + length);
      if (type == 20) {
        // Finished verify data hashes all messages up to but excluding this
        // Finished itself, so verify first and append afterwards.
        final proceed = _onHandshakeMessage(type, body);
        _handshakeLog.addAll(_handshakeMessage(type, body));
        if (!proceed) return;
      } else {
        _handshakeLog.addAll(_handshakeMessage(type, body));
        if (!_onHandshakeMessage(type, body)) return;
      }
    }
  }

  bool _onHandshakeMessage(int type, Uint8List body) {
    switch (type) {
      case 2: // ServerHello
        _parseServerHello(body);
        return !_done.isCompleted;
      case 11: // Certificate
        _parseCertificate(body);
        return !_done.isCompleted;
      case 12: // ServerKeyExchange is not used with static RSA exchange.
        _fail(
          const TlsHandshakeException(
            'server requested an unsupported key exchange',
          ),
          StackTrace.current,
        );
        return false;
      case 13: // CertificateRequest
        _certificateRequested = true;
        return true;
      case 14: // ServerHelloDone
        unawaited(_sendClientFlight());
        return true;
      case 20: // Finished
        return _verifyServerFinished(body);
      case 0: // HelloRequest
        return true;
      default:
        return true;
    }
  }

  void _parseServerHello(Uint8List body) {
    if (body.length < 35) {
      _fail(
        const TlsHandshakeException('short ServerHello'),
        StackTrace.current,
      );
      return;
    }
    final data = ByteData.sublistView(body);
    _negotiatedVersion = data.getUint16(0, Endian.big);
    if (_negotiatedVersion != tlsVersion11 &&
        _negotiatedVersion != tlsVersion12) {
      _fail(
        TlsHandshakeException(
          'unsupported negotiated version 0x'
          '${_negotiatedVersion.toRadixString(16)}',
        ),
        StackTrace.current,
      );
      return;
    }
    _serverRandom = Uint8List.sublistView(body, 2, 34);
    final sessionIdLength = body[34];
    var offset = 35 + sessionIdLength;
    if (body.length < offset + 3) {
      _fail(
        const TlsHandshakeException('short ServerHello session id'),
        StackTrace.current,
      );
      return;
    }
    _sessionId = Uint8List.sublistView(body, 35, offset);
    final cipherId = (body[offset] << 8) | body[offset + 1];
    try {
      _cipher = TlsCipher.fromId(cipherId);
    } on TlsRecordException catch (error) {
      _fail(
        TlsHandshakeException(error.message),
        StackTrace.current,
      );
      return;
    }
    if (body[offset + 2] != 0) {
      _fail(
        const TlsHandshakeException('compression must be null'),
        StackTrace.current,
      );
      return;
    }
  }

  void _parseCertificate(Uint8List body) {
    if (body.length < 6) {
      _fail(
        const TlsHandshakeException('empty Certificate'),
        StackTrace.current,
      );
      return;
    }
    final listLength = (body[0] << 16) | (body[1] << 8) | body[2];
    if (body.length < 3 + listLength || listLength < 3) {
      _fail(
        const TlsHandshakeException('invalid Certificate list'),
        StackTrace.current,
      );
      return;
    }
    final certLength = (body[3] << 16) | (body[4] << 8) | body[5];
    if (body.length < 6 + certLength) {
      _fail(
        const TlsHandshakeException('invalid certificate entry'),
        StackTrace.current,
      );
      return;
    }
    _peerCertificate = Uint8List.sublistView(body, 6, 6 + certLength);
    final validator = _certificateValidator;
    if (validator == null && !_allowUnverified) {
      _fail(
        const TlsHandshakeException(
          'no certificate validator configured; refusing unverified '
          'connection (enable allowUnverifiedCertificates only for testing)',
        ),
        StackTrace.current,
      );
      return;
    }
    if (validator != null && !validator(_peerCertificate)) {
      _fail(
        const TlsHandshakeException('peer certificate rejected'),
        StackTrace.current,
      );
      return;
    }
    try {
      _serverKey = parseRsaPublicKey(_peerCertificate);
    } on Object catch (error, stackTrace) {
      _fail(error, stackTrace);
      return;
    }
  }

  Future<void> _sendClientFlight() async {
    try {
      final serverKey = _serverKey;
      if (serverKey == null) {
        throw const TlsHandshakeException(
          'server certificate missing RSA key',
        );
      }
      if (_certificateRequested) {
        final emptyCertificate = _handshakeMessage(11, Uint8List(3));
        _handshakeLog.addAll(emptyCertificate);
        await _transport.send(
          _buildTlsRecord(
            tlsContentTypeHandshake,
            _negotiatedVersion,
            emptyCertificate,
          ),
        );
      }
      // ClientKeyExchange: RSAES-PKCS1-v1_5 encrypted 48-byte premaster.
      final premaster = Uint8List(48);
      premaster[0] = (_hello.offeredVersion >> 8) & 0xff;
      premaster[1] = _hello.offeredVersion & 0xff;
      premaster.setRange(2, 48, _randomBytes(46));
      final rsa = PKCS1Encoding(RSAEngine())
        ..init(
          true,
          PublicKeyParameter<RSAPublicKey>(
            RSAPublicKey(serverKey.modulus, serverKey.exponent),
          ),
        );
      final encrypted = rsa.process(premaster);
      final ckeBody = BytesBuilder();
      final ckeLength = ByteData(2)..setUint16(0, encrypted.length);
      ckeBody.add(ckeLength.buffer.asUint8List());
      ckeBody.add(encrypted);
      final cke = _handshakeMessage(16, ckeBody.toBytes());
      _handshakeLog.addAll(cke);
      await _transport.send(
        _buildTlsRecord(tlsContentTypeHandshake, _negotiatedVersion, cke),
      );

      // Key schedule (RFC 5246 sections 6.3 and 8.1).
      final tls12 = _negotiatedVersion == tlsVersion12;
      final master = tlsMasterSecret(
        premaster,
        _clientRandom,
        _serverRandom,
        tls12: tls12,
      );
      _masterSecret = master;
      final keyBlock = tlsKeyBlock(
        master,
        _clientRandom,
        _serverRandom,
        tls12: tls12,
      );
      final clientMac = Uint8List.sublistView(keyBlock, 0, 20);
      final serverMac = Uint8List.sublistView(keyBlock, 20, 40);
      final clientKey = Uint8List.sublistView(keyBlock, 40, 56);
      final serverKeyBytes = Uint8List.sublistView(keyBlock, 56, 72);
      _readCrypto = TlsRecordCrypto(
        cipher: _cipher,
        macKey: serverMac,
        encKey: serverKeyBytes,
        random: _random,
      );
      _writeCrypto = TlsRecordCrypto(
        cipher: _cipher,
        macKey: clientMac,
        encKey: clientKey,
        random: _random,
      );

      // ChangeCipherSpec activates the new write state (sequence resets).
      await _transport.send(
        _buildTlsRecord(
          tlsContentTypeCcs,
          _negotiatedVersion,
          Uint8List.fromList(<int>[1]),
        ),
      );
      final verifyData = _verifyData('client finished');
      final finished = _handshakeMessage(20, verifyData);
      _handshakeLog.addAll(finished);
      await _transport.send(
        _buildTlsRecord(
          tlsContentTypeHandshake,
          _negotiatedVersion,
          _writeCrypto!.seal(tlsContentTypeHandshake, _negotiatedVersion, finished),
        ),
      );
    } on Object catch (error, stackTrace) {
      _fail(error, stackTrace);
    }
  }

  Uint8List _verifyData(String label) {
    final master = _masterSecret;
    if (master == null) {
      throw const TlsHandshakeException('master secret missing');
    }
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
      return tls12Prf(master, label, seed, 12);
    }
    return tls11Prf(master, label, seed, 12);
  }

  bool _verifyServerFinished(Uint8List body) {
    if (body.length != 12 || !_serverCcsReceived) {
      _fail(
        const TlsHandshakeException('invalid server Finished'),
        StackTrace.current,
      );
      return false;
    }
    final expected = _verifyData('server finished');
    for (var index = 0; index < 12; index++) {
      if (body[index] != expected[index]) {
        _fail(
          const TlsHandshakeException('server Finished mismatch'),
          StackTrace.current,
        );
        return false;
      }
    }
    final socket = EasyConnectTlsSocket._(
      _transport,
      _readCrypto,
      _negotiatedVersion,
    );
    socket._writeCrypto = _writeCrypto;
    socket._sessionId = _sessionId;
    socket._peerCertificate = _peerCertificate;
    _socket = socket;
    _done.complete(socket);
    return false;
  }

  void _fail(Object error, StackTrace stackTrace) {
    if (_done.isCompleted) return;
    _done.completeError(error, stackTrace);
  }

  Future<void> _abort() async {
    await _subscription?.cancel();
    _subscription = null;
    await _transport.close();
  }

  String _alertName(int description) => switch (description) {
        0 => 'close_notify',
        40 => 'handshake_failure',
        42 => 'bad_certificate',
        47 => 'illegal_parameter',
        48 => 'unknown_ca',
        _ => 'description $description',
      };
}
