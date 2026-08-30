import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

/// HMAC hash functions used by the TLS PRFs.
Uint8List _hmacMd5(Uint8List key, List<int> data) =>
    Uint8List.fromList(crypto.Hmac(crypto.md5, key).convert(data).bytes);

Uint8List _hmacSha1(Uint8List key, List<int> data) =>
    Uint8List.fromList(crypto.Hmac(crypto.sha1, key).convert(data).bytes);

Uint8List _hmacSha256(Uint8List key, List<int> data) =>
    Uint8List.fromList(crypto.Hmac(crypto.sha256, key).convert(data).bytes);

typedef _HmacFn = Uint8List Function(Uint8List key, List<int> data);

Uint8List _pHash(
  _HmacFn hmac,
  Uint8List secret,
  Uint8List seed,
  int length,
) {
  final output = <int>[];
  var a = seed;
  while (output.length < length) {
    a = hmac(secret, a);
    output.addAll(hmac(secret, <int>[...a, ...seed]));
  }
  return Uint8List.fromList(output.sublist(0, length));
}

/// TLS 1.2 PRF: P_SHA-256 over the whole secret (RFC 5246 section 5).
Uint8List tls12Prf(
  Uint8List secret,
  String label,
  Uint8List seed,
  int length,
) =>
    _pHash(
      _hmacSha256,
      secret,
      Uint8List.fromList(<int>[...utf8.encode(label), ...seed]),
      length,
    );

/// TLS 1.1 PRF: P_MD5 over the first half XOR P_SHA-1 over the second half
/// (RFC 4346 section 5). Both halves have ceil(len/2) bytes; the middle byte
/// is shared when the secret has odd length.
Uint8List tls11Prf(
  Uint8List secret,
  String label,
  Uint8List seed,
  int length,
) {
  final seedWithLabel =
      Uint8List.fromList(<int>[...utf8.encode(label), ...seed]);
  final half = (secret.length + 1) ~/ 2;
  final s1 = Uint8List.sublistView(secret, 0, half);
  final s2 = Uint8List.sublistView(secret, secret.length - half);
  final md5 = _pHash(_hmacMd5, s1, seedWithLabel, length);
  final sha1 = _pHash(_hmacSha1, s2, seedWithLabel, length);
  final result = Uint8List(length);
  for (var index = 0; index < length; index++) {
    result[index] = md5[index] ^ sha1[index];
  }
  return result;
}

/// Derives the master secret (RFC 5246 section 8.1).
Uint8List tlsMasterSecret(
  Uint8List premaster,
  Uint8List clientRandom,
  Uint8List serverRandom, {
  bool tls12 = true,
}) =>
    (tls12 ? tls12Prf : tls11Prf)(
      premaster,
      'master secret',
      Uint8List.fromList(<int>[...clientRandom, ...serverRandom]),
      48,
    );

/// Derives the key block (RFC 5246 section 6.3). Key order: client MAC,
/// server MAC, client encryption key, server encryption key; no IV entries
/// because both supported suites use per-record explicit IVs (or a stream
/// cipher).
Uint8List tlsKeyBlock(
  Uint8List masterSecret,
  Uint8List clientRandom,
  Uint8List serverRandom, {
  bool tls12 = true,
}) =>
    (tls12 ? tls12Prf : tls11Prf)(
      masterSecret,
      'key expansion',
      Uint8List.fromList(<int>[...serverRandom, ...clientRandom]),
      72,
    );
