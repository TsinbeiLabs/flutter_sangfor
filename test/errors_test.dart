import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_sangfor/flutter_sangfor.dart';

void main() {
  test('cancellation token races an operation', () async {
    final token = SangforCancellationToken();
    final operation = Future<void>.delayed(const Duration(seconds: 1));
    token.cancel();

    await expectLater(
      token.race(operation),
      throwsA(
        isA<SangforException>().having(
          (error) => error.code,
          'code',
          SangforErrorCode.cancelled,
        ),
      ),
    );
  });

  test('connect options expose bounded defaults', () {
    final options = SangforConnectOptions(
      server: Uri.parse('https://vpn.example.test'),
      username: 'user',
      password: 'password',
    );

    expect(options.timeout, const Duration(seconds: 30));
    expect(options.cancellationToken, isNull);
  });

  test('authenticated state round trips from native values', () {
    expect(
      SangforConnectionState.fromValue('authenticated'),
      SangforConnectionState.authenticated,
    );
  });

  test('connect options validate servers, usernames, and timeouts', () {
    final valid = SangforConnectOptions(
      server: Uri.parse('https://vpn.example.test'),
      username: 'user',
      password: 'password',
    );
    expect(valid.validate, returnsNormally);

    expect(
      () => SangforConnectOptions(
        server: Uri.parse('http://vpn.example.test'),
        username: 'user',
        password: 'password',
      ).validate(),
      throwsA(
        isA<SangforException>().having(
          (error) => error.code,
          'code',
          SangforErrorCode.invalidOptions,
        ),
      ),
    );
    expect(
      () => SangforConnectOptions(
        server: Uri.parse('https://vpn.example.test'),
        username: '  ',
        password: 'password',
      ).validate(),
      throwsA(isA<SangforException>()),
    );
    expect(
      () => SangforConnectOptions(
        server: Uri.parse('https://vpn.example.test'),
        username: 'user',
        password: 'password',
        timeout: Duration.zero,
      ).validate(),
      throwsA(isA<SangforException>()),
    );
  });

  test('sessions compare dry-run flags and DNS lists', () {
    const first = SangforSession(
      state: SangforConnectionState.authenticated,
      dryRun: true,
      dnsServers: <String>['10.0.0.53'],
    );
    const second = SangforSession(
      state: SangforConnectionState.authenticated,
      dryRun: true,
      dnsServers: <String>['10.0.0.53'],
    );
    const different = SangforSession(
      state: SangforConnectionState.authenticated,
      dryRun: false,
    );
    expect(first, second);
    expect(first.hashCode, second.hashCode);
    expect(first, isNot(different));
    expect(
      SangforSession.fromMap(<String, Object?>{
        'state': 'authenticated',
        'dryRun': true,
      }).dryRun,
      isTrue,
    );
  });
}
