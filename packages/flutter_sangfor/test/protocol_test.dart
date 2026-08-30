import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_sangfor/flutter_sangfor.dart';

void main() {
  test('authentication request resolves endpoint below server root', () {
    final request = SangforAuthRequest(
      server: Uri.parse('https://vpn.example.test/portal?ignored=true'),
      username: 'alice',
      password: 'secret',
      loginDomain: 'corp',
      authType: SangforAuthType.cas,
    );

    expect(request.endpoint,
        Uri.parse('https://vpn.example.test/portal/auth/cas'));
    expect(request.fields, <String, String>{
      'username': 'alice',
      'password': 'secret',
      'authType': 'auth/cas',
      'loginDomain': 'corp',
    });
  });

  test('authentication response defaults safely for incomplete payloads', () {
    expect(
      SangforAuthResponse.fromMap(const <String, Object?>{}).authenticated,
      isFalse,
    );
  });
}
