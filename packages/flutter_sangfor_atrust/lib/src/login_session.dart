import 'package:http/http.dart' as http;
import 'package:flutter_sangfor/flutter_sangfor.dart';

import 'api.dart';
import 'anti_mitm.dart';
import 'auth_flow.dart';
import 'password_auth.dart';
import 'resource.dart';
import 'secondary_auth.dart';
import 'session.dart';
import 'snapshot.dart';

typedef ATrustSmsCodeProvider = Future<String> Function(ATrustAuthStep step);
typedef ATrustCodeProvider = Future<String> Function(ATrustAuthStep step);

class ATrustLoginOptions {
  const ATrustLoginOptions({
    required this.server,
    required this.username,
    required this.password,
    required this.loginDomain,
    required this.deviceId,
    this.smsCodeProvider,
    this.totpCodeProvider,
    this.radiusCodeProvider,
    this.customSmsCodeProvider,
  });

  final Uri server;
  final String username;
  final String password;
  final String loginDomain;
  final String deviceId;
  final ATrustSmsCodeProvider? smsCodeProvider;
  final ATrustCodeProvider? totpCodeProvider;
  final ATrustCodeProvider? radiusCodeProvider;
  final ATrustCodeProvider? customSmsCodeProvider;
}

/// Authenticated aTrust data. It does not imply that a tunnel is active.
class ATrustAuthenticatedSession {
  const ATrustAuthenticatedSession({
    required this.username,
    required this.sid,
    required this.resource,
    this.antiMitm,
  });

  final String username;
  final String sid;
  final ATrustResource resource;

  /// Anti-MITM identity data advertised by the server; tunnel connections
  /// use it to pin node TLS certificates when digests are available.
  final ATrustAntiMitmData? antiMitm;
}

class ATrustUnsupportedChallenge implements Exception {
  const ATrustUnsupportedChallenge(this.step);

  final ATrustAuthStep step;

  @override
  String toString() =>
      'ATrustUnsupportedChallenge: ${step.rawService ?? step.service.name}';
}

/// Coordinates the currently implemented aTrust authentication stages.
class ATrustLoginSession {
  ATrustLoginSession({http.Client? client})
      : _sessionClient = client is ATrustSessionClient
            ? client
            : ATrustSessionClient(inner: client);

  final ATrustSessionClient _sessionClient;

  ATrustSessionClient get sessionClient => _sessionClient;

  Future<ATrustAuthenticatedSession> login(ATrustLoginOptions options) async {
    final api = ATrustApiClient(client: _sessionClient);
    final config = await api.fetchAuthConfig(options.server);
    if (config.csrfToken == null || config.csrfToken!.isEmpty) {
      throw const ATrustApiException('aTrust CSRF token is missing');
    }

    var ticket = '';
    if (!config.isLoggedIn) {
      final methodAvailable = config.authMethods.any(
        (method) =>
            method.authType == 'auth/psw' &&
            method.loginDomain == options.loginDomain,
      );
      if (!methodAvailable) {
        throw const ATrustApiException(
          'requested password authentication method is not available',
        );
      }
      final result = await ATrustPasswordAuthenticator(client: _sessionClient)
          .authenticate(
        server: options.server,
        username: options.username,
        password: options.password,
        loginDomain: options.loginDomain,
        config: config,
        deviceId: options.deviceId,
      );
      if (result.graphCheckCodeRequired) {
        throw const ATrustApiException(
          'graph check code is required but no challenge handler is configured',
        );
      }
      ticket = result.ticket;
      final sessionApi = ATrustSessionApi(
        server: options.server,
        csrfToken: config.csrfToken!,
        client: _sessionClient,
      );
      await sessionApi.reportEnvironment(
        ticket: ticket,
        deviceId: options.deviceId,
      );
      await _completeSecondaryAuth(
        options,
        ATrustSecondaryAuthenticator(
          server: options.server,
          csrfToken: config.csrfToken!,
          client: _sessionClient,
        ),
      );
    }

    final sessionApi = ATrustSessionApi(
      server: options.server,
      csrfToken: config.csrfToken!,
      client: _sessionClient,
    );
    final onlineInfo = await sessionApi.fetchOnlineInfo();
    final resourceEnvelope = await api.fetchClientResource(
      server: options.server,
      csrfToken: config.csrfToken!,
    );
    final sid = _sessionClient.sid;
    if (sid == null || sid.isEmpty) {
      throw const ATrustApiException('authenticated session SID is missing');
    }
    return ATrustAuthenticatedSession(
      username: onlineInfo.username,
      sid: sid,
      resource: const ATrustResourceParser().parse(
        resourceEnvelope,
        serverHost: options.server.host,
      ),
      antiMitm: config.antiMitm,
    );
  }

  Future<ATrustAuthenticatedSession> resume(
    ATrustSessionSnapshot snapshot,
  ) async {
    if (!snapshot.server.hasScheme || snapshot.server.scheme != 'https') {
      throw const SangforException(
        SangforErrorCode.invalidOptions,
        'aTrust session server must use HTTPS',
      );
    }
    if (snapshot.csrfToken.isEmpty || snapshot.sid == null) {
      throw const SangforException(
        SangforErrorCode.sessionExpired,
        'aTrust session snapshot has no usable authentication state',
      );
    }
    _sessionClient.restoreCookies(snapshot.cookies);
    final api = ATrustApiClient(client: _sessionClient);
    final sessionApi = ATrustSessionApi(
      server: snapshot.server,
      csrfToken: snapshot.csrfToken,
      client: _sessionClient,
    );
    try {
      final config = await api.fetchAuthConfig(snapshot.server);
      final onlineInfo = await sessionApi.fetchOnlineInfo();
      final resourceEnvelope = await api.fetchClientResource(
        server: snapshot.server,
        csrfToken: snapshot.csrfToken,
      );
      return ATrustAuthenticatedSession(
        username: onlineInfo.username,
        sid: snapshot.sid!,
        resource: const ATrustResourceParser().parse(
          resourceEnvelope,
          serverHost: snapshot.server.host,
        ),
        antiMitm: config.antiMitm,
      );
    } on ATrustApiException catch (error, stackTrace) {
      final message = error.message.toLowerCase();
      if (error.statusCode == 401 ||
          error.statusCode == 403 ||
          message.contains('login') ||
          message.contains('session')) {
        throw SangforException(
          SangforErrorCode.sessionExpired,
          'The aTrust session has expired',
          cause: error,
          stackTrace: stackTrace,
        );
      }
      rethrow;
    }
  }

  Future<void> _completeSecondaryAuth(
    ATrustLoginOptions options,
    ATrustSecondaryAuthenticator authenticator,
  ) async {
    var step = await authenticator.authCheck();
    for (var count = 0; step.service != ATrustAuthService.none; count++) {
      if (count >= 8) {
        throw const ATrustApiException(
          'authentication chain exceeded 8 steps',
        );
      }
      switch (step.service) {
        case ATrustAuthService.sms:
          final provider = options.smsCodeProvider;
          if (provider == null) throw ATrustUnsupportedChallenge(step);
          await authenticator.sendSms(step);
          final code = await provider(step);
          step = await authenticator.verifySms(step: step, code: code);
        case ATrustAuthService.customSms:
          final provider = options.customSmsCodeProvider;
          if (provider == null) throw ATrustUnsupportedChallenge(step);
          step = await authenticator.verifyCustomSms(
            code: await provider(step),
          );
        case ATrustAuthService.totp:
          final provider = options.totpCodeProvider;
          if (provider == null) throw ATrustUnsupportedChallenge(step);
          step = await authenticator.verifyTotp(
            code: await provider(step),
            username: '${options.username}@${options.loginDomain}',
          );
        case ATrustAuthService.radius:
        case ATrustAuthService.challenge:
          final provider = options.radiusCodeProvider;
          if (provider == null) throw ATrustUnsupportedChallenge(step);
          step = await authenticator.verifyRadius(
            code: await provider(step),
            step: step,
            username: '${options.username}@${options.loginDomain}',
          );
        case ATrustAuthService.accessCheck:
          step = await authenticator.accessCheck();
        case ATrustAuthService.preEnhancedAuth:
        case ATrustAuthService.enhancedConfirm:
        case ATrustAuthService.enhancedDone:
          step = await authenticator.continueEnhanced(step);
        case ATrustAuthService.bindAuthDevice:
          step = await authenticator.bindCurrentDevice(
            step: step,
            deviceId: options.deviceId,
          );
        default:
          throw ATrustUnsupportedChallenge(step);
      }
    }
  }
}
