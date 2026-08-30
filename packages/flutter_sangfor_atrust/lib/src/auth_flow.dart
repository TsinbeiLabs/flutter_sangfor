/// Secondary authentication service types advertised by aTrust.
enum ATrustAuthService {
  none(''),
  authCheck('auth/authCheck'),
  sms('auth/sms'),
  customSms('auth/customSms'),
  totp('auth/totp'),
  radius('auth/radius'),
  challenge('auth/challenge'),
  accessCheck('auth/accessCheck'),
  preEnhancedAuth('auth/preEnhancedAuth'),
  enhancedConfirm('auth/enhancedConfirm'),
  enhancedDone('auth/enhancedDone'),
  bindAuthDevice('auth/bindAuthDevice'),
  unknown(null);

  const ATrustAuthService(this.value);

  final String? value;

  static ATrustAuthService fromValue(String? value) => values
      .firstWhere((service) => service.value == value, orElse: () => unknown);
}

enum ATrustSmsMode { none, withAuthId, withoutAuthId }

/// One normalized step in the server-directed authentication chain.
class ATrustAuthStep {
  const ATrustAuthStep({
    required this.service,
    this.rawService,
    this.authId,
    this.smsMode = ATrustSmsMode.none,
  });

  factory ATrustAuthStep.fromMap(Map<String, Object?> map) {
    final rawService = map['nextService'] as String?;
    final services = (map['nextServiceList'] as List<Object?>? ?? const [])
        .whereType<Map>()
        .map((item) => Map<String, Object?>.from(item))
        .toList(growable: false);
    final selected = services.cast<Map<String, Object?>?>().firstWhere(
          (item) => item?['authType'] == rawService,
          orElse: () => services.isEmpty ? null : services.first,
        );
    final selectedService = selected?['authType'] as String?;
    var service = rawService ?? selectedService;
    if (service == 'auth/sendSms') service = 'auth/sms';
    if ((service == null || service.isEmpty) && selected?['authId'] != null) {
      service = 'auth/sms';
    }
    final authId = selected?['authId'] as String?;
    final smsMode = service == 'auth/sms'
        ? (authId == null || authId.isEmpty
            ? ATrustSmsMode.withoutAuthId
            : ATrustSmsMode.withAuthId)
        : ATrustSmsMode.none;
    return ATrustAuthStep(
      service: ATrustAuthService.fromValue(service),
      rawService: service,
      authId: authId,
      smsMode: smsMode,
    );
  }

  final ATrustAuthService service;
  final String? rawService;
  final String? authId;
  final ATrustSmsMode smsMode;
}
