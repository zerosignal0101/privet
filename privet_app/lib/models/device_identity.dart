class DeviceIdentity {
  final String fingerprint;
  final String deviceName;

  const DeviceIdentity({required this.fingerprint, required this.deviceName});

  String get displayFingerprint =>
      fingerprint.length >= 12 ? fingerprint.substring(0, 12) : fingerprint;

  factory DeviceIdentity.fromJson(Map<String, dynamic> json) => DeviceIdentity(
        fingerprint: json['fingerprint'] as String? ?? '',
        deviceName: json['device_name'] as String? ?? '',
      );
}
