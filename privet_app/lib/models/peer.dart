import 'dart:convert';

class PeerId {
  final String uuid;
  const PeerId(this.uuid);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PeerId && runtimeType == other.runtimeType && uuid == other.uuid;

  @override
  int get hashCode => uuid.hashCode;

  @override
  String toString() => uuid;
}

class PeerInfo {
  final PeerId id;
  final String name;
  final List<String> addresses;
  final String fingerprint;
  final bool isTrusted;
  final String? platform;

  const PeerInfo({
    required this.id,
    required this.name,
    required this.addresses,
    required this.fingerprint,
    required this.isTrusted,
    this.platform,
  });

  String get displayFingerprint =>
      fingerprint.length >= 12 ? fingerprint.substring(0, 12) : fingerprint;

  factory PeerInfo.fromJson(Map<String, dynamic> json) => PeerInfo(
        id: PeerId(json['id'] as String? ?? ''),
        name: json['name'] as String? ?? '',
        addresses: (json['addresses'] as List<dynamic>?)
                ?.map((e) => e.toString())
                .toList() ??
            [],
        fingerprint: json['fingerprint'] as String? ?? '',
        isTrusted: json['is_trusted'] as bool? ?? false,
        platform: json['platform'] as String?,
      );

  static List<PeerInfo> listFromJson(String jsonStr) {
    final list = jsonDecode(jsonStr) as List<dynamic>;
    return list.map((e) => PeerInfo.fromJson(e as Map<String, dynamic>)).toList();
  }
}
