import 'package:flutter/foundation.dart';

/// Build and parse pairing URLs in the format:
/// `privet://pair?h=IP1:PORT&h=IP2:PORT&fp=FINGERPRINT&n=NAME`
///
/// "h" (host) is used instead of "addr" to keep the URL compact for QR codes.
class PairingUrl {
  /// Build a pairing URL from the device's identity and current network info.
  ///
  /// [networks] is a list of `{"subnet": ..., "local_ips": [...]}` maps
  /// as returned by `getCurrentNetworks()`.
  /// [port] is the engine listen port (default 53530).
  static String build({
    required String fingerprint,
    required String deviceName,
    required List<Map<String, dynamic>> networks,
    int port = 53530,
  }) {
    final hosts = <String>{};
    for (final net in networks) {
      final ips = net['local_ips'];
      if (ips is List) {
        for (final ip in ips) {
          hosts.add('$ip:$port');
        }
      }
    }

    if (hosts.isEmpty) {
      if (kDebugMode) debugPrint('[pairing_url] no hosts from networks=$networks');
      return '';
    }

    final fp = fingerprint.length >= 12 ? fingerprint.substring(0, 12) : fingerprint;
    final params = {
      'fp': fp,
      'n': deviceName,
    };
    // Add hosts as multiple 'h' params
    final hostParams = hosts.map((h) => 'h=${Uri.encodeComponent(h)}').join('&');
    final otherParams = params.entries
        .map((e) => '${Uri.encodeComponent(e.key)}=${Uri.encodeComponent(e.value)}')
        .join('&');

    final url = 'privet://pair?$hostParams&$otherParams';
    if (kDebugMode) debugPrint('[pairing_url] built URL: $url (fp=${fp.length}chars, ${hosts.length} host(s))');
    return url;
  }

  /// Parse a `privet://pair?...` URL into its components.
  /// Returns null if the URL is not a valid pairing URL.
  static ParsedPairingUrl? parse(String url) {
    final uri = Uri.tryParse(url);
    if (uri == null) return null;
    if (uri.scheme != 'privet') return null;
    if (uri.host != 'pair') return null;

    final params = uri.queryParameters;
    final hosts = <String>[];
    // Read all 'h' params (may appear multiple times)
    for (final entry in uri.queryParametersAll.entries) {
      if (entry.key == 'h') {
        hosts.addAll(entry.value);
      }
    }

    final fingerprint = params['fp'] ?? '';
    final deviceName = params['n'] ?? '';

    if (hosts.isEmpty || fingerprint.isEmpty) return null;

    return ParsedPairingUrl(
      hosts: hosts,
      fingerprint: fingerprint,
      deviceName: deviceName,
    );
  }
}

class ParsedPairingUrl {
  final List<String> hosts; // "IP:PORT" strings
  final String fingerprint;
  final String deviceName;

  const ParsedPairingUrl({
    required this.hosts,
    required this.fingerprint,
    required this.deviceName,
  });

  @override
  String toString() =>
      'ParsedPairingUrl(hosts=$hosts, fingerprint=$fingerprint, name=$deviceName)';
}
