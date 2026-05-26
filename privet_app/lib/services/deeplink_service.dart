import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter/foundation.dart';

import '../utils/pairing_url.dart';

/// Listens for incoming pairing URLs (`privet://pair?...`) on all platforms
/// and exposes them via a stream.
///
/// On Android, deeplinks arrive via the `privet/deeplink` MethodChannel
/// (configured in `MainActivity.kt`). On iOS, they arrive via the
/// `onOpenUrl` method from the Flutter engine.
class DeeplinkService {
  DeeplinkService._();
  static final DeeplinkService instance = DeeplinkService._();

  static const _channel = MethodChannel('privet/deeplink');

  final _controller = StreamController<ParsedPairingUrl>.broadcast();
  StreamSubscription<ParsedPairingUrl>? _sub;

  /// Stream of parsed pairing URLs.
  Stream<ParsedPairingUrl> get pairingUrls => _controller.stream;

  /// Start listening for incoming deeplinks.
  void start() {
    if (_sub != null) return;

    if (Platform.isAndroid) {
      _channel.setMethodCallHandler(_onMethodCall);
    }
  }

  /// Capture a pairing URL string and parse it.
  /// Returns the parsed URL if valid, null otherwise.
  ParsedPairingUrl? handleUrl(String url) {
    if (kDebugMode) debugPrint('[deeplink] URL: $url');
    final parsed = PairingUrl.parse(url);
    if (parsed != null) {
      _controller.add(parsed);
    }
    return parsed;
  }

  Future<void> _onMethodCall(MethodCall call) async {
    if (call.method == 'onDeeplink') {
      final url = call.arguments as String?;
      if (url != null) {
        handleUrl(url);
      }
    }
  }

  void dispose() {
    _sub?.cancel();
    _controller.close();
  }
}
