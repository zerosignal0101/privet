import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'pages/shell_page.dart';
import 'providers/providers.dart';
import 'services/deeplink_service.dart';

void main() {
  runApp(const ProviderScope(child: PrivetApp()));
}

class PrivetApp extends ConsumerStatefulWidget {
  const PrivetApp({super.key});

  @override
  ConsumerState<PrivetApp> createState() => _PrivetAppState();
}

class _PrivetAppState extends ConsumerState<PrivetApp> {
  static const _shareChannel = MethodChannel('privet/share');

  @override
  void initState() {
    super.initState();
    _initShareChannel();
    _initDeeplink();
    // Pull any share data that arrived before the handler was registered
    // (cold start via Android SEND intent).
    _pullPendingShare();
  }

  /// Register the push handler for [onShare] events (fired when app is already
  /// running and a new share intent arrives via onNewIntent).
  void _initShareChannel() {
    _shareChannel.setMethodCallHandler((call) async {
      if (call.method == 'onShare') {
        _handleShareData(call.arguments as Map<String, dynamic>?);
      }
    });
  }

  /// Start listening for incoming deeplinks (privet:// URLs from QR codes).
  void _initDeeplink() {
    DeeplinkService.instance.start();
    // Listen for pairing URLs and trigger the pairing flow
    DeeplinkService.instance.pairingUrls.listen((parsed) {
      if (!mounted) return;
      ref.read(urlPairingProvider.notifier).startPairing(parsed);
    });
  }

  /// Pull any share data that was stored on the native side before the Dart
  /// handler was ready (cold start).
  Future<void> _pullPendingShare() async {
    try {
      final args = await _shareChannel.invokeMethod<Map<dynamic, dynamic>>('getPendingShare');
      if (args != null) {
        _handleShareData(args.cast<String, dynamic>());
      }
    } catch (_) {
      // getPendingShare not supported on this platform — ignore
    }
  }

  void _handleShareData(Map<String, dynamic>? args) {
    if (args == null) return;
    final paths = (args['paths'] as List<dynamic>?)
            ?.cast<String>()
            .toList() ??
        [];
    final text = args['text'] as String?;
    if (paths.isEmpty && (text == null || text.trim().isEmpty)) return;
    ref.read(pendingShareProvider.notifier).set(
      PendingShareData(paths: paths, text: text),
    );
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Privet',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
      ),
      home: const ShellPage(),
    );
  }
}
