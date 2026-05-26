import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:path_provider/path_provider.dart';

import '../providers/providers.dart';
import '../services/clipboard_service.dart';
import 'home_page.dart';
import 'history_page.dart';
import 'settings_page.dart';
import 'send_preparation_page.dart';

/// Bottom navigation shell with 3 tabs: Home, History, Settings.
class ShellPage extends ConsumerStatefulWidget {
  const ShellPage({super.key});

  @override
  ConsumerState<ShellPage> createState() => _ShellPageState();
}

class _ShellPageState extends ConsumerState<ShellPage> with WidgetsBindingObserver {
  static const _shareChannel = MethodChannel('privet/share');

  final _pages = <Widget>[
    const HomePage(),
    const HistoryPage(),
    const SettingsPage(),
  ];

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    // Check for pending share data after the first frame (cold start).
    WidgetsBinding.instance.addPostFrameCallback((_) => _checkPendingShare());
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      // App came to foreground — pull any share data that was waiting
      // (robust fallback for onNewIntent push delivery).
      _pullPendingShare();
    }
  }

  @override
  Widget build(BuildContext context) {
    final currentIndex = ref.watch(shellTabProvider);

    // Watch for pending share data and navigate when it arrives
    ref.listen<PendingShareData?>(pendingShareProvider, (prev, data) {
      if (data != null) {
        _handleShareData(data);
      }
    });

    // Watch for URL pairing (from scanned QR code) and show dialog
    ref.listen<UrlPairingInfo>(urlPairingProvider, (prev, info) {
      if (prev?.status == info.status) return;
      if (info.status == UrlPairingState.found) {
        _showUrlPairingFoundDialog(info);
      } else if (info.status == UrlPairingState.failed) {
        _showUrlPairingFailedDialog(info);
      }
    });

    return Scaffold(
      body: IndexedStack(
        index: currentIndex,
        children: _pages,
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: currentIndex,
        onDestinationSelected: (i) => ref.read(shellTabProvider.notifier).select(i),
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.home_outlined),
            selectedIcon: Icon(Icons.home),
            label: 'Home',
          ),
          NavigationDestination(
            icon: Icon(Icons.history_outlined),
            selectedIcon: Icon(Icons.history),
            label: 'History',
          ),
          NavigationDestination(
            icon: Icon(Icons.settings_outlined),
            selectedIcon: Icon(Icons.settings),
            label: 'Settings',
          ),
        ],
      ),
    );
  }

  /// Pull pending share data from the native side and feed it through
  /// [pendingShareProvider] so [ref.listen] drives the navigation.
  /// This is the single path for both cold-start and on-resume fallback.
  Future<void> _pullPendingShare() async {
    try {
      final args = await _shareChannel.invokeMethod<Map<dynamic, dynamic>>('getPendingShare');
      if (args == null) return;
      final paths = (args['paths'] as List<dynamic>?)
              ?.cast<String>()
              .toList() ?? [];
      final text = args['text'] as String?;
      if (paths.isEmpty && (text == null || text.trim().isEmpty)) return;
      ref.read(pendingShareProvider.notifier).set(
        PendingShareData(paths: paths, text: text),
      );
    } catch (_) {
      // Channel not available on this platform
    }
  }

  void _checkPendingShare() {
    final data = ref.read(pendingShareProvider);
    if (data != null) {
      _handleShareData(data);
    }
  }

  Future<void> _handleShareData(PendingShareData data) async {
    // Clear immediately so it won't re-trigger via ref.listen
    ref.read(pendingShareProvider.notifier).clear();
    // Consume native-side pending data so the next resume pull is a no-op.
    try { _shareChannel.invokeMethod('getPendingShare'); } catch (_) {}

    final entries = <SendFileEntry>[];

    // Shared file URIs — already copied to cache by native side
    for (final path in data.paths) {
      final file = File(path);
      if (file.existsSync()) {
        entries.add(SendFileEntry(
          absolutePath: path,
          relativePath: path.split(Platform.pathSeparator).last,
          size: file.lengthSync(),
        ));
      }
    }

    // Shared text — save as .txt file
    if (data.text != null && data.text!.trim().isNotEmpty) {
      try {
        final dir = (await getApplicationDocumentsDirectory()).path;
        final name = ClipboardService.textFilename(data.text!);
        final (path: txtPath, relativePath: relPath) =
            ClipboardService.uniqueFile(dir, '$name.txt');
        await File(txtPath).writeAsString(data.text!);
        entries.add(SendFileEntry(
          absolutePath: txtPath,
          relativePath: relPath,
          size: File(txtPath).lengthSync(),
        ));
      } catch (e) {
        debugPrint('[share] failed to save shared text: $e');
      }
    }

    if (entries.isEmpty || !mounted) return;

    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => SendPreparationPage(initialEntries: entries),
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // URL Pairing dialogs (from scanned QR code)
  // ---------------------------------------------------------------------------

  void _showUrlPairingFoundDialog(UrlPairingInfo info) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Device Found'),
        content: Text(
          'Found ${info.deviceName} from QR code.\n\n'
          'Fingerprint verified. Do you want to trust this device?',
        ),
        actions: [
          TextButton(
            onPressed: () {
              ref.read(urlPairingProvider.notifier).cancel();
              Navigator.pop(ctx);
            },
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () async {
              await ref.read(urlPairingProvider.notifier).confirmTrust();
              if (ctx.mounted) Navigator.pop(ctx);
              if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text('${info.deviceName} is now trusted'),
                    duration: const Duration(seconds: 2),
                  ),
                );
              }
            },
            child: const Text('Trust'),
          ),
        ],
      ),
    );
  }

  void _showUrlPairingFailedDialog(UrlPairingInfo info) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Pairing Failed'),
        content: Text(info.error ?? 'Could not connect to the device.'),
        actions: [
          FilledButton(
            onPressed: () {
              ref.read(urlPairingProvider.notifier).cancel();
              Navigator.pop(ctx);
            },
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }
}
