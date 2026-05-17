import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';

import '../providers/providers.dart';
import '../services/privet/privet_service.dart';

class SettingsPage extends ConsumerWidget {
  const SettingsPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final settings = ref.watch(settingsProvider);
    final identity = ref.watch(identityProvider);

    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        children: [
          // Device identity
          if (identity.value != null) ...[
            ListTile(
              leading: const Icon(Icons.fingerprint),
              title: const Text('Device Fingerprint'),
              subtitle: Text(identity.value!.displayFingerprint),
            ),
            const Divider(),
          ],

          // Device name
          ListTile(
            leading: const Icon(Icons.badge),
            title: const Text('Device Name'),
            subtitle: Text(settings.deviceName),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _editDeviceName(context, ref, settings.deviceName),
          ),

          // Download directory
          ListTile(
            leading: const Icon(Icons.folder),
            title: const Text('Download Directory'),
            subtitle: Text(
              settings.downloadDir.isEmpty ? 'Default' : settings.downloadDir,
              overflow: TextOverflow.ellipsis,
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _pickDownloadDir(ref),
          ),

          const Divider(),

          // Auto-accept trusted
          SwitchListTile(
            secondary: const Icon(Icons.auto_mode),
            title: const Text('Auto-Accept Trusted'),
            subtitle: const Text('Automatically accept files from trusted peers'),
            value: settings.autoAcceptTrusted,
            onChanged: (v) =>
                ref.read(settingsProvider.notifier).setAutoAcceptTrusted(v),
          ),

          // TCP fallback
          SwitchListTile(
            secondary: const Icon(Icons.lan),
            title: const Text('TCP Fallback'),
            subtitle: const Text('Fall back to TCP if QUIC/UDP is blocked'),
            value: settings.enableTcpFallback,
            onChanged: (v) =>
                ref.read(settingsProvider.notifier).setEnableTcpFallback(v),
          ),

          const Divider(),

          // Restart engine
          ListTile(
            leading: const Icon(Icons.restart_alt),
            title: const Text('Restart Engine'),
            subtitle: const Text('Apply settings changes by restarting the engine'),
            onTap: () => _restartEngine(context, ref),
          ),
        ],
      ),
    );
  }

  Future<void> _editDeviceName(
    BuildContext context,
    WidgetRef ref,
    String current,
  ) async {
    final controller = TextEditingController(text: current);
    final name = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Device Name'),
        content: TextField(controller: controller),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, controller.text),
            child: const Text('Save'),
          ),
        ],
      ),
    );
    if (name != null && name.isNotEmpty) {
      await ref.read(settingsProvider.notifier).setDeviceName(name);
    }
  }

  Future<void> _pickDownloadDir(WidgetRef ref) async {
    final result = await FilePicker.platform.getDirectoryPath();
    if (result != null) {
      await ref.read(settingsProvider.notifier).setDownloadDir(result);
    }
  }

  Future<void> _restartEngine(BuildContext context, WidgetRef ref) async {
    final service = PrivetService.instance;
    await service.stop();

    // Get data directory for mobile platforms.
    String? dataDir;
    try {
      final dir = await getApplicationDocumentsDirectory();
      dataDir = dir.path;
    } catch (_) {}

    final settings = ref.read(settingsProvider);
    final ok = await service.start(deviceName: settings.deviceName, dataDir: dataDir);
    ref.read(engineRunningProvider.notifier).setRunning(ok);

    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(ok ? 'Engine restarted' : 'Failed to restart')),
      );
    }
  }
}
