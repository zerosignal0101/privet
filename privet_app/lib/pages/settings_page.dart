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
    final trusted = ref.watch(trustedListProvider);
    final accepted = ref.watch(acceptedListProvider);

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

          // Security mode selection
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
            child: Text(
              'Security Mode',
              style: Theme.of(context).textTheme.titleMedium,
            ),
          ),
          RadioGroup<String>(
            groupValue: settings.securityMode,
            onChanged: (v) { if (v != null) ref.read(settingsProvider.notifier).setSecurityMode(v); },
            child: Column(
              children: [
                RadioListTile<String>(
                  title: const Text('Trust Required (默认)'),
                  subtitle: const Text('手动配对信任，信任后自动接收文件'),
                  secondary: const Icon(Icons.shield_outlined),
                  value: 'trust_required',
                ),
                RadioListTile<String>(
                  title: const Text('Allow All'),
                  subtitle: const Text('自动信任未知设备，自动接受所有传输'),
                  secondary: const Icon(Icons.public),
                  value: 'allow_all',
                ),
                RadioListTile<String>(
                  title: const Text('Strict'),
                  subtitle: const Text('手动配对，特殊准许设备自动接收，其余需手动确认'),
                  secondary: const Icon(Icons.security),
                  value: 'strict',
                ),
              ],
            ),
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

          // Trusted Devices management
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
            child: Text(
              'Trusted Devices',
              style: Theme.of(context).textTheme.titleMedium,
            ),
          ),
          if (trusted.isEmpty)
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              child: Text('No trusted devices', style: TextStyle(color: Colors.grey)),
            )
          else
            ...trusted.map((fp) => ListTile(
                  dense: true,
                  leading: const Icon(Icons.verified_user, size: 20),
                  title: Text(
                    fp.length > 16 ? '${fp.substring(0, 16)}...' : fp,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
                  ),
                  trailing: IconButton(
                    icon: const Icon(Icons.delete_outline, size: 20),
                    onPressed: () => _confirmUntrust(context, ref, fp),
                  ),
                )),

          const SizedBox(height: 8),

          // Accepted (auto-accept) Devices management
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
            child: Text(
              'Auto-Accept Devices',
              style: Theme.of(context).textTheme.titleMedium,
            ),
          ),
          if (accepted.isEmpty)
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              child: Text('No auto-accept devices', style: TextStyle(color: Colors.grey)),
            )
          else
            ...accepted.map((fp) => ListTile(
                  dense: true,
                  leading: const Icon(Icons.auto_mode, size: 20),
                  title: Text(
                    fp.length > 16 ? '${fp.substring(0, 16)}...' : fp,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
                  ),
                  trailing: IconButton(
                    icon: const Icon(Icons.delete_outline, size: 20),
                    onPressed: () => _confirmUnaccept(context, ref, fp),
                  ),
                )),

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

  Future<void> _confirmUntrust(BuildContext context, WidgetRef ref, String fp) async {
    final short = fp.length > 16 ? '${fp.substring(0, 16)}...' : fp;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Remove Trust?'),
        content: Text('Remove trust for $short?\nThis will also remove auto-accept if set.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          TextButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Remove')),
        ],
      ),
    );
    if (confirmed == true) {
      await ref.read(trustedListProvider.notifier).untrust(fp);
      await ref.read(acceptedListProvider.notifier).refresh();
    }
  }

  Future<void> _confirmUnaccept(BuildContext context, WidgetRef ref, String fp) async {
    final short = fp.length > 16 ? '${fp.substring(0, 16)}...' : fp;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Remove Auto-Accept?'),
        content: Text('Remove auto-accept for $short?\nThe device will remain trusted.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          TextButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Remove')),
        ],
      ),
    );
    if (confirmed == true) {
      await ref.read(acceptedListProvider.notifier).unaccept(fp);
    }
  }

  Future<void> _restartEngine(BuildContext context, WidgetRef ref) async {
    final service = PrivetService.instance;
    await service.stop();

    String? dataDir;
    try {
      final dir = await getApplicationDocumentsDirectory();
      dataDir = dir.path;
    } catch (_) {}

    final settings = ref.read(settingsProvider);
    final ok = await service.start(
      deviceName: settings.deviceName,
      dataDir: dataDir,
      downloadDir: settings.downloadDir.isNotEmpty ? settings.downloadDir : null,
      securityMode: settings.securityMode,
    );
    ref.read(engineRunningProvider.notifier).setRunning(ok);

    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(ok ? 'Engine restarted' : 'Failed to restart')),
      );
    }
  }
}
