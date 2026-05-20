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
    final knownDevices = ref.watch(knownDevicesProvider);
    final currentNetworks = ref.watch(currentNetworksProvider);

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
                  title: const Text('Trust Required (Default)'),
                  subtitle: const Text('Manual pairing and trust; auto-accept from trusted devices'),
                  secondary: const Icon(Icons.shield_outlined),
                  value: 'trust_required',
                ),
                RadioListTile<String>(
                  title: const Text('Allow All'),
                  subtitle: const Text('Auto-trust unknown devices and auto-accept all transfers'),
                  secondary: const Icon(Icons.public),
                  value: 'allow_all',
                ),
                RadioListTile<String>(
                  title: const Text('Strict'),
                  subtitle: const Text('Manual pairing; auto-accept from approved devices, manual confirm for others'),
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

          // Listen port
          ListTile(
            leading: const Icon(Icons.settings_ethernet),
            title: const Text('Listen Port'),
            subtitle: Text('${settings.listenPort}'),
            trailing: const Icon(Icons.edit),
            onTap: () => _editPort(context, ref, settings.listenPort),
          ),

          const Divider(),

          // Current Network(s)
          _CurrentNetworkSection(currentNetworks: currentNetworks),
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

          // Known Devices management
          _KnownDevicesSection(
            knownDevices: knownDevices,
            onRefresh: () => ref.read(knownDevicesProvider.notifier).refresh(),
            onEdit: (device) => _editKnownDevice(context, ref, device),
            onDelete: (fingerprint) => _deleteKnownDevice(context, ref, fingerprint),
            onAddIp: (device) => _addDeviceIp(context, ref, device),
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

  Future<void> _editPort(BuildContext context, WidgetRef ref, int currentPort) async {
    final controller = TextEditingController(text: currentPort.toString());
    final confirmed = await showDialog<int>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Listen Port'),
        content: TextField(
          controller: controller,
          keyboardType: TextInputType.number,
          decoration: const InputDecoration(
            labelText: 'Port (1–65535)',
            hintText: '53530',
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          TextButton(
            onPressed: () {
              final value = int.tryParse(controller.text.trim());
              if (value == null || value < 1 || value > 65535) {
                ScaffoldMessenger.of(ctx).showSnackBar(
                  const SnackBar(content: Text('Invalid port number')),
                );
                return;
              }
              Navigator.pop(ctx, value);
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
    if (confirmed != null && confirmed != currentPort) {
      await ref.read(settingsProvider.notifier).setListenPort(confirmed);
    }
    controller.dispose();
  }

  Future<void> _editKnownDevice(
    BuildContext context,
    WidgetRef ref,
    Map<String, dynamic> device,
  ) async {
    await showDialog(
      context: context,
      builder: (ctx) => _DeviceDetailDialog(device: device),
    );
  }

  Future<void> _deleteKnownDevice(
    BuildContext context,
    WidgetRef ref,
    String fingerprint,
  ) async {
    final name = ref.read(knownDevicesProvider)
        .where((d) => d['fingerprint'] == fingerprint)
        .map((d) => d['device_name'] as String? ?? 'this device')
        .firstOrNull ?? 'this device';
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Remove Known Device?'),
        content: Text('Remove $name from known devices?\nIt will be re-discovered if still reachable.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          TextButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Remove')),
        ],
      ),
    );
    if (confirmed != true) return;

    final service = PrivetService.instance;
    final knownDevices = ref.read(knownDevicesProvider);
    for (final device in knownDevices) {
      if (device['fingerprint'] == fingerprint) {
        final networks = device['networks'] as Map<String, dynamic>? ?? {};
        for (final subnet in networks.keys) {
          await service.removeKnownDeviceIp(
            fingerprint: fingerprint,
            subnet: subnet,
            addr: '',
          );
        }
      }
    }
    await ref.read(knownDevicesProvider.notifier).refresh();
  }

  Future<void> _addDeviceIp(
    BuildContext context,
    WidgetRef ref,
    Map<String, dynamic> device,
  ) async {
    final subnetController = TextEditingController();
    final addrController = TextEditingController();
    final labelController = TextEditingController();

    final result = await showDialog<Map<String, String>>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Add Network IP'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: subnetController,
              decoration: const InputDecoration(
                labelText: 'Subnet (e.g. 192.168.1.0/24)',
                hintText: '192.168.1.0/24',
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: addrController,
              decoration: const InputDecoration(
                labelText: 'IP:Port (e.g. 192.168.1.100:53530)',
                hintText: '192.168.1.100:53530',
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: labelController,
              decoration: const InputDecoration(
                labelText: 'Network Label (e.g. Office Network)',
                hintText: 'Office Network',
              ),
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          TextButton(
            onPressed: () => Navigator.pop(ctx, {
              'subnet': subnetController.text,
              'addr': addrController.text,
              'label': labelController.text,
            }),
            child: const Text('Add'),
          ),
        ],
      ),
    );

    if (result != null) {
      final service = PrivetService.instance;
      await service.addKnownDeviceIp(
        fingerprint: device['fingerprint'] as String? ?? '',
        peerId: device['peer_id'] as String? ?? '',
        deviceName: device['device_name'] as String? ?? '',
        subnet: result['subnet'] ?? '',
        addr: result['addr'] ?? '',
        label: result['label'],
      );
      await ref.read(knownDevicesProvider.notifier).refresh();
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
    if (ok) {
      ref.read(activeTransfersProvider.notifier).clear();
    }

    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(ok ? 'Engine restarted' : 'Failed to restart')),
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Current Network section
// ---------------------------------------------------------------------------

class _CurrentNetworkSection extends StatelessWidget {
  final List<Map<String, dynamic>> currentNetworks;

  const _CurrentNetworkSection({required this.currentNetworks});

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
          child: Row(
            children: [
              Text(
                'Current Network(s)',
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const Spacer(),
              if (currentNetworks.isEmpty)
                const SizedBox(
                  width: 16, height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                ),
            ],
          ),
        ),
        if (currentNetworks.isEmpty)
          const Padding(
            padding: EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: Text('Detecting network...', style: TextStyle(color: Colors.grey)),
          )
        else
          ...currentNetworks.map((net) => ListTile(
                dense: true,
                leading: const Icon(Icons.wifi, size: 20),
                title: Text(
                  net['subnet'] as String? ?? 'Unknown',
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
                ),
                subtitle: Text(
                  (net['local_ips'] as List<dynamic>?)
                      ?.map((ip) => ip.toString())
                      .join(', ') ?? '',
                  style: const TextStyle(fontSize: 11),
                ),
              )),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Known Devices section
// ---------------------------------------------------------------------------

class _KnownDevicesSection extends StatelessWidget {
  final List<Map<String, dynamic>> knownDevices;
  final VoidCallback onRefresh;
  final void Function(Map<String, dynamic>) onEdit;
  final void Function(String fingerprint) onDelete;
  final void Function(Map<String, dynamic>) onAddIp;

  const _KnownDevicesSection({
    required this.knownDevices,
    required this.onRefresh,
    required this.onEdit,
    required this.onDelete,
    required this.onAddIp,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
          child: Row(
            children: [
              Text(
                'Known Devices',
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.refresh, size: 20),
                onPressed: onRefresh,
                tooltip: 'Refresh known devices',
              ),
            ],
          ),
        ),
        if (knownDevices.isEmpty)
          const Padding(
            padding: EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: Text(
              'No known devices. Devices discovered via mDNS/beacon or manually sent will appear here.',
              style: TextStyle(color: Colors.grey, fontSize: 12),
            ),
          )
        else
          ...knownDevices.map((device) => _KnownDeviceTile(
                device: device,
                onEdit: () => onEdit(device),
                onAddIp: () => onAddIp(device),
                onDelete: () => onDelete(device['fingerprint'] as String? ?? ''),
              )),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Known Device Tile
// ---------------------------------------------------------------------------

class _KnownDeviceTile extends StatelessWidget {
  final Map<String, dynamic> device;
  final VoidCallback onEdit;
  final VoidCallback onAddIp;
  final VoidCallback onDelete;

  const _KnownDeviceTile({
    required this.device,
    required this.onEdit,
    required this.onAddIp,
    required this.onDelete,
  });

  @override
  Widget build(BuildContext context) {
    final name = device['device_name'] as String? ?? 'Unknown';
    final fingerprint = device['fingerprint'] as String? ?? '';
    final shortFp = fingerprint.length > 12
        ? fingerprint.substring(0, 12)
        : fingerprint;
    final networks = device['networks'] as Map<String, dynamic>? ?? {};

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: Padding(
        padding: const EdgeInsets.all(8),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            ListTile(
              dense: true,
              leading: const Icon(Icons.devices, size: 20),
              title: Text(name, style: const TextStyle(fontWeight: FontWeight.w500)),
              subtitle: Text(shortFp,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: Colors.grey)),
              trailing: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  IconButton(
                    icon: const Icon(Icons.add_link, size: 18),
                    onPressed: onAddIp,
                    tooltip: 'Add network IP',
                  ),
                  IconButton(
                    icon: const Icon(Icons.delete_outline, size: 18, color: Colors.red),
                    onPressed: onDelete,
                    tooltip: 'Remove device',
                  ),
                ],
              ),
            ),
            // Show each network entry
            ...networks.entries.map((entry) {
              final subnet = entry.key;
              final netInfo = entry.value as Map<String, dynamic>;
              final addrs = (netInfo['addresses'] as List<dynamic>?)
                      ?.cast<String>() ?? [];
              final label = netInfo['label'] as String?;

              return Padding(
                padding: const EdgeInsets.only(left: 48, bottom: 4),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.lan, size: 14, color: Colors.grey.shade600),
                        const SizedBox(width: 4),
                        Text(
                          label ?? subnet,
                          style: TextStyle(
                            fontSize: 12,
                            color: Colors.grey.shade700,
                            fontFamily: 'monospace',
                          ),
                        ),
                      ],
                    ),
                    ...addrs.map((addr) => Padding(
                      padding: const EdgeInsets.only(left: 18),
                      child: Text(
                        addr,
                        style: TextStyle(fontSize: 11, color: Colors.grey.shade500),
                      ),
                    )),
                  ],
                ),
              );
            }),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Device Detail Dialog
// ---------------------------------------------------------------------------

class _DeviceDetailDialog extends ConsumerWidget {
  final Map<String, dynamic> device;

  const _DeviceDetailDialog({required this.device});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final name = device['device_name'] as String? ?? 'Unknown';
    final fingerprint = device['fingerprint'] as String? ?? '';
    final networks = device['networks'] as Map<String, dynamic>? ?? {};

    return AlertDialog(
      title: Text(name),
      content: SizedBox(
        width: double.maxFinite,
        child: ListView(
          shrinkWrap: true,
          children: [
            ListTile(
              title: const Text('Fingerprint'),
              subtitle: Text(
                fingerprint,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
              ),
            ),
            const Divider(),
            Text('Network IP Mappings',
              style: Theme.of(context).textTheme.titleSmall,
            ),
            if (networks.isEmpty)
              const Padding(
                padding: EdgeInsets.all(8),
                child: Text('No network mappings', style: TextStyle(color: Colors.grey)),
              )
            else
              ...networks.entries.map((entry) {
                final subnet = entry.key;
                final netInfo = entry.value as Map<String, dynamic>;
                final addrs = (netInfo['addresses'] as List<dynamic>?)
                        ?.cast<String>() ?? [];
                final label = netInfo['label'] as String?;
                final lastSeen = netInfo['last_seen'] as String?;

                return ListTile(
                  dense: true,
                  title: Text(label ?? subnet,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
                  subtitle: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      ...addrs.map((a) => Text(a, style: const TextStyle(fontSize: 11))),
                      if (lastSeen != null)
                        Text('Last seen: $lastSeen', style: const TextStyle(fontSize: 10, color: Colors.grey)),
                    ],
                  ),
                  trailing: IconButton(
                    icon: const Icon(Icons.delete_outline, size: 16, color: Colors.red),
                    onPressed: () async {
                      final service = PrivetService.instance;
                      await service.removeKnownDeviceIp(
                        fingerprint: fingerprint,
                        subnet: subnet,
                        addr: '',
                      );
                      await ref.read(knownDevicesProvider.notifier).refresh();
                      if (context.mounted) Navigator.pop(context);
                    },
                  ),
                );
              }),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Close'),
        ),
      ],
    );
  }
}
