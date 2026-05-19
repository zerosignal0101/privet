import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../providers/providers.dart';

/// Bottom sheet for picking a peer to send files to.
/// Shows: discovered peers, probed devices, known devices, "Send by Address" option.
class PeerPickerSheet extends ConsumerWidget {
  final void Function(String address, {String? name, String? fingerprint}) onSelected;

  const PeerPickerSheet({super.key, required this.onSelected});

  static Future<void> show(
    BuildContext context, {
    required void Function(String address, {String? name, String? fingerprint}) onSelected,
  }) {
    return showModalBottomSheet(
      context: context,
      builder: (_) => PeerPickerSheet(onSelected: onSelected),
    );
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final peers = ref.watch(peerListProvider);
    final probed = ref.watch(probedDevicesProvider);

    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.only(bottom: 16),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
              child: Text(
                'Select Recipient',
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
              ),
            ),
            const Divider(height: 1),
            ListTile(
              leading: const Icon(Icons.input),
              title: const Text('Send by Address'),
              subtitle: const Text('Enter IP:Port manually'),
              onTap: () {
                Navigator.pop(context);
                _showAddressDialog(context);
              },
            ),
            if (peers.isNotEmpty) ...[
              const Padding(
                padding: EdgeInsets.fromLTRB(16, 8, 16, 4),
                child: Text('Nearby Devices',
                    style: TextStyle(fontSize: 12, color: Colors.grey)),
              ),
              ...peers.map((peer) => ListTile(
                    leading: Icon(
                      peer.isTrusted ? Icons.verified_user : Icons.devices,
                      size: 20,
                    ),
                    title: Text(peer.name, style: const TextStyle(fontSize: 14)),
                    subtitle: Text(peer.displayFingerprint,
                        style: const TextStyle(fontSize: 11, color: Colors.grey)),
                    dense: true,
                    onTap: () {
                      Navigator.pop(context);
                      if (peer.addresses.isNotEmpty) {
                        onSelected(peer.addresses.first,
                            name: peer.name, fingerprint: peer.fingerprint);
                      }
                    },
                  )),
            ],
            if (probed.isNotEmpty) ...[
              const Padding(
                padding: EdgeInsets.fromLTRB(16, 8, 16, 4),
                child: Text('Probed Devices',
                    style: TextStyle(fontSize: 12, color: Colors.grey)),
              ),
              ...probed.map((peer) => ListTile(
                    leading: const Icon(Icons.link, size: 20),
                    title: Text(peer.name, style: const TextStyle(fontSize: 14)),
                    dense: true,
                    onTap: () {
                      Navigator.pop(context);
                      if (peer.addresses.isNotEmpty) {
                        onSelected(peer.addresses.first,
                            name: peer.name, fingerprint: peer.fingerprint);
                      }
                    },
                  )),
            ],
            if (peers.isEmpty && probed.isEmpty)
              const Padding(
                padding: EdgeInsets.all(16),
                child: Center(
                  child: Text('No devices found. Use "Send by Address" to enter an IP manually.',
                      style: TextStyle(color: Colors.grey)),
                ),
              ),
          ],
        ),
      ),
    );
  }

  void _showAddressDialog(BuildContext context) {
    final controller = TextEditingController();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Send to Address'),
        content: TextField(
          controller: controller,
          decoration: const InputDecoration(
            hintText: '192.168.1.5:53530',
            labelText: 'IP:Port',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () {
              final addr = controller.text.trim();
              if (addr.isNotEmpty) {
                Navigator.pop(ctx);
                onSelected(addr);
              }
            },
            child: const Text('Send'),
          ),
        ],
      ),
    );
  }
}
