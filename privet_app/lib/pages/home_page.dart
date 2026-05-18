import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';

import '../models/peer.dart';
import '../models/transfer.dart';
import '../providers/providers.dart';
import '../services/privet/privet_service.dart';
import 'transfer_page.dart';
import 'settings_page.dart';

class HomePage extends ConsumerStatefulWidget {
  const HomePage({super.key});

  @override
  ConsumerState<HomePage> createState() => _HomePageState();
}

class _HomePageState extends ConsumerState<HomePage> {
  bool _isScanning = false;

  @override
  void initState() {
    super.initState();
    _initEngine();
  }

  Future<void> _initEngine() async {
    final service = PrivetService.instance;
    final settings = ref.read(settingsProvider);

    // Get the app's documents directory for data storage (important on Android).
    String? dataDir;
    try {
      final dir = await getApplicationDocumentsDirectory();
      dataDir = dir.path;
      debugPrint('[home] dataDir=$dataDir');
    } catch (e) {
      debugPrint('[home] getApplicationDocumentsDirectory failed: $e');
    }

    // Use public Downloads folder for received files (user-accessible).
    String? downloadDir;
    if (settings.downloadDir.isNotEmpty) {
      downloadDir = settings.downloadDir;
    } else {
      try {
        final dir = await getDownloadsDirectory();
        downloadDir = dir?.path;
        debugPrint('[home] downloadDir=$downloadDir');
      } catch (e) {
        debugPrint('[home] getDownloadsDirectory failed: $e');
      }
    }

    final ok = await service.start(
      deviceName: settings.deviceName,
      dataDir: dataDir,
      downloadDir: downloadDir,
      securityMode: settings.securityMode,
    );
    debugPrint('[home] _initEngine: ok=$ok, lastError=${service.lastError}');
    if (mounted) {
      ref.read(engineRunningProvider.notifier).setRunning(ok);
    }
  }

  Future<void> _scanKnownDevices() async {
    setState(() => _isScanning = true);
    try {
      await ref.read(probedDevicesProvider.notifier).scan();
    } finally {
      if (mounted) setState(() => _isScanning = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final peers = ref.watch(peerListProvider);
    final pairingRequests = ref.watch(pairingProvider);
    final incoming = ref.watch(incomingTransferProvider);
    final progress = ref.watch(transferProgressProvider);
    final isRunning = ref.watch(engineRunningProvider);
    final probedDevices = ref.watch(probedDevicesProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Privet'),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const SettingsPage()),
            ),
          ),
        ],
      ),
      body: !isRunning
          ? const Center(child: Text('Engine not running'))
          : RefreshIndicator(
              onRefresh: () => ref.read(peerListProvider.notifier).refresh(),
              child: ListView(
                children: [
                  // Pairing requests banner
                  if (pairingRequests.isNotEmpty)
                    ...pairingRequests.map((req) => _PairingBanner(
                          request: req,
                          onTrust: () => ref
                              .read(pairingProvider.notifier)
                              .trust(req.peer.fingerprint),
                          onTrustAndAccept: () => ref
                              .read(pairingProvider.notifier)
                              .trustAndAccept(req.peer.fingerprint),
                          onDismiss: () => ref
                              .read(pairingProvider.notifier)
                              .reject(req.peer.fingerprint),
                        )),

                  // Incoming transfers
                  if (incoming.isNotEmpty)
                    ...incoming.map((t) => _IncomingTransferTile(
                          transfer: t,
                          onAccept: () => ref
                              .read(incomingTransferProvider.notifier)
                              .accept(t.sessionId),
                          onReject: () => ref
                              .read(incomingTransferProvider.notifier)
                              .reject(t.sessionId),
                        )),

                  // Active transfers
                  if (progress.isNotEmpty)
                    Padding(
                      padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
                      child: Text(
                        'Active Transfers',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                    ),
                  ...progress.entries.map((e) => _ActiveTransferTile(
                        sessionId: e.key,
                        progress: e.value,
                      )),

                  // Known / Probed Devices section
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
                    child: Row(
                      children: [
                        Text(
                          'Known Devices',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const Spacer(),
                        SizedBox(
                          height: 32,
                          child: _isScanning
                              ? const SizedBox(
                                  width: 16,
                                  height: 16,
                                  child: CircularProgressIndicator(strokeWidth: 2),
                                )
                              : TextButton.icon(
                                  onPressed: _scanKnownDevices,
                                  icon: const Icon(Icons.search, size: 16),
                                  label: const Text('Scan', style: TextStyle(fontSize: 12)),
                                ),
                        ),
                      ],
                    ),
                  ),
                  if (probedDevices.isEmpty)
                    const Padding(
                      padding: EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                      child: Text(
                        'Tap "Scan" to check for known devices on this network',
                        style: TextStyle(color: Colors.grey, fontSize: 12),
                      ),
                    )
                  else
                    ...probedDevices.map((peer) => _ProbedPeerTile(
                          peer: peer,
                          onSend: () => _sendToPeer(peer),
                        )),

                  // Nearbby Devices (auto-discovered)
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
                    child: Text(
                      'Nearby Devices',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                  ),
                  if (peers.isEmpty)
                    const Padding(
                      padding: EdgeInsets.all(32),
                      child: Center(
                        child: Text('Scanning for devices...'),
                      ),
                    )
                  else
                    ...peers.map((peer) => _PeerTile(
                          peer: peer,
                          onSend: () => _sendToPeer(peer),
                        )),
                ],
              ),
            ),
      floatingActionButton: FloatingActionButton(
        onPressed: _sendByAddress,
        child: const Icon(Icons.send),
      ),
    );
  }

  Future<void> _sendToPeer(PeerInfo peer) async {
    final result = await FilePicker.platform.pickFiles(allowMultiple: true);
    if (result == null || result.files.isEmpty) return;

    final paths = result.files.map((f) => f.path!).toList();
    final addr = peer.addresses.isNotEmpty ? peer.addresses.first : '';

    final service = PrivetService.instance;
    final sessionId = await service.sendFilesToAddr(addr, paths);

    if (sessionId != null && mounted) {
      Navigator.push(
        context,
        MaterialPageRoute(
          builder: (_) => TransferPage(sessionId: sessionId),
        ),
      );
    }
  }

  Future<void> _sendByAddress() async {
    final controller = TextEditingController();
    final addr = await showDialog<String>(
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
            onPressed: () => Navigator.pop(ctx, controller.text),
            child: const Text('Send'),
          ),
        ],
      ),
    );

    if (addr == null || addr.isEmpty) return;

    final result = await FilePicker.platform.pickFiles(allowMultiple: true);
    if (result == null || result.files.isEmpty) return;

    final paths = result.files.map((f) => f.path!).toList();
    final service = PrivetService.instance;
    final sessionId = await service.sendFilesToAddr(addr, paths);

    if (sessionId != null && mounted) {
      Navigator.push(
        context,
        MaterialPageRoute(
          builder: (_) => TransferPage(sessionId: sessionId),
        ),
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Probed Peer Tile — for known devices found via directed probe
// ---------------------------------------------------------------------------

class _ProbedPeerTile extends StatelessWidget {
  final PeerInfo peer;
  final VoidCallback onSend;

  const _ProbedPeerTile({required this.peer, required this.onSend});

  @override
  Widget build(BuildContext context) {
    final icon = peer.isTrusted
        ? Icon(Icons.verified_user, color: Colors.green.shade700, size: 20)
        : Icon(Icons.link, color: Colors.blue.shade600, size: 20);

    return ListTile(
      dense: true,
      leading: icon,
      title: Text(peer.name, style: const TextStyle(fontSize: 14)),
      subtitle: Row(
        children: [
          Icon(Icons.check_circle, size: 12, color: Colors.green.shade600),
          const SizedBox(width: 4),
          Text('Online', style: TextStyle(fontSize: 11, color: Colors.green.shade700)),
          const SizedBox(width: 8),
          Text(peer.displayFingerprint,
            style: const TextStyle(fontSize: 11, color: Colors.grey)),
        ],
      ),
      trailing: IconButton(
        icon: const Icon(Icons.send, size: 18),
        onPressed: onSend,
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Sub-widgets (unchanged)
// ---------------------------------------------------------------------------

class _PeerTile extends StatelessWidget {
  final PeerInfo peer;
  final VoidCallback onSend;

  const _PeerTile({required this.peer, required this.onSend});

  @override
  Widget build(BuildContext context) {
    final icon = peer.isTrusted
        ? Icon(Icons.verified_user, color: Colors.green.shade700)
        : const Icon(Icons.devices);

    return ListTile(
      leading: icon,
      title: Text(peer.name),
      subtitle: Text(
        '${peer.displayFingerprint}${peer.platform != null ? ' · ${peer.platform}' : ''}',
      ),
      trailing: IconButton(
        icon: const Icon(Icons.send),
        onPressed: onSend,
      ),
    );
  }
}

class _PairingBanner extends StatelessWidget {
  final PairRequest request;
  final VoidCallback onTrust;
  final VoidCallback onTrustAndAccept;
  final VoidCallback onDismiss;

  const _PairingBanner({
    required this.request,
    required this.onTrust,
    required this.onTrustAndAccept,
    required this.onDismiss,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      color: Colors.orange.shade50,
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Pairing Request from ${request.peer.name}',
              style: const TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 4),
            Text('Verification code: ${request.code}'),
            const SizedBox(height: 8),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                TextButton(onPressed: onDismiss, child: const Text('Reject')),
                const SizedBox(width: 8),
                OutlinedButton(onPressed: onTrust, child: const Text('Trust')),
                const SizedBox(width: 8),
                FilledButton(onPressed: onTrustAndAccept, child: const Text('Trust & Accept')),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _IncomingTransferTile extends StatelessWidget {
  final IncomingTransfer transfer;
  final VoidCallback onAccept;
  final VoidCallback onReject;

  const _IncomingTransferTile({
    required this.transfer,
    required this.onAccept,
    required this.onReject,
  });

  @override
  Widget build(BuildContext context) {
    final fileCount = transfer.files.length;
    final totalSize = transfer.files.fold<int>(0, (sum, f) => sum + f.size);

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: ListTile(
        leading: const Icon(Icons.download),
        title: Text('Incoming: $fileCount file${fileCount != 1 ? 's' : ''}'),
        subtitle: Text(_formatSize(totalSize)),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            IconButton(
              icon: const Icon(Icons.close, color: Colors.red),
              onPressed: onReject,
            ),
            IconButton(
              icon: const Icon(Icons.check, color: Colors.green),
              onPressed: onAccept,
            ),
          ],
        ),
      ),
    );
  }

  String _formatSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }
}

class _ActiveTransferTile extends StatelessWidget {
  final String sessionId;
  final TransferProgress progress;

  const _ActiveTransferTile({
    required this.sessionId,
    required this.progress,
  });

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: const Icon(Icons.swap_vert),
      title: Text(progress.speedText),
      subtitle: Text(
        '${progress.sizeText} · ${progress.percent.toStringAsFixed(1)}%',
      ),
      trailing: LinearProgressIndicator(value: progress.percent / 100),
    );
  }
}
