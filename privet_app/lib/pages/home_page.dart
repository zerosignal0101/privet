import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:path_provider/path_provider.dart';

import '../models/peer.dart';
import '../models/transfer.dart';
import '../models/transfer_history.dart';
import '../providers/providers.dart';
import '../services/privet/privet_service.dart';
import '../widgets/transfer_tile.dart';
import '../widgets/pairing_banner.dart';
import 'send_preparation_page.dart';

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
    await ref.read(settingsProvider.notifier).ready;
    final settings = ref.read(settingsProvider);

    String? dataDir;
    try {
      final dir = await getApplicationDocumentsDirectory();
      dataDir = dir.path;
    } catch (_) {}

    // Resolve actual download dir and persist it so history can read it
    String? resolvedDownloadDir;
    if (settings.downloadDir.isNotEmpty) {
      resolvedDownloadDir = settings.downloadDir;
    } else {
      try {
        resolvedDownloadDir = (await getDownloadsDirectory())?.path;
      } catch (_) {}
    }
    if (resolvedDownloadDir != null) {
      await ref.read(settingsProvider.notifier).setDownloadDir(resolvedDownloadDir);
    }

    final ok = await service.start(
      deviceName: settings.deviceName,
      dataDir: dataDir,
      downloadDir: resolvedDownloadDir,
      securityMode: settings.securityMode,
      listenPort: settings.listenPort,
    );
    if (mounted) {
      ref.read(engineRunningProvider.notifier).setRunning(ok);
    }
    if (ok) {
      ref.read(activeTransfersProvider.notifier).clear();
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
    final activeMap = ref.watch(activeTransfersProvider);
    final isRunning = ref.watch(engineRunningProvider);
    final probedDevices = ref.watch(probedDevicesProvider);

    final activeList = activeMap.values.toList();
    final awaitingAccept = activeList.where((t) => t.isAwaitingAccept).toList();
    final transferring = activeList.where((t) =>
        t.state == TransferState.transferring ||
        t.state == TransferState.negotiating ||
        t.state == TransferState.paused ||
        t.state == TransferState.completing).toList();
    final completed = activeList.where((t) => t.isCompleted || t.isFailed).toList();
    final otherIncoming = activeList
        .where((t) => t.direction == TransferDirection.receiving
            && !t.isAwaitingAccept
            && !t.isCompleted
            && !t.isFailed
            && t.state != TransferState.transferring
            && t.state != TransferState.negotiating
            && t.state != TransferState.paused
            && t.state != TransferState.completing)
        .toList();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Privet'),
      ),
      body: !isRunning
          ? const Center(child: Text('Engine not running'))
          : RefreshIndicator(
              onRefresh: () => ref.read(peerListProvider.notifier).refresh(),
              child: ListView(
                children: [
                  // Pairing requests
                  if (pairingRequests.isNotEmpty)
                    ...pairingRequests.map((req) => PairingBanner(
                          request: req,
                          onTrust: () => ref.read(pairingProvider.notifier)
                              .trust(req.peer.fingerprint),
                          onTrustAndAccept: () => ref.read(pairingProvider.notifier)
                              .trustAndAccept(req.peer.fingerprint),
                          onDismiss: () => ref.read(pairingProvider.notifier)
                              .reject(req.peer.fingerprint),
                        )),

                  // Awaiting accept
                  if (awaitingAccept.isNotEmpty)
                    ...awaitingAccept.map((t) => TransferTile(transfer: t)),

                  // Active transfers
                  if (transferring.isNotEmpty)
                    Padding(
                      padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
                      child: Text('Active Transfers',
                          style: Theme.of(context).textTheme.titleMedium),
                    ),
                  ...transferring.map((t) => TransferTile(transfer: t)),

                  // Other incoming (auto-processing)
                  ...otherIncoming.map((t) => TransferTile(transfer: t)),

                  // Recently completed/failed
                  if (completed.isNotEmpty)
                    Padding(
                      padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
                      child: Text('Recent',
                          style: Theme.of(context).textTheme.titleMedium),
                    ),
                  ...completed.map((t) => TransferTile(transfer: t)),

                  // Probed / Known devices
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
                    child: Row(
                      children: [
                        Text('Known Devices',
                            style: Theme.of(context).textTheme.titleMedium),
                        const Spacer(),
                        SizedBox(
                          height: 32,
                          child: _isScanning
                              ? const SizedBox(
                                  width: 16, height: 16,
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
                          onSend: () => _navigateToSend(peer),
                        )),

                  // Nearby devices
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
                    child: Text('Nearby Devices',
                        style: Theme.of(context).textTheme.titleMedium),
                  ),
                  if (peers.isEmpty)
                    const Padding(
                      padding: EdgeInsets.all(32),
                      child: Center(child: Text('Scanning for devices...')),
                    )
                  else
                    ...peers.map((peer) => _PeerTile(
                          peer: peer,
                          onSend: () => _navigateToSend(peer),
                        )),
                ],
              ),
            ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _navigateToSend(null),
        child: const Icon(Icons.send),
      ),
    );
  }

  void _navigateToSend(PeerInfo? peer) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => SendPreparationPage(
          initialPeerAddress: peer?.addresses.isNotEmpty == true
              ? peer!.addresses.first
              : null,
          initialPeerName: peer?.name,
          initialPeerFingerprint: peer?.fingerprint,
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Probed Peer Tile
// ---------------------------------------------------------------------------

class _ProbedPeerTile extends StatelessWidget {
  final PeerInfo peer;
  final VoidCallback onSend;

  const _ProbedPeerTile({required this.peer, required this.onSend});

  @override
  Widget build(BuildContext context) {
    return ListTile(
      dense: true,
      leading: Icon(
        peer.isTrusted ? Icons.verified_user : Icons.link,
        color: peer.isTrusted ? Colors.green.shade700 : Colors.blue.shade600,
        size: 20,
      ),
      title: Text(peer.name, style: const TextStyle(fontSize: 14)),
      subtitle: Row(
        children: [
          Icon(Icons.check_circle, size: 12, color: Colors.green.shade600),
          const SizedBox(width: 4),
          Expanded(
            child: Text(
              peer.addresses.isNotEmpty ? peer.addresses.first : 'Online',
              overflow: TextOverflow.ellipsis,
              style: TextStyle(fontSize: 11, color: Colors.green.shade700),
            ),
          ),
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
// Peer Tile
// ---------------------------------------------------------------------------

class _PeerTile extends StatelessWidget {
  final PeerInfo peer;
  final VoidCallback onSend;

  const _PeerTile({required this.peer, required this.onSend});

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: peer.isTrusted
          ? Icon(Icons.verified_user, color: Colors.green.shade700)
          : const Icon(Icons.devices),
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
