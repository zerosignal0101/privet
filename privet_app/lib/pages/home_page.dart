import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:path_provider/path_provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../models/device_identity.dart';
import '../models/peer.dart';
import '../models/transfer.dart';
import '../models/transfer_history.dart';
import '../providers/providers.dart';
import '../services/privet/privet_service.dart';
import '../utils/pairing_url.dart';
import '../utils/platform.dart';
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
  bool _showQr = false;

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
      dataDir = await engineDataDir();
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
    final identity = ref.watch(identityProvider);
    final networks = ref.watch(currentNetworksProvider);
    final settings = ref.watch(settingsProvider);

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
        actions: [
          if (identity.value != null && identity.value!.fingerprint.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(right: 12),
              child: Text(
                identity.value!.displayFingerprint,
                style: const TextStyle(fontSize: 12, color: Colors.grey),
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
                  // Identity & Network card
                  _IdentityCard(
                    identity: identity.value,
                    configuredName: settings.deviceName,
                    networks: networks,
                    showQr: _showQr,
                    onToggleQr: () => setState(() => _showQr = !_showQr),
                  ),

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
// Identity Card — device name, fingerprint, local IPs, QR pairing code
// ---------------------------------------------------------------------------

class _IdentityCard extends StatelessWidget {
  final DeviceIdentity? identity;
  final String configuredName;
  final List<Map<String, dynamic>> networks;
  final bool showQr;
  final VoidCallback onToggleQr;

  const _IdentityCard({
    this.identity,
    required this.configuredName,
    required this.networks,
    required this.showQr,
    required this.onToggleQr,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final fp = identity?.fingerprint ?? '';
    final displayFp = identity?.displayFingerprint ?? '';
    final deviceName = identity?.deviceName ?? configuredName;

    if (kDebugMode) {
      debugPrint('[identity_card] build: fp_len=${fp.length} name=$deviceName '
          'networks=${networks.length} configuredName=$configuredName');
    }

    // Collect unique local IPs
    final localIps = <String>[];
    for (final net in networks) {
      final ips = net['local_ips'];
      if (ips is List) {
        for (final ip in ips) {
          final s = ip.toString();
          if (!localIps.contains(s)) localIps.add(s);
        }
      }
    }

    return Card(
      margin: const EdgeInsets.fromLTRB(12, 8, 12, 4),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Device name + fingerprint
            Row(
              children: [
                Icon(Icons.computer, size: 20, color: theme.colorScheme.primary),
                const SizedBox(width: 8),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(deviceName,
                          style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 14)),
                      if (displayFp.isNotEmpty)
                        Text(displayFp,
                            style: const TextStyle(fontSize: 11, color: Colors.grey)),
                    ],
                  ),
                ),
                // Pairing QR toggle
                TextButton.icon(
                  onPressed: onToggleQr,
                  icon: Icon(showQr ? Icons.qr_code_2 : Icons.qr_code, size: 20),
                  label: Text(showQr ? 'Hide QR' : 'Pair', style: const TextStyle(fontSize: 12)),
                ),
              ],
            ),
            // Local IPs
            if (localIps.isNotEmpty) ...[
              const SizedBox(height: 8),
              Wrap(
                spacing: 6,
                runSpacing: 4,
                children: localIps.map((ip) {
                  final port = '53530';
                  return Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                    decoration: BoxDecoration(
                      color: Colors.green.shade50,
                      borderRadius: BorderRadius.circular(4),
                      border: Border.all(color: Colors.green.shade200),
                    ),
                    child: Text(
                      '$ip:$port',
                      style: TextStyle(fontSize: 11, color: Colors.green.shade800,
                          fontFamily: 'monospace'),
                    ),
                  );
                }).toList(),
              ),
            ],
            // QR code
            if (showQr) ...[
              const SizedBox(height: 12),
              _PairingQrCode(
                fingerprint: fp,
                deviceName: deviceName,
                networks: networks,
              ),
            ],
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Pairing QR Code
// ---------------------------------------------------------------------------

class _PairingQrCode extends StatelessWidget {
  final String fingerprint;
  final String deviceName;
  final List<Map<String, dynamic>> networks;

  const _PairingQrCode({
    required this.fingerprint,
    required this.deviceName,
    required this.networks,
  });

  @override
  Widget build(BuildContext context) {
    if (kDebugMode) debugPrint('[pairing_qr] build: fp_len=${fingerprint.length} networks=${networks.length}');

    if (fingerprint.isEmpty) {
      if (kDebugMode) debugPrint('[pairing_qr] fingerprint empty, hiding QR');
      return const SizedBox.shrink();
    }

    final url = PairingUrl.build(
      fingerprint: fingerprint,
      deviceName: deviceName,
      networks: networks,
    );

    if (url.isEmpty) {
      if (kDebugMode) debugPrint('[pairing_qr] url empty, showing "no networks" msg');
      return const Padding(
        padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No network interfaces available',
            style: TextStyle(color: Colors.grey, fontSize: 12)),
      );
    }

    return Column(
      children: [
        QrImageView(
          data: url,
          version: QrVersions.auto,
          size: 180,
          eyeStyle: const QrEyeStyle(
            eyeShape: QrEyeShape.square,
            color: Colors.black87,
          ),
          dataModuleStyle: const QrDataModuleStyle(
            dataModuleShape: QrDataModuleShape.square,
            color: Colors.black87,
          ),
          padding: const EdgeInsets.all(4),
        ),
        const SizedBox(height: 4),
        Text('Scan with camera to pair',
            style: TextStyle(fontSize: 11, color: Colors.grey.shade600)),
        const SizedBox(height: 2),
        GestureDetector(
          onTap: () {
            // Copy URL to clipboard for testing
            Clipboard.setData(ClipboardData(text: url));
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Pairing URL copied to clipboard'),
                  duration: Duration(seconds: 1)),
            );
          },
          child: Text('or tap to copy URL',
              style: TextStyle(fontSize: 10, color: Colors.grey.shade400,
                  decoration: TextDecoration.underline)),
        ),
      ],
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
      subtitle: Row(
        children: [
          if (peer.isTrusted)
            Padding(
              padding: const EdgeInsets.only(right: 4),
              child: Icon(Icons.check_circle, size: 12, color: Colors.green.shade600),
            ),
          Expanded(
            child: Text(
              peer.addresses.isNotEmpty ? peer.addresses.first : peer.displayFingerprint,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                fontSize: 12,
                color: peer.addresses.isNotEmpty ? Colors.green.shade700 : Colors.grey,
              ),
            ),
          ),
          if (peer.platform != null) ...[
            const SizedBox(width: 6),
            Text(peer.platform!, style: const TextStyle(fontSize: 11, color: Colors.grey)),
          ],
        ],
      ),
      trailing: IconButton(
        icon: const Icon(Icons.send),
        onPressed: onSend,
      ),
    );
  }
}
