import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../models/peer.dart';
import '../models/transfer.dart';
import '../models/device_identity.dart';
import '../services/privet/privet_service.dart';

// ---------------------------------------------------------------------------
// Service provider
// ---------------------------------------------------------------------------

final privetServiceProvider = Provider<PrivetService>((ref) {
  return PrivetService.instance;
});

// ---------------------------------------------------------------------------
// Engine state
// ---------------------------------------------------------------------------

class EngineRunningNotifier extends Notifier<bool> {
  @override
  bool build() => false;

  void setRunning(bool value) => state = value;
}

final engineRunningProvider =
    NotifierProvider<EngineRunningNotifier, bool>(EngineRunningNotifier.new);

// ---------------------------------------------------------------------------
// Discovery: peer list updated by events
// ---------------------------------------------------------------------------

class PeerListNotifier extends Notifier<List<PeerInfo>> {
  StreamSubscription<PrivetEvent>? _sub;

  @override
  List<PeerInfo> build() {
    final service = ref.read(privetServiceProvider);
    _sub = service.events.listen(_onEvent);
    ref.onDispose(() => _sub?.cancel());
    _loadPeers();
    return [];
  }

  Future<void> _loadPeers() async {
    final service = ref.read(privetServiceProvider);
    final peers = await service.getPeers();
    state = peers;
  }

  void _onEvent(PrivetEvent event) {
    if (event.type == PrivetEventType.peerDiscovered && event.peer != null) {
      state = [
        ...state.where((p) => p.id.uuid != event.peer!.id.uuid),
        event.peer!,
      ];
    } else if (event.type == PrivetEventType.peerLost && event.peerId != null) {
      state = state.where((p) => p.id.uuid != event.peerId).toList();
    }
  }

  Future<void> refresh() async {
    final service = ref.read(privetServiceProvider);
    final peers = await service.getPeers();
    state = peers;
  }
}

final peerListProvider =
    NotifierProvider<PeerListNotifier, List<PeerInfo>>(PeerListNotifier.new);

// ---------------------------------------------------------------------------
// Transfer progress: map of session_id → progress
// ---------------------------------------------------------------------------

class TransferProgressNotifier
    extends Notifier<Map<String, TransferProgress>> {
  StreamSubscription<PrivetEvent>? _sub;

  @override
  Map<String, TransferProgress> build() {
    final service = ref.read(privetServiceProvider);
    _sub = service.events.listen(_onEvent);
    ref.onDispose(() => _sub?.cancel());
    return {};
  }

  void _onEvent(PrivetEvent event) {
    if (event.type == PrivetEventType.transferProgress &&
        event.sessionId != null &&
        event.progress != null) {
      state = {
        ...state,
        event.sessionId!: event.progress!,
      };
    } else if (event.type == PrivetEventType.transferComplete &&
        event.sessionId != null) {
      state = {
        ...state,
        event.sessionId!: const TransferProgress(
          totalBytes: 1,
          bytesTransferred: 1,
          currentSpeedBps: 0,
          percent: 100,
        ),
      };
      Future.delayed(const Duration(seconds: 3), () {
        state = Map.from(state)..remove(event.sessionId);
      });
    } else if (event.type == PrivetEventType.transferFailed &&
        event.sessionId != null) {
      state = Map.from(state)..remove(event.sessionId);
    }
  }
}

final transferProgressProvider = NotifierProvider<TransferProgressNotifier,
    Map<String, TransferProgress>>(TransferProgressNotifier.new);

// ---------------------------------------------------------------------------
// Pairing requests: list of pending pair requests
// ---------------------------------------------------------------------------

class PairRequest {
  final PeerInfo peer;
  final String code;
  const PairRequest(this.peer, this.code);
}

class PairingNotifier extends Notifier<List<PairRequest>> {
  StreamSubscription<PrivetEvent>? _sub;

  @override
  List<PairRequest> build() {
    final service = ref.read(privetServiceProvider);
    _sub = service.events.listen(_onEvent);
    ref.onDispose(() => _sub?.cancel());
    return [];
  }

  void _onEvent(PrivetEvent event) {
    if ((event.type == PrivetEventType.pairRequest ||
            event.type == PrivetEventType.awaitingPairing) &&
        event.peer != null &&
        event.pairingCode != null) {
      if (!state.any((p) => p.peer.fingerprint == event.peer!.fingerprint)) {
        state = [...state, PairRequest(event.peer!, event.pairingCode!)];
      }
    }
  }

  Future<bool> trust(String fingerprint) async {
    debugPrint('[pairing] trust_peer called: fingerprint=$fingerprint');
    final service = ref.read(privetServiceProvider);
    final ok = await service.trustPeer(fingerprint);
    debugPrint('[pairing] trust_peer result: ok=$ok');
    if (ok) {
      state = state.where((p) => p.peer.fingerprint != fingerprint).toList();
    }
    return ok;
  }

  Future<bool> trustAndAccept(String fingerprint) async {
    debugPrint('[pairing] trust_and_accept_peer called: fingerprint=$fingerprint');
    final service = ref.read(privetServiceProvider);
    final ok = await service.trustAndAcceptPeer(fingerprint);
    debugPrint('[pairing] trust_and_accept_peer result: ok=$ok');
    if (ok) {
      state = state.where((p) => p.peer.fingerprint != fingerprint).toList();
    }
    return ok;
  }

  Future<bool> reject(String fingerprint) async {
    debugPrint('[pairing] reject_pairing called: fingerprint=$fingerprint');
    final service = ref.read(privetServiceProvider);
    final ok = await service.rejectPairing(fingerprint);
    debugPrint('[pairing] reject_pairing result: ok=$ok');
    if (ok) {
      state = state.where((p) => p.peer.fingerprint != fingerprint).toList();
    }
    return ok;
  }
}

final pairingProvider =
    NotifierProvider<PairingNotifier, List<PairRequest>>(PairingNotifier.new);

// ---------------------------------------------------------------------------
// Incoming transfers: list of pending incoming transfer requests
// ---------------------------------------------------------------------------

class IncomingTransfer {
  final String sessionId;
  final PeerInfo? peer;
  final List<FileEntry> files;
  const IncomingTransfer(this.sessionId, this.peer, this.files);
}

class IncomingTransferNotifier extends Notifier<List<IncomingTransfer>> {
  StreamSubscription<PrivetEvent>? _sub;

  @override
  List<IncomingTransfer> build() {
    final service = ref.read(privetServiceProvider);
    _sub = service.events.listen(_onEvent);
    ref.onDispose(() => _sub?.cancel());
    return [];
  }

  void _onEvent(PrivetEvent event) {
    if ((event.type == PrivetEventType.incomingTransfer ||
            event.type == PrivetEventType.awaitingAccept) &&
        event.sessionId != null) {
      state = [
        ...state.where((t) => t.sessionId != event.sessionId),
        IncomingTransfer(event.sessionId!, event.peer, event.files ?? []),
      ];
    } else if ((event.type == PrivetEventType.transferComplete ||
            event.type == PrivetEventType.transferFailed) &&
        event.sessionId != null) {
      state = state.where((t) => t.sessionId != event.sessionId).toList();
    }
  }

  Future<bool> accept(String sessionId) async {
    final service = ref.read(privetServiceProvider);
    final ok = await service.acceptTransfer(sessionId);
    if (ok) {
      state = state.where((t) => t.sessionId != sessionId).toList();
    }
    return ok;
  }

  Future<bool> reject(String sessionId) async {
    final service = ref.read(privetServiceProvider);
    final ok = await service.rejectTransfer(sessionId);
    if (ok) {
      state = state.where((t) => t.sessionId != sessionId).toList();
    }
    return ok;
  }
}

final incomingTransferProvider = NotifierProvider<IncomingTransferNotifier,
    List<IncomingTransfer>>(IncomingTransferNotifier.new);

// ---------------------------------------------------------------------------
// Trusted peers list (for settings management)
// ---------------------------------------------------------------------------

class TrustedListNotifier extends Notifier<List<String>> {
  @override
  List<String> build() {
    _load();
    return [];
  }

  Future<void> _load() async {
    final service = ref.read(privetServiceProvider);
    state = await service.getTrustedFingerprints();
  }

  Future<void> refresh() async {
    await _load();
  }

  Future<void> untrust(String fingerprint) async {
    final service = ref.read(privetServiceProvider);
    final ok = await service.untrustPeer(fingerprint);
    if (ok) {
      state = state.where((fp) => fp != fingerprint).toList();
    }
  }
}

final trustedListProvider =
    NotifierProvider<TrustedListNotifier, List<String>>(TrustedListNotifier.new);

// ---------------------------------------------------------------------------
// Accepted (auto-accept) peers list (for settings management)
// ---------------------------------------------------------------------------

class AcceptedListNotifier extends Notifier<List<String>> {
  @override
  List<String> build() {
    _load();
    return [];
  }

  Future<void> _load() async {
    final service = ref.read(privetServiceProvider);
    state = await service.getAcceptedFingerprints();
  }

  Future<void> refresh() async {
    await _load();
  }

  Future<void> unaccept(String fingerprint) async {
    final service = ref.read(privetServiceProvider);
    final ok = await service.unacceptPeer(fingerprint);
    if (ok) {
      state = state.where((fp) => fp != fingerprint).toList();
    }
  }
}

final acceptedListProvider =
    NotifierProvider<AcceptedListNotifier, List<String>>(AcceptedListNotifier.new);

// ---------------------------------------------------------------------------
// Device identity
// ---------------------------------------------------------------------------

final identityProvider = FutureProvider<DeviceIdentity?>((ref) async {
  final service = ref.watch(privetServiceProvider);
  return service.getIdentity();
});

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

class Settings {
  final String deviceName;
  final String downloadDir;
  final String securityMode; // 'allow_all', 'trust_required', 'strict'
  final bool enableTcpFallback;

  const Settings({
    this.deviceName = 'Privet',
    this.downloadDir = '',
    this.securityMode = 'trust_required',
    this.enableTcpFallback = true,
  });

  Settings copyWith({
    String? deviceName,
    String? downloadDir,
    String? securityMode,
    bool? enableTcpFallback,
  }) =>
      Settings(
        deviceName: deviceName ?? this.deviceName,
        downloadDir: downloadDir ?? this.downloadDir,
        securityMode: securityMode ?? this.securityMode,
        enableTcpFallback: enableTcpFallback ?? this.enableTcpFallback,
      );
}

class SettingsNotifier extends Notifier<Settings> {
  @override
  Settings build() {
    _load();
    return const Settings();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    state = Settings(
      deviceName: prefs.getString('device_name') ?? 'Privet',
      downloadDir: prefs.getString('download_dir') ?? '',
      securityMode: prefs.getString('security_mode') ?? 'trust_required',
      enableTcpFallback: prefs.getBool('enable_tcp_fallback') ?? true,
    );
  }

  Future<void> setDeviceName(String name) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('device_name', name);
    state = state.copyWith(deviceName: name);
  }

  Future<void> setDownloadDir(String dir) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('download_dir', dir);
    state = state.copyWith(downloadDir: dir);
  }

  Future<void> setSecurityMode(String value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('security_mode', value);
    state = state.copyWith(securityMode: value);
  }

  Future<void> setEnableTcpFallback(bool value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('enable_tcp_fallback', value);
    state = state.copyWith(enableTcpFallback: value);
  }
}

final settingsProvider =
    NotifierProvider<SettingsNotifier, Settings>(SettingsNotifier.new);

// ---------------------------------------------------------------------------
// Known devices (from Rust known_device_store)
// ---------------------------------------------------------------------------

class KnownDevicesNotifier extends Notifier<List<Map<String, dynamic>>> {
  @override
  List<Map<String, dynamic>> build() {
    return [];
  }

  Future<void> refresh() async {
    final service = ref.read(privetServiceProvider);
    state = await service.getKnownDevices();
  }
}

final knownDevicesProvider = NotifierProvider<KnownDevicesNotifier,
    List<Map<String, dynamic>>>(KnownDevicesNotifier.new);

// ---------------------------------------------------------------------------
// Current networks (from Rust network detection)
// ---------------------------------------------------------------------------

class CurrentNetworksNotifier extends Notifier<List<Map<String, dynamic>>> {
  @override
  List<Map<String, dynamic>> build() {
    _load();
    return [];
  }

  Future<void> _load() async {
    final service = ref.read(privetServiceProvider);
    state = await service.getCurrentNetworks();
  }

  Future<void> refresh() async {
    await _load();
  }
}

final currentNetworksProvider = NotifierProvider<CurrentNetworksNotifier,
    List<Map<String, dynamic>>>(CurrentNetworksNotifier.new);

// ---------------------------------------------------------------------------
// Probed known devices (on-demand scan results)
// ---------------------------------------------------------------------------

class ProbedDevicesNotifier extends Notifier<List<PeerInfo>> {
  @override
  List<PeerInfo> build() => [];

  Future<void> scan() async {
    final service = ref.read(privetServiceProvider);
    final rawList = await service.probeKnownDevices();
    state = rawList.map((e) => PeerInfo.fromJson(e)).toList();
  }
}

final probedDevicesProvider = NotifierProvider<ProbedDevicesNotifier,
    List<PeerInfo>>(ProbedDevicesNotifier.new);
