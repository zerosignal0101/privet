import 'dart:async';
import 'dart:io';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../models/peer.dart';
import '../models/transfer.dart';
import '../models/transfer_history.dart';
import '../models/device_identity.dart';
import '../services/privet/privet_service.dart';
import '../services/privet/file_identifier_store.dart';

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
    ref.listen(engineRunningProvider, (prev, next) {
      if (next == true && prev == false) _loadPeers();
    });
    Future.microtask(() => _loadPeers());
    return [];
  }

  Future<void> _loadPeers() async {
    if (!ref.read(engineRunningProvider)) return;
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
// Active transfers: map of session_id → ActiveTransfer
// Merges the old TransferProgressNotifier + IncomingTransferNotifier.
// ---------------------------------------------------------------------------

class ActiveTransfersNotifier extends Notifier<Map<String, ActiveTransfer>> {
  StreamSubscription<PrivetEvent>? _sub;
  final Map<String, Timer> _timers = {};

  @override
  Map<String, ActiveTransfer> build() {
    final service = ref.read(privetServiceProvider);
    _sub = service.events.listen(_onEvent);
    ref.onDispose(() {
      _sub?.cancel();
      for (final t in _timers.values) t.cancel();
    });
    return {};
  }

  void _onEvent(PrivetEvent event) {
    if (event.type == PrivetEventType.transferProgress &&
        event.sessionId != null &&
        event.progress != null) {
      final sid = event.sessionId!;
      final existing = state[sid];
      final direction = event.direction == 0
          ? TransferDirection.sending
          : TransferDirection.receiving;
      state = {
        ...state,
        sid: ActiveTransfer(
          sessionId: sid,
          direction: existing?.direction ?? direction,
          progress: event.progress!,
          peerName: existing?.peerName,
          peerFingerprint: existing?.peerFingerprint,
          files: existing?.files ?? [],
          state: TransferState.transferring,
        ),
      };
    } else if (event.type == PrivetEventType.transferComplete &&
        event.sessionId != null) {
      final sid = event.sessionId!;
      final existing = state[sid];
      if (existing != null) {
        state = {
          ...state,
          sid: existing.copyWith(
            state: TransferState.completed,
            progress: const TransferProgress(
              totalBytes: 1, bytesTransferred: 1,
              currentSpeedBps: 0, percent: 100,
            ),
          ),
        };
        _startRemoveTimer(sid);
      }
    } else if (event.type == PrivetEventType.transferFailed &&
        event.sessionId != null) {
      final sid = event.sessionId!;
      final existing = state[sid];
      if (existing != null) {
        state = {
          ...state,
          sid: existing.copyWith(state: TransferState.failed),
        };
        _startRemoveTimer(sid);
      }
    } else if ((event.type == PrivetEventType.incomingTransfer ||
            event.type == PrivetEventType.awaitingAccept) &&
        event.sessionId != null) {
      final sid = event.sessionId!;
      final isAwaiting = event.type == PrivetEventType.awaitingAccept;
      final peerName = event.peer?.name;
      final peerFp = event.peer?.fingerprint;
      state = {
        ...state,
        sid: ActiveTransfer(
          sessionId: sid,
          direction: TransferDirection.receiving,
          progress: const TransferProgress(
            totalBytes: 0, bytesTransferred: 0,
            currentSpeedBps: 0, percent: 0,
          ),
          peerName: peerName,
          peerFingerprint: peerFp,
          files: event.files ?? [],
          state: isAwaiting
              ? TransferState.waitingAcceptance
              : TransferState.transferring,
        ),
      };
    }
  }

  void _startRemoveTimer(String sessionId) {
    _timers[sessionId]?.cancel();
    _timers[sessionId] = Timer(const Duration(seconds: 5), () {
      final map = Map<String, ActiveTransfer>.from(state);
      map.remove(sessionId);
      state = map;
      _timers.remove(sessionId);
    });
  }

  /// Register a send session (called when sendFilesToAddr returns a sessionId
  /// before the first TransferProgress event arrives).
  /// Does nothing if the session is already tracked (events arrived first).
  void registerSendSession(
    String sessionId, {
    String? peerName,
    String? peerFingerprint,
    List<FileEntry> files = const [],
  }) {
    if (state.containsKey(sessionId)) return;
    state = {
      ...state,
      sessionId: ActiveTransfer(
        sessionId: sessionId,
        direction: TransferDirection.sending,
        progress: const TransferProgress(
          totalBytes: 0, bytesTransferred: 0,
          currentSpeedBps: 0, percent: 0,
        ),
        peerName: peerName,
        peerFingerprint: peerFingerprint,
        files: files,
        state: TransferState.negotiating,
      ),
    };
  }

  Future<bool> acceptTransfer(String sessionId) async {
    final ok = await ref.read(privetServiceProvider).acceptTransfer(sessionId);
    if (ok) {
      final existing = state[sessionId];
      if (existing != null) {
        state = {
          ...state,
          sessionId: existing.copyWith(state: TransferState.transferring),
        };
      }
    }
    return ok;
  }

  Future<bool> rejectTransfer(String sessionId) async {
    final ok = await ref.read(privetServiceProvider).rejectTransfer(sessionId);
    state = Map.from(state)..remove(sessionId);
    return ok;
  }

  Future<bool> cancelTransfer(String sessionId) async {
    final ok = await ref.read(privetServiceProvider).cancelTransfer(sessionId);
    if (ok) {
      final existing = state[sessionId];
      if (existing != null) {
        state = {
          ...state,
          sessionId: existing.copyWith(state: TransferState.cancelled),
        };
        _startRemoveTimer(sessionId);
      }
    }
    return ok;
  }

  /// Clear all — called on engine restart.
  void clear() {
    for (final t in _timers.values) t.cancel();
    _timers.clear();
    state = {};
  }
}

final activeTransfersProvider = NotifierProvider<ActiveTransfersNotifier,
    Map<String, ActiveTransfer>>(ActiveTransfersNotifier.new);

// ---------------------------------------------------------------------------
// Legacy aliases — for backward compatibility during migration
// ---------------------------------------------------------------------------

final transferProgressProvider =
    Provider<Map<String, TransferProgress>>((ref) {
  final active = ref.watch(activeTransfersProvider);
  return Map.fromEntries(
    active.entries.map((e) => MapEntry(e.key, e.value.progress)),
  );
});

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
  Completer<void>? _resolutionCompleter;
  bool _pendingResolution = false;
  /// Cache the most recent peer info per fingerprint for known-device recording.
  final Map<String, _CachedPeerInfo> _cachedPeers = {};

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
        _resolutionCompleter = Completer<void>();
        state = [...state, PairRequest(event.peer!, event.pairingCode!)];
        debugPrint('[pairing] _onEvent: type=${event.type} name=${event.peer!.name} addrs=${event.peer!.addresses}');
        // Cache peer info for known-device recording
        _cachedPeers[event.peer!.fingerprint] = _CachedPeerInfo(
          name: event.peer!.name,
          addresses: event.peer!.addresses,
        );
      }
    }
  }

  /// Returns a future that completes when the current pairing is resolved.
  /// If already resolved, returns immediately.
  /// If no request is pending, waits a short while (acts as poll delay).
  Future<void> get waitForResolution async {
    if (_pendingResolution) {
      debugPrint('[pairing] waitForResolution: pendingResolution=true, returning immediately');
      _pendingResolution = false;
      return;
    }
    if (_resolutionCompleter != null) {
      debugPrint('[pairing] waitForResolution: awaiting completer');
      await _resolutionCompleter!.future;
      debugPrint('[pairing] waitForResolution: completer resolved');
      return;
    }
    // No pending request yet — wait a minimum interval to avoid busy loop
    await Future.delayed(const Duration(milliseconds: 100));
  }

  void _resolve(String fingerprint) {
    state = state.where((p) => p.peer.fingerprint != fingerprint).toList();
    _pendingResolution = true;
    if (state.isEmpty && _resolutionCompleter != null) {
      _resolutionCompleter!.complete();
      _resolutionCompleter = null;
    }
  }

  Future<bool> trust(String fingerprint) async {
    debugPrint('[pairing] trust_peer called: fingerprint=$fingerprint');
    final service = ref.read(privetServiceProvider);
    final ok = await service.trustPeer(fingerprint);
    debugPrint('[pairing] trust_peer result: ok=$ok');
    if (ok) {
      _resolve(fingerprint);
      ref.read(trustedListProvider.notifier).refresh();
      debugPrint('[pairing] refreshing known devices after trust');
      ref.read(knownDevicesProvider.notifier).refresh();
    }
    return ok;
  }

  Future<bool> trustAndAccept(String fingerprint) async {
    debugPrint('[pairing] trust_and_accept_peer called: fingerprint=$fingerprint');
    final service = ref.read(privetServiceProvider);
    final ok = await service.trustAndAcceptPeer(fingerprint);
    debugPrint('[pairing] trust_and_accept_peer result: ok=$ok');
    if (ok) {
      _resolve(fingerprint);
      ref.read(trustedListProvider.notifier).refresh();
      ref.read(acceptedListProvider.notifier).refresh();
      debugPrint('[pairing] refreshing known devices after trust+accept');
      ref.read(knownDevicesProvider.notifier).refresh();
    }
    return ok;
  }

  Future<bool> reject(String fingerprint) async {
    debugPrint('[pairing] reject_pairing called: fingerprint=$fingerprint');
    final service = ref.read(privetServiceProvider);
    final ok = await service.rejectPairing(fingerprint);
    debugPrint('[pairing] reject_pairing result: ok=$ok');
    if (ok) {
      _resolve(fingerprint);
    }
    return ok;
  }
}

final pairingProvider =
    NotifierProvider<PairingNotifier, List<PairRequest>>(PairingNotifier.new);

class _CachedPeerInfo {
  final String name;
  final List<String> addresses;
  const _CachedPeerInfo({required this.name, required this.addresses});
}

// ---------------------------------------------------------------------------
// IncomingTransfer (kept for backward compat, reads from ActiveTransfersNotifier)
// ---------------------------------------------------------------------------

class IncomingTransfer {
  final String sessionId;
  final PeerInfo? peer;
  final List<FileEntry> files;
  final bool isAwaitingAccept;
  const IncomingTransfer(this.sessionId, this.peer, this.files,
      {this.isAwaitingAccept = false});
}

final incomingTransferProvider =
    Provider<List<IncomingTransfer>>((ref) {
  final active = ref.watch(activeTransfersProvider);
  return active.values
      .where((t) =>
          t.direction == TransferDirection.receiving &&
          (t.state == TransferState.waitingAcceptance ||
           t.state == TransferState.negotiating ||
           t.state == TransferState.transferring))
      .map((t) => IncomingTransfer(
            t.sessionId,
            t.peerFingerprint != null
                ? PeerInfo(
                    id: PeerId(''),
                    name: t.peerName ?? '',
                    addresses: [],
                    fingerprint: t.peerFingerprint ?? '',
                    isTrusted: false,
                  )
                : null,
            t.files,
            isAwaitingAccept: t.isAwaitingAccept,
          ))
      .toList();
});

// ---------------------------------------------------------------------------
// Trusted peers list
// ---------------------------------------------------------------------------

class TrustedListNotifier extends Notifier<List<String>> {
  @override
  List<String> build() {
    ref.listen(engineRunningProvider, (prev, next) {
      if (next == true && prev == false) refresh();
    });
    Future.microtask(() => _load());
    return [];
  }

  Future<void> _load() async {
    if (!ref.read(engineRunningProvider)) return;
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
// Accepted (auto-accept) peers list
// ---------------------------------------------------------------------------

class AcceptedListNotifier extends Notifier<List<String>> {
  @override
  List<String> build() {
    ref.listen(engineRunningProvider, (prev, next) {
      if (next == true && prev == false) refresh();
    });
    Future.microtask(() => _load());
    return [];
  }

  Future<void> _load() async {
    if (!ref.read(engineRunningProvider)) return;
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
  final String securityMode;
  final bool enableTcpFallback;
  final int listenPort;

  const Settings({
    this.deviceName = 'Privet',
    this.downloadDir = '',
    this.securityMode = 'trust_required',
    this.enableTcpFallback = true,
    this.listenPort = 53530,
  });

  Settings copyWith({
    String? deviceName,
    String? downloadDir,
    String? securityMode,
    bool? enableTcpFallback,
    int? listenPort,
  }) =>
      Settings(
        deviceName: deviceName ?? this.deviceName,
        downloadDir: downloadDir ?? this.downloadDir,
        securityMode: securityMode ?? this.securityMode,
        enableTcpFallback: enableTcpFallback ?? this.enableTcpFallback,
        listenPort: listenPort ?? this.listenPort,
      );
}

class SettingsNotifier extends Notifier<Settings> {
  final _readyCompleter = Completer<void>();
  Future<void> get ready => _readyCompleter.future;

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
      listenPort: prefs.getInt('listen_port') ?? 53530,
    );
    _readyCompleter.complete();
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

  Future<void> setListenPort(int port) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt('listen_port', port);
    state = state.copyWith(listenPort: port);
  }
}

final settingsProvider =
    NotifierProvider<SettingsNotifier, Settings>(SettingsNotifier.new);

// ---------------------------------------------------------------------------
// Known devices
// ---------------------------------------------------------------------------

class KnownDevicesNotifier extends Notifier<List<Map<String, dynamic>>> {
  StreamSubscription<PrivetEvent>? _sub;

  @override
  List<Map<String, dynamic>> build() {
    final service = ref.read(privetServiceProvider);
    _sub = service.events.listen((event) {
      if (event.type == PrivetEventType.peerDiscovered ||
          event.type == PrivetEventType.knownDeviceProbed ||
          event.type == PrivetEventType.transferComplete) {
        refresh();
      }
    });
    ref.onDispose(() => _sub?.cancel());
    ref.listen(engineRunningProvider, (prev, next) {
      if (next == true && prev == false) refresh();
    });
    Future.microtask(() => refresh());
    return [];
  }

  Future<void> refresh() async {
    final service = ref.read(privetServiceProvider);
    final list = await service.getKnownDevices();
    if (list.isNotEmpty || state.isNotEmpty) {
      state = list;
    }
  }
}

final knownDevicesProvider = NotifierProvider<KnownDevicesNotifier,
    List<Map<String, dynamic>>>(KnownDevicesNotifier.new);

// ---------------------------------------------------------------------------
// Current networks
// ---------------------------------------------------------------------------

class CurrentNetworksNotifier extends Notifier<List<Map<String, dynamic>>> {
  @override
  List<Map<String, dynamic>> build() {
    // Reload when engine becomes running
    ref.listen(engineRunningProvider, (prev, next) {
      if (next == true && prev == false) refresh();
    });
    // Also try immediately — engine may already be running
    _load();
    return [];
  }

  Future<void> _load() async {
    // Don't bother if engine isn't running
    if (!ref.read(engineRunningProvider)) return;
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
// Probed known devices (on-demand scan)
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

// ---------------------------------------------------------------------------
// Transfer history
// ---------------------------------------------------------------------------

class TransferHistoryNotifier extends Notifier<List<TransferHistoryRecord>> {
  StreamSubscription<PrivetEvent>? _sub;

  @override
  List<TransferHistoryRecord> build() {
    // Auto-refresh when a transfer completes or fails
    final service = ref.read(privetServiceProvider);
    _sub = service.events.listen((event) {
      if (event.type == PrivetEventType.transferComplete ||
          event.type == PrivetEventType.transferFailed) {
        refresh();
      }
    });
    ref.onDispose(() => _sub?.cancel());
    // Reload when engine becomes running
    ref.listen(engineRunningProvider, (prev, next) {
      if (next == true && prev == false) refresh();
    });
    // Initial load
    Future.microtask(() => refresh());
    return [];
  }

  Future<void> load({int limit = 100, int offset = 0}) async {
    final service = ref.read(privetServiceProvider);
    final raw = await service.getTransferHistory(limit: limit, offset: offset);
    final records = raw.map((j) => TransferHistoryRecord.fromJson(j)).toList();

    // Merge Dart-side file identifiers (Android content:// URIs) for send records
    for (int i = 0; i < records.length; i++) {
      final rec = records[i];
      if (rec.direction == TransferDirection.sending) {
        final ids = await FileIdentifierStore.instance
            .getSessionIdentifiers(rec.sessionId);
        if (ids.isNotEmpty) {
          final updatedFiles = rec.files.map((f) {
            final id = ids[f.path];
            if (id != null) {
              return TransferFileRecord(
                path: f.path, identifier: id,
                size: f.size, isDir: f.isDir,
              );
            }
            return f;
          }).toList();
          records[i] = TransferHistoryRecord(
            sessionId: rec.sessionId,
            direction: rec.direction,
            peerFingerprint: rec.peerFingerprint,
            peerName: rec.peerName,
            files: updatedFiles,
            totalBytes: rec.totalBytes,
            bytesTransferred: rec.bytesTransferred,
            startedAt: rec.startedAt,
            completedAt: rec.completedAt,
            state: rec.state,
            error: rec.error,
          );
        }
      }
    }
    state = records;
  }

  Future<void> refresh() => load();

  Future<TransferHistoryRecord?> getRecord(String sessionId) async {
    final service = ref.read(privetServiceProvider);
    final raw = await service.getTransferRecord(sessionId);
    if (raw != null) return TransferHistoryRecord.fromJson(raw);
    return null;
  }

  Future<bool> deleteRecord(String sessionId) async {
    final service = ref.read(privetServiceProvider);
    final ok = await service.deleteTransferRecord(sessionId);
    if (ok) {
      state = state.where((r) => r.sessionId != sessionId).toList();
    }
    return ok;
  }
}

final transferHistoryProvider = NotifierProvider<TransferHistoryNotifier,
    List<TransferHistoryRecord>>(TransferHistoryNotifier.new);

// ---------------------------------------------------------------------------
// Send preparation state
// ---------------------------------------------------------------------------

/// A file entry with both absolute path (for reading) and relative path (for protocol).
class SendFileEntry {
  final String absolutePath;
  final String relativePath;
  final int size;
  final bool isDir;

  const SendFileEntry({
    required this.absolutePath,
    required this.relativePath,
    this.size = 0,
    this.isDir = false,
  });
}

class SendPreparationState {
  /// Top-level paths as added by user (files or directories).
  final List<String> filePaths;
  /// Expanded entries with relative paths (for tree display and FFI sending).
  final List<SendFileEntry> entries;
  /// Path → identifier (Android content:// URI) for files picked via file_picker.
  final Map<String, String?> fileIdentifiers;
  final String? peerName;
  final String? peerAddress;
  final String? peerFingerprint;
  final PairRequest? pairingRequest;
  final String? sendError;
  final bool sending;

  const SendPreparationState({
    this.filePaths = const [],
    this.entries = const [],
    this.fileIdentifiers = const {},
    this.peerName,
    this.peerAddress,
    this.peerFingerprint,
    this.pairingRequest,
    this.sendError,
    this.sending = false,
  });

  SendPreparationState copyWith({
    List<String>? filePaths,
    List<SendFileEntry>? entries,
    Map<String, String?>? fileIdentifiers,
    String? peerName,
    String? peerAddress,
    String? peerFingerprint,
    bool? clearPeer,
    PairRequest? pairingRequest,
    bool? clearPairing,
    String? sendError,
    bool? sending,
  }) =>
      SendPreparationState(
        filePaths: filePaths ?? this.filePaths,
        entries: entries ?? this.entries,
        fileIdentifiers: fileIdentifiers ?? this.fileIdentifiers,
        peerName: clearPeer == true ? null : (peerName ?? this.peerName),
        peerAddress: clearPeer == true ? null : (peerAddress ?? this.peerAddress),
        peerFingerprint: clearPeer == true ? null : (peerFingerprint ?? this.peerFingerprint),
        pairingRequest: clearPairing == true ? null : (pairingRequest ?? this.pairingRequest),
        sendError: sendError == '' ? null : (sendError ?? this.sendError),
        sending: sending ?? this.sending,
      );

  bool get isReady => filePaths.isNotEmpty && (peerAddress != null) && !sending;

  /// Total size of all file entries.
  int get totalSize => entries.fold(0, (sum, e) => sum + e.size);
}

class SendPreparationNotifier extends Notifier<SendPreparationState> {
  @override
  SendPreparationState build() => const SendPreparationState();

  /// Add pre-built file entries (from SAF cache, already have relative paths).
  void addFileEntries(List<SendFileEntry> newEntries) {
    state = state.copyWith(
      filePaths: [...state.filePaths, ...newEntries.map((e) => e.absolutePath)],
      entries: [...state.entries, ...newEntries],
      sendError: '',
    );
  }

  /// Add files or directories. Directories are expanded recursively.
  void addFiles(List<String> paths, {Map<String, String?>? identifiers}) {
    final newEntries = <SendFileEntry>[];
    for (final p in paths) {
      newEntries.addAll(_scanPath(p));
    }
    state = state.copyWith(
      filePaths: [...state.filePaths, ...paths],
      entries: [...state.entries, ...newEntries],
      fileIdentifiers: identifiers != null
          ? {...state.fileIdentifiers, ...identifiers}
          : state.fileIdentifiers,
      sendError: '',
    );
  }

  /// Scan a single path (file or directory) and return expanded entries.
  List<SendFileEntry> _scanPath(String path) {
    FileSystemEntityType type;
    try {
      type = FileSystemEntity.typeSync(path);
    } catch (e) {
      debugPrint('[scanPath] typeSync error for "$path": $e');
      return [];
    }
    debugPrint('[scanPath] "$path" type=$type');
    if (type == FileSystemEntityType.notFound) return [];

    if (type == FileSystemEntityType.directory) {
      final entries = _scanDirectory(path, path);
      debugPrint('[scanPath] scanned dir "$path": ${entries.length} files');
      return entries;
    }

    // Single file
    try {
      final size = File(path).lengthSync();
      final name = path.split(Platform.pathSeparator).last;
      debugPrint('[scanPath] single file "$name" size=$size');
      return [SendFileEntry(absolutePath: path, relativePath: name, size: size)];
    } catch (e) {
      debugPrint('[scanPath] error reading file "$path": $e');
      return [];
    }
  }

  /// Recursively scan a directory, computing relative paths.
  /// Uses manual recursion (not listSync recursive) to handle scoped storage
  /// where each subdirectory must be tried independently.
  List<SendFileEntry> _scanDirectory(String dirPath, String rootPath) {
    final result = <SendFileEntry>[];
    _scanDirRecursive(dirPath, rootPath, result);
    debugPrint('[scanDir] found ${result.length} files total in $dirPath');
    return result;
  }

  void _scanDirRecursive(String dirPath, String rootPath, List<SendFileEntry> result) {
    final dir = Directory(dirPath);
    if (!dir.existsSync()) return;

    List<FileSystemEntity> entries;
    try {
      entries = dir.listSync();
    } catch (e) {
      debugPrint('[scanDir] listSync error for "$dirPath": $e');
      return;
    }

    debugPrint('[scanDir] scanning $dirPath: ${entries.length} entries');

    for (final entity in entries) {
      final absPath = entity.path;
      final relPath = absPath.startsWith(rootPath)
          ? absPath.substring(rootPath.length + 1)
          : absPath.split(Platform.pathSeparator).last;

      // Check if it's a directory by trying to list it (most reliable on scoped storage)
      bool isDir = false;
      try {
        // Try listing as directory first — if it succeeds, it IS a directory
        Directory(absPath).listSync();
        isDir = true;
      } catch (_) {
        // Not a directory or blocked — try typeSync as fallback
        try {
          isDir = FileSystemEntity.typeSync(absPath) == FileSystemEntityType.directory;
        } catch (_) {
          // Both blocked — use extension heuristic
          isDir = !relPath.contains('.');
        }
      }

      if (isDir) {
        result.add(SendFileEntry(
          absolutePath: absPath,
          relativePath: relPath.replaceAll('\\', '/'),
          size: 0,
          isDir: true,
        ));
        _scanDirRecursive(absPath, rootPath, result);
      } else {
        int size = 0;
        try { size = File(absPath).lengthSync(); } catch (_) {}
        result.add(SendFileEntry(
          absolutePath: absPath,
          relativePath: relPath.replaceAll('\\', '/'),
          size: size,
        ));
        debugPrint('[scanDir] found file "$relPath" size=$size');
      }
    }
  }

  /// Remove a file entry by its relative path.
  /// If the relative path matches a directory prefix, removes all entries under it.
  void removeByRelativePath(String relativePath) {
    final remaining = state.entries.where((e) {
      if (e.relativePath == relativePath) return false;
      if (e.relativePath.startsWith('$relativePath/')) return false;
      return true;
    }).toList();

    // Also update filePaths: remove entries whose files are gone
    final removedAbs = <String>{};
    for (final e in state.entries) {
      if (!remaining.contains(e)) removedAbs.add(e.absolutePath);
    }

    state = state.copyWith(
      entries: remaining,
      filePaths: state.filePaths.where((p) => !removedAbs.contains(p)).toList(),
      sendError: '',
    );
  }

  /// Remove a file by its index in the flat filePaths list (legacy).
  void removeFile(int index) {
    final removed = state.entries.where((e) => e.absolutePath == state.filePaths[index]).toList();
    if (removed.isNotEmpty) {
      for (final r in removed) {
        removeByRelativePath(r.relativePath);
      }
      return;
    }
    final paths = [...state.filePaths]..removeAt(index);
    state = state.copyWith(filePaths: paths, sendError: '');
  }

  void clearFiles() {
    state = state.copyWith(filePaths: [], entries: [], fileIdentifiers: {}, sendError: '');
  }

  /// Reset all state for a fresh preparation page.
  void reset() {
    state = const SendPreparationState();
  }

  void setPeer(String address, {String? name, String? fingerprint}) {
    state = state.copyWith(
      peerAddress: address,
      peerName: name,
      peerFingerprint: fingerprint,
      sendError: '',
      clearPairing: true,
    );
  }

  void clearPeer() {
    state = state.copyWith(clearPeer: true, sendError: '', clearPairing: true);
  }

  void clearPairing() {
    state = state.copyWith(clearPairing: true);
  }

  /// Try to send, handling pairing if the peer is not trusted.
  /// Returns session_id on success, null on unrecoverable failure.
  /// Generate a v4 UUID string for session identification.
  String _generateUuid() {
    final r = Random();
    final bytes = List<int>.generate(16, (_) => r.nextInt(256));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    return '${_hex(bytes[0])}${_hex(bytes[1])}${_hex(bytes[2])}${_hex(bytes[3])}-'
        '${_hex(bytes[4])}${_hex(bytes[5])}-${_hex(bytes[6])}${_hex(bytes[7])}-'
        '${_hex(bytes[8])}${_hex(bytes[9])}-${_hex(bytes[10])}${_hex(bytes[11])}'
        '${_hex(bytes[12])}${_hex(bytes[13])}${_hex(bytes[14])}${_hex(bytes[15])}';
  }

  String _hex(int v) => v.toRadixString(16).padLeft(2, '0');

  Future<String?> send() async {
    print('[send] send() called, isReady=${state.isReady} filePaths=${state.filePaths.length} peerAddress=${state.peerAddress}');
    if (!state.isReady) return null;
    state = state.copyWith(sending: true, sendError: '', clearPairing: true);

    final service = ref.read(privetServiceProvider);

    // Generate session_id on Dart side and register BEFORE starting the
    // Rust send, so there is no race between event arrival and registration.
    final sessionId = _generateUuid();
    ref.read(activeTransfersProvider.notifier).registerSendSession(
      sessionId,
      peerName: state.peerName,
      peerFingerprint: state.peerFingerprint,
    );

    // Build payload: new format (with relative paths) or old format (just paths)
    final payload = state.entries.isNotEmpty
        ? state.entries.map((e) => {
            'path': e.absolutePath,
            'relative': e.relativePath,
          }).toList()
        : state.filePaths; // old format

    // First attempt
    var ok = await service.sendFilesStart(
      sessionId,
      state.peerAddress!,
      payload,
    );
    print('[send] sendFilesStart returned ok=$ok');

    // Wait briefly for a possible PairRequest event (FFI event polling
    // delay: the Rust engine emits PairRequest BEFORE sendFilesStart
    // returns, but the event may not have reached PairingNotifier yet).
    // If PairRequest arrives, enter pairing flow. Otherwise, the send
    // genuinely succeeded or it's a connection error.
    final pairNotifier = ref.read(pairingProvider.notifier);
    bool hadPairRequest = ref.read(pairingProvider).isNotEmpty;

    // Quick check: if PairRequest is already pending, go straight to pairing
    if (!hadPairRequest) {
      // Wait up to 2 seconds for a potential PairRequest to arrive
      for (int i = 0; i < 20; i++) {
        await Future.delayed(const Duration(milliseconds: 100));
        final p = ref.read(pairingProvider);
        if (p.isNotEmpty) {
          hadPairRequest = true;
          break;
        }
      }
    }

    if (!hadPairRequest) {
      // No PairRequest — either succeeded or connection error
      if (ok) {
        print('[send] send succeeded');
        if (state.fileIdentifiers.isNotEmpty) {
          FileIdentifierStore.instance.recordIdentifiers(sessionId, state.fileIdentifiers);
        }
        state = state.copyWith(sending: false, clearPairing: true);
        return sessionId;
      }
      state = state.copyWith(
        sending: false,
        sendError: 'peer is offline or unreachable',
      );
      return null;
    }

    // PairRequest was seen — wait for resolution (user trust/reject)
    state = state.copyWith(sendError: '');

    for (int i = 0; i < 150; i++) {
      final p = ref.read(pairingProvider);
      if (p.isEmpty) {
        print('[send] pairing resolved at poll $i');
        break;
      }

      await Future.any([
        Future.delayed(const Duration(milliseconds: 100)),
        pairNotifier.waitForResolution,
      ]);
    }

    print('[send] pairing done, retrying...');

    // Retry after pairing (new connection, both sides should now trust)
    final sessionId2 = _generateUuid();
    ref.read(activeTransfersProvider.notifier).registerSendSession(
      sessionId2,
      peerName: state.peerName,
      peerFingerprint: state.peerFingerprint,
    );
    ok = await service.sendFilesStart(
      sessionId2,
      state.peerAddress!,
      payload,
    );

    if (ok) {
      if (state.fileIdentifiers.isNotEmpty) {
        FileIdentifierStore.instance.recordIdentifiers(sessionId2, state.fileIdentifiers);
      }
      state = state.copyWith(sending: false, clearPairing: true);
      return sessionId2;
    }

    state = state.copyWith(
      sending: false,
      sendError: 'Transfer failed after pairing',
    );
    return null;
  }
  Future<bool> trustPeer() async {
    final pairing = ref.read(pairingProvider);
    if (pairing.isEmpty) return false;
    final fp = pairing.last.peer.fingerprint;
    final ok = await ref.read(pairingProvider.notifier).trust(fp);
    if (ok) {
      state = state.copyWith(clearPairing: true);
    }
    return ok;
  }

  Future<bool> trustAndAcceptPeer() async {
    final pairing = ref.read(pairingProvider);
    if (pairing.isEmpty) return false;
    final fp = pairing.last.peer.fingerprint;
    final ok = await ref.read(pairingProvider.notifier).trustAndAccept(fp);
    if (ok) {
      state = state.copyWith(clearPairing: true);
    }
    return ok;
  }

  Future<bool> rejectPeer() async {
    final pairing = ref.read(pairingProvider);
    if (pairing.isEmpty) return false;
    final fp = pairing.last.peer.fingerprint;
    final ok = await ref.read(pairingProvider.notifier).reject(fp);
    if (ok) state = state.copyWith(clearPairing: true, sendError: 'Pairing rejected');
    return ok;
  }
}

final sendPreparationProvider =
    NotifierProvider<SendPreparationNotifier, SendPreparationState>(
  SendPreparationNotifier.new,
);
