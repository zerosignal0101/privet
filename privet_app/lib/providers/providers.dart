import 'dart:async';

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
      }
    }
  }

  /// Wait for a pending pairing request to be resolved.
  /// If no request has arrived yet, polls briefly for one.
  Future<void> get waitForResolution async {
    if (_resolutionCompleter != null) {
      await _resolutionCompleter!.future;
      return;
    }
    for (var i = 0; i < 50; i++) {
      await Future.delayed(const Duration(milliseconds: 100));
      if (_resolutionCompleter != null) {
        await _resolutionCompleter!.future;
        return;
      }
    }
  }

  void _resolve(String fingerprint) {
    state = state.where((p) => p.peer.fingerprint != fingerprint).toList();
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

class SendPreparationState {
  final List<String> filePaths;
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
        fileIdentifiers: fileIdentifiers ?? this.fileIdentifiers,
        peerName: clearPeer == true ? null : (peerName ?? this.peerName),
        peerAddress: clearPeer == true ? null : (peerAddress ?? this.peerAddress),
        peerFingerprint: clearPeer == true ? null : (peerFingerprint ?? this.peerFingerprint),
        pairingRequest: clearPairing == true ? null : (pairingRequest ?? this.pairingRequest),
        sendError: sendError == '' ? null : (sendError ?? this.sendError),
        sending: sending ?? this.sending,
      );

  bool get isReady => filePaths.isNotEmpty && (peerAddress != null) && !sending;
}

class SendPreparationNotifier extends Notifier<SendPreparationState> {
  @override
  SendPreparationState build() => const SendPreparationState();

  void addFiles(List<String> paths, {Map<String, String?>? identifiers}) {
    state = state.copyWith(
      filePaths: [...state.filePaths, ...paths],
      fileIdentifiers: identifiers != null
          ? {...state.fileIdentifiers, ...identifiers}
          : state.fileIdentifiers,
      sendError: '',
    );
  }

  void removeFile(int index) {
    final paths = [...state.filePaths]..removeAt(index);
    final removedPath = state.filePaths[index];
    final ids = Map<String, String?>.from(state.fileIdentifiers)..remove(removedPath);
    state = state.copyWith(filePaths: paths, fileIdentifiers: ids, sendError: '');
  }

  void clearFiles() {
    state = state.copyWith(filePaths: [], fileIdentifiers: {}, sendError: '');
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
  Future<String?> send() async {
    if (!state.isReady) return null;
    state = state.copyWith(sending: true, sendError: '', clearPairing: true);

    final service = ref.read(privetServiceProvider);

    // First attempt
    var sessionId = await service.sendFilesToAddr(
      state.peerAddress!,
      state.filePaths,
    );

    // If failed, handle pairing flow — poll for the PairRequest event
    // (which may arrive asynchronously via the 50ms event poll loop)
    if (sessionId == null) {
      state = state.copyWith(
        sendError: 'Pairing required',
      );

      // Poll for the PairRequest to arrive
      PairRequest? pr;
      for (int i = 0; i < 50; i++) {
        await Future.delayed(const Duration(milliseconds: 100));
        final p = ref.read(pairingProvider);
        if (p.isNotEmpty) {
          pr = p.last;
          state = state.copyWith(pairingRequest: pr);
          break;
        }
      }

      if (pr == null) {
        state = state.copyWith(
          sending: false,
          sendError: 'No pairing response from peer',
        );
        return null;
      }

      // Wait for user to accept/reject pairing (Trust button on the card)
      await ref.read(pairingProvider.notifier).waitForResolution;

      // Retry after pairing
      sessionId = await service.sendFilesToAddr(
        state.peerAddress!,
        state.filePaths,
      );
    }

    if (sessionId != null) {
      ref.read(activeTransfersProvider.notifier).registerSendSession(
        sessionId,
        peerName: state.peerName,
        peerFingerprint: state.peerFingerprint,
      );
      // Persist file identifiers for history
      if (state.fileIdentifiers.isNotEmpty) {
        FileIdentifierStore.instance.recordIdentifiers(sessionId, state.fileIdentifiers);
      }
      state = state.copyWith(sending: false, clearPairing: true);
    } else {
      state = state.copyWith(
        sending: false,
        sendError: 'Failed to start transfer after pairing',
      );
    }
    return sessionId;
  }

  /// Handle pairing decision from within the preparation page.
  Future<bool> trustPeer() async {
    if (state.pairingRequest == null) return false;
    final fp = state.pairingRequest!.peer.fingerprint;
    final ok = await ref.read(pairingProvider.notifier).trust(fp);
    if (ok) state = state.copyWith(clearPairing: true);
    return ok;
  }

  Future<bool> trustAndAcceptPeer() async {
    if (state.pairingRequest == null) return false;
    final fp = state.pairingRequest!.peer.fingerprint;
    final ok = await ref.read(pairingProvider.notifier).trustAndAccept(fp);
    if (ok) state = state.copyWith(clearPairing: true);
    return ok;
  }

  Future<bool> rejectPeer() async {
    if (state.pairingRequest == null) return false;
    final fp = state.pairingRequest!.peer.fingerprint;
    final ok = await ref.read(pairingProvider.notifier).reject(fp);
    if (ok) state = state.copyWith(clearPairing: true, sendError: 'Pairing rejected');
    return ok;
  }
}

final sendPreparationProvider =
    NotifierProvider<SendPreparationNotifier, SendPreparationState>(
  SendPreparationNotifier.new,
);
