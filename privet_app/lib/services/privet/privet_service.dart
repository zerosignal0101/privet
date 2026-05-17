import 'dart:async';
import 'dart:convert';

import '../../models/peer.dart';
import '../../models/transfer.dart';
import '../../models/device_identity.dart';
import 'privet_ffi_isolate.dart';

// ---------------------------------------------------------------------------
// Event types exposed to the UI layer
// ---------------------------------------------------------------------------

enum PrivetEventType {
  peerDiscovered,
  peerLost,
  pairRequest,
  transferProgress,
  transferComplete,
  transferFailed,
  incomingTransfer,
  networkChanged,
  awaitingAccept,
  awaitingPairing,
}

class PrivetEvent {
  final PrivetEventType type;
  final String? sessionId;
  final String? peerId;
  final TransferProgress? progress;
  final PeerInfo? peer;
  final String? pairingCode;
  final List<FileEntry>? files;
  final String? error;

  const PrivetEvent({
    required this.type,
    this.sessionId,
    this.peerId,
    this.progress,
    this.peer,
    this.pairingCode,
    this.files,
    this.error,
  });
}

// ---------------------------------------------------------------------------
// PrivetService — top-level singleton for the UI layer
// ---------------------------------------------------------------------------

class PrivetService {
  PrivetService._();
  static final PrivetService instance = PrivetService._();

  final _ffiIsolate = PrivetFfiIsolate.instance;

  bool _isRunning = false;
  String? _lastError;

  final _eventController = StreamController<PrivetEvent>.broadcast();
  StreamSubscription? _eventSub;

  /// Stream of engine events for UI consumption.
  Stream<PrivetEvent> get events => _eventController.stream;

  bool get isRunning => _isRunning;
  String? get lastError => _lastError;

  // -----------------------------------------------------------------------
  // Lifecycle
  // -----------------------------------------------------------------------

  /// Initialize and start the engine with defaults.
  ///
  /// On mobile platforms, pass [dataDir] from `path_provider`'s
  /// `getApplicationDocumentsDirectory()` so the Rust engine can write
  /// certificates and logs to the app's sandbox.
  Future<bool> start({String? deviceName, String? dataDir}) async {
    try {
      final name = deviceName ?? _defaultDeviceName();

      // Always use JSON config so auto_accept_trusted and other settings
      // are consistently applied. Fall back to "." when dataDir is null.
      final resolvedDataDir = dataDir ?? '.';
      final ok = await _ffiIsolate.init(_buildConfigJson(name, resolvedDataDir));
      if (!ok) {
        _lastError = 'Failed to initialize engine';
        return false;
      }

      // Listen for events from the isolate
      final stream = await _ffiIsolate.eventStream;
      _eventSub = stream.listen(_onRawEvent);

      final started = await _ffiIsolate.start();
      if (!started) {
        _lastError = 'Failed to start engine';
        return false;
      }

      _isRunning = true;
      return true;
    } catch (e) {
      _lastError = e.toString();
      return false;
    }
  }

  /// Build a JSON config with paths rooted at [dataDir].
  String _buildConfigJson(String deviceName, String dataDir) {
    final certDir = '$dataDir/privet/certs';
    final logDir = '$dataDir/privet/logs';
    final downloadDir = '$dataDir/Downloads';

    return jsonEncode({
      'device_name': deviceName,
      'download_dir': downloadDir,
      'log_dir': logDir,
      'security': {
        'cert_dir': certDir,
        'cert_validity_years': 10,
      },
      'transport': {
        'listen_port': 53530,
        'enable_tcp_fallback': true,
      },
      'discovery': {
        'enable_mdns': true,
        'enable_beacon': true,
      },
      'auto_accept_trusted': true,
    });
  }

  /// Initialize with custom JSON config.
  Future<bool> startWithConfig(String configJson) async {
    try {
      final ok = await _ffiIsolate.init(configJson);
      if (!ok) {
        _lastError = 'Failed to initialize engine';
        return false;
      }

      final stream = await _ffiIsolate.eventStream;
      _eventSub = stream.listen(_onRawEvent);

      final started = await _ffiIsolate.start();
      if (!started) {
        _lastError = 'Failed to start engine';
        return false;
      }

      _isRunning = true;
      return true;
    } catch (e) {
      _lastError = e.toString();
      return false;
    }
  }

  Future<void> stop() async {
    await _ffiIsolate.stop();
    _isRunning = false;
    await _eventSub?.cancel();
    _eventSub = null;
  }

  // -----------------------------------------------------------------------
  // File transfer
  // -----------------------------------------------------------------------

  Future<String?> sendFilesToAddr(String addr, List<String> paths) =>
      _ffiIsolate.sendFilesToAddr(addr, paths);

  Future<String?> sendFilesToName(String name, List<String> paths) =>
      _ffiIsolate.sendFilesToName(name, paths);

  Future<bool> acceptTransfer(String sessionId) =>
      _ffiIsolate.acceptTransfer(sessionId);

  Future<bool> rejectTransfer(String sessionId) =>
      _ffiIsolate.rejectTransfer(sessionId);

  Future<bool> cancelTransfer(String sessionId) =>
      _ffiIsolate.cancelTransfer(sessionId);

  // -----------------------------------------------------------------------
  // Trust / pairing
  // -----------------------------------------------------------------------

  Future<bool> trustPeer(String fingerprint) =>
      _ffiIsolate.trustPeer(fingerprint);

  Future<bool> untrustPeer(String fingerprint) =>
      _ffiIsolate.untrustPeer(fingerprint);

  Future<bool> trustAndAcceptPeer(String fingerprint) =>
      _ffiIsolate.trustAndAcceptPeer(fingerprint);

  Future<bool> rejectPairing(String fingerprint) =>
      _ffiIsolate.rejectPairing(fingerprint);

  Future<bool> unacceptPeer(String fingerprint) =>
      _ffiIsolate.unacceptPeer(fingerprint);

  // -----------------------------------------------------------------------
  // Queries
  // -----------------------------------------------------------------------

  Future<List<PeerInfo>> getPeers() async {
    final list = await _ffiIsolate.getPeers();
    return list.map((e) => PeerInfo.fromJson(e)).toList();
  }

  Future<List<String>> getTrustedFingerprints() =>
      _ffiIsolate.getTrustedFingerprints();

  Future<List<String>> getAcceptedFingerprints() =>
      _ffiIsolate.getAcceptedFingerprints();

  Future<DeviceIdentity?> getIdentity() async {
    final json = await _ffiIsolate.getIdentity();
    if (json == null) return null;
    try {
      return DeviceIdentity.fromJson(
          jsonDecode(json) as Map<String, dynamic>);
    } catch (_) {
      return null;
    }
  }

  // -----------------------------------------------------------------------
  // Internal: convert raw events to typed PrivetEvents
  // -----------------------------------------------------------------------

  void _onRawEvent(Map<String, dynamic> raw) {
    final eventType = raw['event_type'] as int? ?? -1;
    final sessionId = raw['session_id'] as String?;
    final peerId = raw['peer_id'] as String?;
    final extra = raw['extra'] as Map<String, dynamic>?;

    PrivetEvent event;
    switch (eventType) {
      case 0: // PeerDiscovered
        event = PrivetEvent(
          type: PrivetEventType.peerDiscovered,
          peerId: peerId,
          peer: extra?['peer'] != null
              ? PeerInfo.fromJson(extra!['peer'] as Map<String, dynamic>)
              : null,
        );
        break;
      case 1: // PeerLost
        event = PrivetEvent(
          type: PrivetEventType.peerLost,
          peerId: peerId,
        );
        break;
      case 2: // PairRequest
        event = PrivetEvent(
          type: PrivetEventType.pairRequest,
          peerId: peerId,
          peer: extra?['peer'] != null
              ? PeerInfo.fromJson(extra!['peer'] as Map<String, dynamic>)
              : null,
          pairingCode: extra?['code'] as String?,
        );
        break;
      case 3: // TransferProgress
        event = PrivetEvent(
          type: PrivetEventType.transferProgress,
          sessionId: sessionId,
          progress: TransferProgress(
            totalBytes: raw['total_bytes'] as int? ?? 0,
            bytesTransferred: raw['bytes_transferred'] as int? ?? 0,
            currentSpeedBps: (raw['speed_bps'] as num?)?.toDouble() ?? 0.0,
            percent: (raw['progress_percent'] as num?)?.toDouble() ?? 0.0,
          ),
        );
        break;
      case 4: // TransferComplete
        event = PrivetEvent(
          type: PrivetEventType.transferComplete,
          sessionId: sessionId,
        );
        break;
      case 5: // TransferFailed
        event = PrivetEvent(
          type: PrivetEventType.transferFailed,
          sessionId: sessionId,
          error: extra?['error'] as String?,
        );
        break;
      case 6: // IncomingTransfer
        final filesRaw = extra?['files']?['files'] as List<dynamic>?;
        event = PrivetEvent(
          type: PrivetEventType.incomingTransfer,
          sessionId: sessionId,
          peerId: peerId,
          peer: extra?['peer'] != null
              ? PeerInfo.fromJson(extra!['peer'] as Map<String, dynamic>)
              : null,
          files: filesRaw
              ?.map((f) =>
                  FileEntry.fromJson(f as Map<String, dynamic>))
              .toList(),
        );
        break;
      case 7: // NetworkChanged
        event = const PrivetEvent(type: PrivetEventType.networkChanged);
        break;
      case 8: // AwaitingAccept
        final aFilesRaw = extra?['files']?['files'] as List<dynamic>?;
        event = PrivetEvent(
          type: PrivetEventType.awaitingAccept,
          sessionId: sessionId,
          peerId: peerId,
          peer: extra?['peer'] != null
              ? PeerInfo.fromJson(extra!['peer'] as Map<String, dynamic>)
              : null,
          files: aFilesRaw
              ?.map((f) => FileEntry.fromJson(f as Map<String, dynamic>))
              .toList(),
        );
        break;
      case 9: // AwaitingPairing
        event = PrivetEvent(
          type: PrivetEventType.awaitingPairing,
          sessionId: sessionId,
          peerId: peerId,
          peer: extra?['peer'] != null
              ? PeerInfo.fromJson(extra!['peer'] as Map<String, dynamic>)
              : null,
          pairingCode: extra?['code'] as String?,
        );
        break;
      default:
        return; // Unknown event, skip
    }

    _eventController.add(event);
  }

  String _defaultDeviceName() {
    // Use hostname as a default device name
    try {
      return 'Privet-Device';
    } catch (_) {
      return 'Privet';
    }
  }
}
