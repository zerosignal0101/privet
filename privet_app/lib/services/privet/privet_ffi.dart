import 'dart:ffi';
import 'dart:io' show Platform;

import 'package:ffi/ffi.dart';

// ---------------------------------------------------------------------------
// CEvent struct — must match Rust types::CEvent exactly
// ---------------------------------------------------------------------------

final class CEvent extends Struct {
  @Int32()
  external int eventType;

  external Pointer<Uint8> sessionId; // 37 bytes (36 UUID chars + NUL)

  external Pointer<Uint8> peerId; // 37 bytes (36 UUID chars + NUL)

  @Double()
  external double progressPercent;

  @Double()
  external double speedBps;

  @Uint64()
  external int bytesTransferred;

  @Uint64()
  external int totalBytes;

  @Uint8()
  external int direction; // 0=Sending, 1=Receiving, 255=N/A

  external Pointer<Utf8> extraJson;
}

// Event type constants — must match Rust types.rs
const int eventPeerDiscovered = 0;
const int eventPeerLost = 1;
const int eventPairRequest = 2;
const int eventTransferProgress = 3;
const int eventTransferComplete = 4;
const int eventTransferFailed = 5;
const int eventIncomingTransfer = 6;
const int eventNetworkChanged = 7;
const int eventAwaitingAccept = 8;
const int eventAwaitingPairing = 9;
const int eventKnownDeviceProbed = 10;

// ---------------------------------------------------------------------------
// FFI function typedefs
// ---------------------------------------------------------------------------

typedef PrivetInitNative = Int32 Function(Pointer<Utf8> configJson);
typedef PrivetInitDart = int Function(Pointer<Utf8> configJson);

typedef PrivetInitWithDefaultsNative = Int32 Function(Pointer<Utf8> deviceName);
typedef PrivetInitWithDefaultsDart = int Function(Pointer<Utf8> deviceName);

typedef PrivetStartNative = Int32 Function();
typedef PrivetStartDart = int Function();

typedef PrivetStopNative = Void Function();
typedef PrivetStopDart = void Function();

typedef PrivetRegisterEventCallbackNative = Void Function(
    Pointer<NativeFunction<Void Function(Pointer<CEvent>)>>);
typedef PrivetRegisterEventCallbackDart = void Function(
    Pointer<NativeFunction<Void Function(Pointer<CEvent>)>>);

typedef PrivetSendFilesStartNative = Int32 Function(
    Pointer<Utf8> sessionId, Pointer<Utf8> addr, Pointer<Utf8> pathsJson);
typedef PrivetSendFilesStartDart = int Function(
    Pointer<Utf8> sessionId, Pointer<Utf8> addr, Pointer<Utf8> pathsJson);

typedef PrivetSendFilesToNameNative = Int32 Function(
    Pointer<Utf8> name, Pointer<Utf8> pathsJson, Pointer<Utf8> outSessionId);
typedef PrivetSendFilesToNameDart = int Function(
    Pointer<Utf8> name, Pointer<Utf8> pathsJson, Pointer<Utf8> outSessionId);

typedef PrivetAcceptTransferNative = Int32 Function(Pointer<Utf8> sessionId);
typedef PrivetAcceptTransferDart = int Function(Pointer<Utf8> sessionId);

typedef PrivetRejectTransferNative = Int32 Function(Pointer<Utf8> sessionId);
typedef PrivetRejectTransferDart = int Function(Pointer<Utf8> sessionId);

typedef PrivetCancelTransferNative = Int32 Function(Pointer<Utf8> sessionId);
typedef PrivetCancelTransferDart = int Function(Pointer<Utf8> sessionId);

typedef PrivetTrustPeerNative = Int32 Function(Pointer<Utf8> fingerprint);
typedef PrivetTrustPeerDart = int Function(Pointer<Utf8> fingerprint);

typedef PrivetUntrustPeerNative = Int32 Function(Pointer<Utf8> fingerprint);
typedef PrivetUntrustPeerDart = int Function(Pointer<Utf8> fingerprint);

typedef PrivetTrustAndAcceptPeerNative = Int32 Function(Pointer<Utf8> fingerprint);
typedef PrivetTrustAndAcceptPeerDart = int Function(Pointer<Utf8> fingerprint);

typedef PrivetRejectPairingNative = Int32 Function(Pointer<Utf8> fingerprint);
typedef PrivetRejectPairingDart = int Function(Pointer<Utf8> fingerprint);

typedef PrivetGetAcceptedFingerprintsNative = Pointer<Utf8> Function();
typedef PrivetGetAcceptedFingerprintsDart = Pointer<Utf8> Function();

typedef PrivetUnacceptPeerNative = Int32 Function(Pointer<Utf8> fingerprint);
typedef PrivetUnacceptPeerDart = int Function(Pointer<Utf8> fingerprint);

typedef PrivetGetPeersNative = Pointer<Utf8> Function();
typedef PrivetGetPeersDart = Pointer<Utf8> Function();

typedef PrivetGetTrustedFingerprintsNative = Pointer<Utf8> Function();
typedef PrivetGetTrustedFingerprintsDart = Pointer<Utf8> Function();

typedef PrivetGetSessionsNative = Pointer<Utf8> Function();
typedef PrivetGetSessionsDart = Pointer<Utf8> Function();

typedef PrivetGetIdentityNative = Pointer<Utf8> Function();
typedef PrivetGetIdentityDart = Pointer<Utf8> Function();

typedef PrivetFreeStringNative = Void Function(Pointer<Utf8>);
typedef PrivetFreeStringDart = void Function(Pointer<Utf8>);

typedef PrivetPollEventNative = Pointer<Utf8> Function();
typedef PrivetPollEventDart = Pointer<Utf8> Function();

typedef PrivetGetCurrentNetworksNative = Pointer<Utf8> Function();
typedef PrivetGetCurrentNetworksDart = Pointer<Utf8> Function();

typedef PrivetSetNetworksNative = Int32 Function(Pointer<Utf8> json);
typedef PrivetSetNetworksDart = int Function(Pointer<Utf8> json);

typedef PrivetProbeKnownDevicesNative = Pointer<Utf8> Function();
typedef PrivetProbeKnownDevicesDart = Pointer<Utf8> Function();

typedef PrivetGetKnownDevicesNative = Pointer<Utf8> Function();
typedef PrivetGetKnownDevicesDart = Pointer<Utf8> Function();

typedef PrivetAddKnownDeviceIpNative = Int32 Function(Pointer<Utf8> argsJson);
typedef PrivetAddKnownDeviceIpDart = int Function(Pointer<Utf8> argsJson);

typedef PrivetRemoveKnownDeviceIpNative = Int32 Function(Pointer<Utf8> argsJson);
typedef PrivetRemoveKnownDeviceIpDart = int Function(Pointer<Utf8> argsJson);

typedef PrivetSetNetworkLabelNative = Int32 Function(Pointer<Utf8> argsJson);
typedef PrivetSetNetworkLabelDart = int Function(Pointer<Utf8> argsJson);

typedef PrivetProbeAddressNative = Pointer<Utf8> Function(Pointer<Utf8> addr);
typedef PrivetProbeAddressDart = Pointer<Utf8> Function(Pointer<Utf8> addr);

typedef PrivetGetTransferHistoryNative = Pointer<Utf8> Function(Uint32 limit, Uint32 offset);
typedef PrivetGetTransferHistoryDart = Pointer<Utf8> Function(int limit, int offset);

typedef PrivetGetTransferRecordNative = Pointer<Utf8> Function(Pointer<Utf8> sessionId);
typedef PrivetGetTransferRecordDart = Pointer<Utf8> Function(Pointer<Utf8> sessionId);

typedef PrivetDeleteTransferRecordNative = Int32 Function(Pointer<Utf8> sessionId);
typedef PrivetDeleteTransferRecordDart = int Function(Pointer<Utf8> sessionId);

// ---------------------------------------------------------------------------
// PrivetFfi — raw FFI bindings (singleton)
// ---------------------------------------------------------------------------

class PrivetFfi {
  PrivetFfi._();
  static final PrivetFfi instance = PrivetFfi._();

  DynamicLibrary? _lib;
  bool _initialized = false;

  // Cached function pointers
  late PrivetInitDart _init;
  late PrivetInitWithDefaultsDart _initWithDefaults;
  late PrivetStartDart _start;
  late PrivetStopDart _stop;
  late PrivetPollEventDart _pollEvent;
  late PrivetSendFilesStartDart _sendFilesStart;
  late PrivetSendFilesToNameDart _sendFilesToName;
  late PrivetAcceptTransferDart _acceptTransfer;
  late PrivetRejectTransferDart _rejectTransfer;
  late PrivetCancelTransferDart _cancelTransfer;
  late PrivetTrustPeerDart _trustPeer;
  late PrivetUntrustPeerDart _untrustPeer;
  late PrivetTrustAndAcceptPeerDart _trustAndAcceptPeer;
  late PrivetRejectPairingDart _rejectPairing;
  late PrivetGetAcceptedFingerprintsDart _getAcceptedFingerprints;
  late PrivetUnacceptPeerDart _unacceptPeer;
  late PrivetGetPeersDart _getPeers;
  late PrivetGetTrustedFingerprintsDart _getTrustedFingerprints;
  late PrivetGetSessionsDart _getSessions;
  late PrivetGetIdentityDart _getIdentity;
  late PrivetFreeStringDart _freeString;
  late PrivetGetCurrentNetworksDart _getCurrentNetworks;
  late PrivetSetNetworksDart _setNetworks;
  late PrivetProbeKnownDevicesDart _probeKnownDevices;
  late PrivetGetKnownDevicesDart _getKnownDevices;
  late PrivetAddKnownDeviceIpDart _addKnownDeviceIp;
  late PrivetRemoveKnownDeviceIpDart _removeKnownDeviceIp;
  late PrivetSetNetworkLabelDart _setNetworkLabel;
  late PrivetProbeAddressDart _probeAddress;
  late PrivetGetTransferHistoryDart _getTransferHistory;
  late PrivetGetTransferRecordDart _getTransferRecord;
  late PrivetDeleteTransferRecordDart _deleteTransferRecord;

  /// Load the native library and bind all FFI functions.
  bool initialize() {
    if (_initialized) return true;

    _lib = _openLibrary();
    if (_lib == null) return false;

    _init = _lib!.lookupFunction<PrivetInitNative, PrivetInitDart>(
        'privet_init');
    _initWithDefaults = _lib!
        .lookupFunction<PrivetInitWithDefaultsNative, PrivetInitWithDefaultsDart>(
            'privet_init_with_defaults');
    _start = _lib!.lookupFunction<PrivetStartNative, PrivetStartDart>(
        'privet_start');
    _stop =
        _lib!.lookupFunction<PrivetStopNative, PrivetStopDart>('privet_stop');
    _pollEvent = _lib!.lookupFunction<PrivetPollEventNative,
        PrivetPollEventDart>('privet_poll_event');
    _sendFilesStart = _lib!.lookupFunction<PrivetSendFilesStartNative,
        PrivetSendFilesStartDart>('privet_send_files_start');
    _sendFilesToName = _lib!.lookupFunction<PrivetSendFilesToNameNative,
        PrivetSendFilesToNameDart>('privet_send_files_to_name');
    _acceptTransfer = _lib!.lookupFunction<PrivetAcceptTransferNative,
        PrivetAcceptTransferDart>('privet_accept_transfer');
    _rejectTransfer = _lib!.lookupFunction<PrivetRejectTransferNative,
        PrivetRejectTransferDart>('privet_reject_transfer');
    _cancelTransfer = _lib!.lookupFunction<PrivetCancelTransferNative,
        PrivetCancelTransferDart>('privet_cancel_transfer');
    _trustPeer = _lib!.lookupFunction<PrivetTrustPeerNative,
        PrivetTrustPeerDart>('privet_trust_peer');
    _untrustPeer = _lib!.lookupFunction<PrivetUntrustPeerNative,
        PrivetUntrustPeerDart>('privet_untrust_peer');
    _trustAndAcceptPeer = _lib!.lookupFunction<PrivetTrustAndAcceptPeerNative,
        PrivetTrustAndAcceptPeerDart>('privet_trust_and_accept_peer');
    _rejectPairing = _lib!.lookupFunction<PrivetRejectPairingNative,
        PrivetRejectPairingDart>('privet_reject_pairing');
    _getAcceptedFingerprints = _lib!.lookupFunction<
        PrivetGetAcceptedFingerprintsNative,
        PrivetGetAcceptedFingerprintsDart>('privet_get_accepted_fingerprints');
    _unacceptPeer = _lib!.lookupFunction<PrivetUnacceptPeerNative,
        PrivetUnacceptPeerDart>('privet_unaccept_peer');
    _getPeers = _lib!.lookupFunction<PrivetGetPeersNative, PrivetGetPeersDart>(
        'privet_get_peers');
    _getTrustedFingerprints = _lib!.lookupFunction<
        PrivetGetTrustedFingerprintsNative,
        PrivetGetTrustedFingerprintsDart>('privet_get_trusted_fingerprints');
    _getSessions = _lib!.lookupFunction<PrivetGetSessionsNative,
        PrivetGetSessionsDart>('privet_get_sessions');
    _getIdentity = _lib!.lookupFunction<PrivetGetIdentityNative,
        PrivetGetIdentityDart>('privet_get_identity');
    _freeString = _lib!.lookupFunction<PrivetFreeStringNative,
        PrivetFreeStringDart>('privet_free_string');
    _getCurrentNetworks = _lib!.lookupFunction<PrivetGetCurrentNetworksNative,
        PrivetGetCurrentNetworksDart>('privet_get_current_networks');
    _setNetworks = _lib!.lookupFunction<PrivetSetNetworksNative,
        PrivetSetNetworksDart>('privet_set_networks');
    _probeKnownDevices = _lib!.lookupFunction<PrivetProbeKnownDevicesNative,
        PrivetProbeKnownDevicesDart>('privet_probe_known_devices');
    _getKnownDevices = _lib!.lookupFunction<PrivetGetKnownDevicesNative,
        PrivetGetKnownDevicesDart>('privet_get_known_devices');
    _addKnownDeviceIp = _lib!.lookupFunction<PrivetAddKnownDeviceIpNative,
        PrivetAddKnownDeviceIpDart>('privet_add_known_device_ip');
    _removeKnownDeviceIp = _lib!.lookupFunction<PrivetRemoveKnownDeviceIpNative,
        PrivetRemoveKnownDeviceIpDart>('privet_remove_known_device_ip');
    _setNetworkLabel = _lib!.lookupFunction<PrivetSetNetworkLabelNative,
        PrivetSetNetworkLabelDart>('privet_set_network_label');
    _probeAddress = _lib!.lookupFunction<PrivetProbeAddressNative,
        PrivetProbeAddressDart>('privet_probe_address');
    _getTransferHistory = _lib!.lookupFunction<PrivetGetTransferHistoryNative,
        PrivetGetTransferHistoryDart>('privet_get_transfer_history');
    _getTransferRecord = _lib!.lookupFunction<PrivetGetTransferRecordNative,
        PrivetGetTransferRecordDart>('privet_get_transfer_record');
    _deleteTransferRecord = _lib!.lookupFunction<PrivetDeleteTransferRecordNative,
        PrivetDeleteTransferRecordDart>('privet_delete_transfer_record');

    _initialized = true;
    return true;
  }

  DynamicLibrary? _openLibrary() {
    if (Platform.isAndroid) {
      return DynamicLibrary.open('libprivet_ffi.so');
    }
    if (Platform.isIOS) {
      return DynamicLibrary.process();
    }
    if (Platform.isWindows) {
      try {
        return DynamicLibrary.open('privet_ffi.dll');
      } catch (_) {
        return null;
      }
    }
    if (Platform.isMacOS) {
      for (final name in ['libprivet_ffi.dylib', 'privet_ffi.dylib']) {
        try {
          return DynamicLibrary.open(name);
        } catch (_) {}
      }
      return null;
    }
    if (Platform.isLinux) {
      for (final name in ['libprivet_ffi.so', 'libprivet_ffi.so.0']) {
        try {
          return DynamicLibrary.open(name);
        } catch (_) {}
      }
      return null;
    }
    return null;
  }

  // -----------------------------------------------------------------------
  // FFI call wrappers
  // -----------------------------------------------------------------------

  int init(Pointer<Utf8> configJson) => _init(configJson);

  int initWithDefaults(Pointer<Utf8> deviceName) =>
      _initWithDefaults(deviceName);

  int start() => _start();

  void stop() => _stop();

  Pointer<Utf8> pollEvent() => _pollEvent();

  int sendFilesStart(Pointer<Utf8> sessionId, Pointer<Utf8> addr, Pointer<Utf8> pathsJson) =>
      _sendFilesStart(sessionId, addr, pathsJson);

  int sendFilesToName(Pointer<Utf8> name, Pointer<Utf8> pathsJson, Pointer<Utf8> outSessionId) =>
      _sendFilesToName(name, pathsJson, outSessionId);

  int acceptTransfer(Pointer<Utf8> sessionId) => _acceptTransfer(sessionId);
  int rejectTransfer(Pointer<Utf8> sessionId) => _rejectTransfer(sessionId);
  int cancelTransfer(Pointer<Utf8> sessionId) => _cancelTransfer(sessionId);

  int trustPeer(Pointer<Utf8> fingerprint) => _trustPeer(fingerprint);
  int untrustPeer(Pointer<Utf8> fingerprint) => _untrustPeer(fingerprint);
  int trustAndAcceptPeer(Pointer<Utf8> fingerprint) => _trustAndAcceptPeer(fingerprint);
  int rejectPairing(Pointer<Utf8> fingerprint) => _rejectPairing(fingerprint);
  int unacceptPeer(Pointer<Utf8> fingerprint) => _unacceptPeer(fingerprint);

  Pointer<Utf8> getPeers() => _getPeers();
  Pointer<Utf8> getTrustedFingerprints() => _getTrustedFingerprints();
  Pointer<Utf8> getAcceptedFingerprints() => _getAcceptedFingerprints();
  Pointer<Utf8> getSessions() => _getSessions();
  Pointer<Utf8> getIdentity() => _getIdentity();

  void freeString(Pointer<Utf8> ptr) => _freeString(ptr);

  Pointer<Utf8> getCurrentNetworks() => _getCurrentNetworks();
  int setNetworks(Pointer<Utf8> json) => _setNetworks(json);
  Pointer<Utf8> probeKnownDevices() => _probeKnownDevices();
  Pointer<Utf8> getKnownDevices() => _getKnownDevices();
  Pointer<Utf8> probeAddress(Pointer<Utf8> addr) => _probeAddress(addr);
  int addKnownDeviceIp(Pointer<Utf8> argsJson) => _addKnownDeviceIp(argsJson);
  int removeKnownDeviceIp(Pointer<Utf8> argsJson) => _removeKnownDeviceIp(argsJson);
  int setNetworkLabel(Pointer<Utf8> argsJson) => _setNetworkLabel(argsJson);

  Pointer<Utf8> getTransferHistory(int limit, int offset) => _getTransferHistory(limit, offset);
  Pointer<Utf8> getTransferRecord(Pointer<Utf8> sessionId) => _getTransferRecord(sessionId);
  int deleteTransferRecord(Pointer<Utf8> sessionId) => _deleteTransferRecord(sessionId);

  /// Read a C-allocated JSON string and free it.
  String? readAndFreeJson(Pointer<Utf8> ptr) {
    if (ptr == nullptr) return null;
    try {
      return ptr.toDartString();
    } finally {
      freeString(ptr);
    }
  }

  /// Read sessionId from the 36-byte fixed buffer in CEvent.
  String readSessionId(Pointer<CEvent> event) {
    final buf = event.ref.sessionId;
    // Find NUL terminator
    var len = 0;
    while (len < 36 && buf[len] != 0) {
      len++;
    }
    return String.fromCharCodes(List.generate(len, (i) => buf[i]));
  }

  /// Read peerId from the 36-byte fixed buffer in CEvent.
  String readPeerId(Pointer<CEvent> event) {
    final buf = event.ref.peerId;
    var len = 0;
    while (len < 36 && buf[len] != 0) {
      len++;
    }
    return String.fromCharCodes(List.generate(len, (i) => buf[i]));
  }
}
