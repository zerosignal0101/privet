import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

import 'privet_ffi.dart';

// ---------------------------------------------------------------------------
// Isolate command/result protocol
// ---------------------------------------------------------------------------

/// Commands sent from main isolate to FFI isolate.
class _FfiCommand {
  final String cmd;
  final Map<String, dynamic> args;
  final SendPort replyTo;

  _FfiCommand(this.cmd, this.args, this.replyTo);
}

// ---------------------------------------------------------------------------
// PrivetFfiIsolate — runs FFI calls on a background Isolate
// ---------------------------------------------------------------------------

class PrivetFfiIsolate {
  PrivetFfiIsolate._();
  static final PrivetFfiIsolate instance = PrivetFfiIsolate._();

  SendPort? _sendPort;
  ReceivePort? _eventPort; // receives CEvent notifications
  StreamController<Map<String, dynamic>>? _eventController;

  bool _initStarted = false;
  Completer<void>? _initCompleter;

  Future<void> _ensureIsolate() async {
    if (_sendPort != null) return;
    if (_initStarted) {
      return _initCompleter?.future ?? Future<void>.value();
    }
    _initStarted = true;
    _initCompleter = Completer<void>();

    try {
      final readyPort = ReceivePort();
      _eventPort = ReceivePort();

      Isolate.spawn(
        _isolateEntry,
        _IsolateInit(readyPort.sendPort, _eventPort!.sendPort),
      );

      _sendPort = await readyPort.first as SendPort;
      readyPort.close();

      // Start listening for events from the isolate
      _eventController = StreamController<Map<String, dynamic>>.broadcast();
      _eventPort!.listen((message) {
        if (message is Map<String, dynamic>) {
          _eventController!.add(message);
        }
      });

      _initCompleter!.complete();
    } catch (e) {
      _initCompleter?.completeError(e);
      _initStarted = false;
      rethrow;
    }
  }

  /// Stream of events from the engine. Must be awaited.
  Future<Stream<Map<String, dynamic>>> get eventStream async {
    await _ensureIsolate();
    return _eventController?.stream ?? const Stream.empty();
  }

  Future<Map<String, dynamic>> _call(String cmd, Map<String, dynamic> args) async {
    await _ensureIsolate();
    final response = ReceivePort();
    _sendPort!.send(_FfiCommand(cmd, args, response.sendPort));
    final result = await response.first;
    response.close();
    if (result is Map<String, dynamic>) return result;
    return {'ok': false, 'error': 'unexpected response type'};
  }

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------

  Future<bool> init(String configJson) async {
    final r = await _call('init', {'config_json': configJson});
    return r['ok'] == true;
  }

  Future<bool> initWithDefaults(String deviceName) async {
    final r = await _call('init_with_defaults', {'device_name': deviceName});
    return r['ok'] == true;
  }

  Future<bool> start() async {
    final r = await _call('start', {});
    return r['ok'] == true;
  }

  Future<void> stop() async {
    await _call('stop', {});
  }

  /// Start sending files with a pre-generated session_id (non-blocking).
  /// The caller must register the session via [registerSendSession] before
  /// calling this to avoid a race between session registration and failure events.
  Future<bool> sendFilesStart(String sessionId, String addr, List<String> paths) async {
    final r = await _call('send_files_start', {
      'session_id': sessionId,
      'addr': addr,
      'paths': paths,
    });
    return r['ok'] == true;
  }

  Future<String?> sendFilesToName(String name, List<String> paths) async {
    final r = await _call('send_files_to_name', {
      'name': name,
      'paths': paths,
    });
    if (r['ok'] == true) return r['session_id'] as String?;
    return null;
  }

  Future<bool> acceptTransfer(String sessionId) async {
    final r = await _call('accept_transfer', {'session_id': sessionId});
    return r['ok'] == true;
  }

  Future<bool> rejectTransfer(String sessionId) async {
    final r = await _call('reject_transfer', {'session_id': sessionId});
    return r['ok'] == true;
  }

  Future<bool> cancelTransfer(String sessionId) async {
    final r = await _call('cancel_transfer', {'session_id': sessionId});
    return r['ok'] == true;
  }

  Future<bool> trustPeer(String fingerprint) async {
    final r = await _call('trust_peer', {'fingerprint': fingerprint});
    return r['ok'] == true;
  }

  Future<bool> untrustPeer(String fingerprint) async {
    final r = await _call('untrust_peer', {'fingerprint': fingerprint});
    return r['ok'] == true;
  }

  Future<bool> trustAndAcceptPeer(String fingerprint) async {
    final r = await _call('trust_and_accept_peer', {'fingerprint': fingerprint});
    return r['ok'] == true;
  }

  Future<bool> rejectPairing(String fingerprint) async {
    final r = await _call('reject_pairing', {'fingerprint': fingerprint});
    return r['ok'] == true;
  }

  Future<bool> unacceptPeer(String fingerprint) async {
    final r = await _call('unaccept_peer', {'fingerprint': fingerprint});
    return r['ok'] == true;
  }

  Future<List<Map<String, dynamic>>> getPeers() async {
    final r = await _call('get_peers', {});
    if (r['ok'] == true && r['data'] != null) {
      return (r['data'] as List).cast<Map<String, dynamic>>();
    }
    return [];
  }

  Future<List<String>> getTrustedFingerprints() async {
    final r = await _call('get_trusted_fingerprints', {});
    if (r['ok'] == true && r['data'] != null) {
      return (r['data'] as List).cast<String>();
    }
    return [];
  }

  Future<List<String>> getAcceptedFingerprints() async {
    final r = await _call('get_accepted_fingerprints', {});
    if (r['ok'] == true && r['data'] != null) {
      return (r['data'] as List).cast<String>();
    }
    return [];
  }

  Future<String?> getIdentity() async {
    final r = await _call('get_identity', {});
    if (r['ok'] == true) return r['data'] as String?;
    return null;
  }

  Future<List<Map<String, dynamic>>> getCurrentNetworks() async {
    final r = await _call('get_current_networks', {});
    if (r['ok'] == true && r['data'] != null) {
      return (r['data'] as List).cast<Map<String, dynamic>>();
    }
    return [];
  }

  Future<List<Map<String, dynamic>>> probeKnownDevices() async {
    final r = await _call('probe_known_devices', {});
    if (r['ok'] == true && r['data'] != null) {
      return (r['data'] as List).cast<Map<String, dynamic>>();
    }
    return [];
  }

  Future<List<Map<String, dynamic>>> getKnownDevices() async {
    final r = await _call('get_known_devices', {});
    if (r['ok'] == true && r['data'] != null) {
      return (r['data'] as List).cast<Map<String, dynamic>>();
    }
    return [];
  }

  Future<bool> addKnownDeviceIp(Map<String, dynamic> args) async {
    final r = await _call('add_known_device_ip', args);
    return r['ok'] == true;
  }

  Future<bool> removeKnownDeviceIp(Map<String, dynamic> args) async {
    final r = await _call('remove_known_device_ip', args);
    return r['ok'] == true;
  }

  Future<bool> setNetworkLabel(Map<String, dynamic> args) async {
    final r = await _call('set_network_label', args);
    return r['ok'] == true;
  }

  Future<List<Map<String, dynamic>>> getTransferHistory({
    int limit = 100, int offset = 0,
  }) async {
    final r = await _call('get_transfer_history', {
      'limit': limit, 'offset': offset,
    });
    if (r['ok'] == true && r['data'] != null) {
      return (r['data'] as List).cast<Map<String, dynamic>>();
    }
    return [];
  }

  Future<Map<String, dynamic>?> getTransferRecord(String sessionId) async {
    final r = await _call('get_transfer_record', {
      'session_id': sessionId,
    });
    if (r['ok'] == true && r['data'] != null) {
      return r['data'] as Map<String, dynamic>?;
    }
    return null;
  }

  Future<bool> deleteTransferRecord(String sessionId) async {
    final r = await _call('delete_transfer_record', {
      'session_id': sessionId,
    });
    return r['ok'] == true;
  }
}

// ---------------------------------------------------------------------------
// Isolate init payload
// ---------------------------------------------------------------------------

class _IsolateInit {
  final SendPort readyPort;
  final SendPort eventPort;
  _IsolateInit(this.readyPort, this.eventPort);
}

// ---------------------------------------------------------------------------
// Isolate entry point — all FFI calls happen here
// ---------------------------------------------------------------------------

void _isolateEntry(_IsolateInit init) {
  final port = ReceivePort();
  init.readyPort.send(port.sendPort);

  final ffi = PrivetFfi.instance;
  if (!ffi.initialize()) {
    // Send the port back so the main isolate doesn't hang waiting for init.
    port.listen((message) {
      if (message is _FfiCommand) {
        message.replyTo.send({'ok': false, 'error': 'FFI library not found'});
      }
    });
    return;
  }
  // Poll for events every 50 ms instead of using NativeCallable.listener
  // (which crashes when called from Rust/Tokio threads on Android).
  Timer.periodic(const Duration(milliseconds: 50), (_) {
    _pollEvents(ffi, init);
  });

  // Handle commands from main isolate
  port.listen((message) {
    if (message is! _FfiCommand) return;
    _handleCommand(ffi, message);
  });
}

/// Poll for pending events from Rust and forward them to the main isolate.
void _pollEvents(PrivetFfi ffi, _IsolateInit init) {
  while (true) {
    final ptr = ffi.pollEvent();
    if (ptr == nullptr) break;
    final json = ffi.readAndFreeJson(ptr);
    if (json == null) continue;

    try {
      final data = jsonDecode(json) as Map<String, dynamic>;
      final extraJson = data['extra_json'] as String?;

      Map<String, dynamic>? extra;
      if (extraJson != null) {
        try {
          extra = jsonDecode(extraJson) as Map<String, dynamic>;
        } catch (_) {}
      }

      init.eventPort.send({
        'event_type': data['event_type'] as int? ?? -1,
        'session_id': data['session_id'] as String? ?? '',
        'peer_id': data['peer_id'] as String? ?? '',
        'progress_percent': (data['progress_percent'] as num?)?.toDouble() ?? 0.0,
        'speed_bps': (data['speed_bps'] as num?)?.toDouble() ?? 0.0,
        'bytes_transferred': data['bytes_transferred'] as int? ?? 0,
        'total_bytes': data['total_bytes'] as int? ?? 0,
        'direction': data['direction'] as int? ?? 255,
        'extra': extra,
      });
    } catch (_) {}
  }
}

void _handleCommand(PrivetFfi ffi, _FfiCommand cmd) {
  try {
    switch (cmd.cmd) {
      case 'init':
        _cmdInit(ffi, cmd);
        break;
      case 'init_with_defaults':
        _cmdInitWithDefaults(ffi, cmd);
        break;
      case 'start':
        _cmdStart(ffi, cmd);
        break;
      case 'stop':
        ffi.stop();
        cmd.replyTo.send({'ok': true});
        break;
      case 'send_files_start':
        _cmdSendFilesStart(ffi, cmd);
        break;
      case 'send_files_to_name':
        _cmdSendFilesToName(ffi, cmd);
        break;
      case 'accept_transfer':
        _cmdTransferAction(ffi, cmd, ffi.acceptTransfer);
        break;
      case 'reject_transfer':
        _cmdTransferAction(ffi, cmd, ffi.rejectTransfer);
        break;
      case 'cancel_transfer':
        _cmdTransferAction(ffi, cmd, ffi.cancelTransfer);
        break;
      case 'trust_peer':
        _cmdTrustAction(ffi, cmd, ffi.trustPeer);
        break;
      case 'untrust_peer':
        _cmdTrustAction(ffi, cmd, ffi.untrustPeer);
        break;
      case 'trust_and_accept_peer':
        _cmdTrustAction(ffi, cmd, ffi.trustAndAcceptPeer);
        break;
      case 'reject_pairing':
        _cmdTrustAction(ffi, cmd, ffi.rejectPairing);
        break;
      case 'unaccept_peer':
        _cmdTrustAction(ffi, cmd, ffi.unacceptPeer);
        break;
      case 'get_peers':
        _cmdGetPeers(ffi, cmd);
        break;
      case 'get_trusted_fingerprints':
        _cmdGetTrustedFingerprints(ffi, cmd);
        break;
      case 'get_accepted_fingerprints':
        _cmdGetAcceptedFingerprints(ffi, cmd);
        break;
      case 'get_identity':
        _cmdGetIdentity(ffi, cmd);
        break;
      case 'get_current_networks':
        _cmdGetCurrentNetworks(ffi, cmd);
        break;
      case 'probe_known_devices':
        _cmdProbeKnownDevices(ffi, cmd);
        break;
      case 'get_known_devices':
        _cmdGetKnownDevices(ffi, cmd);
        break;
      case 'add_known_device_ip':
        _cmdAddKnownDeviceIp(ffi, cmd);
        break;
      case 'remove_known_device_ip':
        _cmdRemoveKnownDeviceIp(ffi, cmd);
        break;
      case 'set_network_label':
        _cmdSetNetworkLabel(ffi, cmd);
        break;
      case 'get_transfer_history':
        _cmdGetTransferHistory(ffi, cmd);
        break;
      case 'get_transfer_record':
        _cmdGetTransferRecord(ffi, cmd);
        break;
      case 'delete_transfer_record':
        _cmdDeleteTransferRecord(ffi, cmd);
        break;
      default:
        cmd.replyTo.send({'ok': false, 'error': 'unknown command: ${cmd.cmd}'});
    }
  } catch (e) {
    cmd.replyTo.send({'ok': false, 'error': e.toString()});
  }
}

void _cmdInit(PrivetFfi ffi, _FfiCommand cmd) {
  final configJson = cmd.args['config_json'] as String;
  final ptr = configJson.toNativeUtf8();
  try {
    final result = ffi.init(ptr);
    cmd.replyTo.send({'ok': result == 0});
  } finally {
    calloc.free(ptr);
  }
}

void _cmdInitWithDefaults(PrivetFfi ffi, _FfiCommand cmd) {
  final deviceName = cmd.args['device_name'] as String;
  final ptr = deviceName.toNativeUtf8();
  try {
    final result = ffi.initWithDefaults(ptr);
    cmd.replyTo.send({'ok': result == 0});
  } finally {
    calloc.free(ptr);
  }
}

void _cmdStart(PrivetFfi ffi, _FfiCommand cmd) {
  final result = ffi.start();
  cmd.replyTo.send({'ok': result == 0});
}

void _cmdSendFilesStart(PrivetFfi ffi, _FfiCommand cmd) {
  final sessionId = (cmd.args['session_id'] as String).toNativeUtf8();
  final addr = (cmd.args['addr'] as String).toNativeUtf8();
  final paths = cmd.args['paths'] as List<String>;
  final pathsJson = jsonEncode(paths).toNativeUtf8();

  try {
    final result = ffi.sendFilesStart(sessionId, addr, pathsJson);
    cmd.replyTo.send({'ok': result == 0});
  } finally {
    calloc.free(sessionId);
    calloc.free(addr);
    calloc.free(pathsJson);
  }
}

void _cmdSendFilesToName(PrivetFfi ffi, _FfiCommand cmd) {
  final name = (cmd.args['name'] as String).toNativeUtf8();
  final paths = cmd.args['paths'] as List<String>;
  final pathsJson = jsonEncode(paths).toNativeUtf8();
  final outSessionId = calloc<Uint8>(37);

  try {
    final result = ffi.sendFilesToName(name, pathsJson, outSessionId.cast<Utf8>());
    if (result == 0) {
      var len = 0;
      while (len < 36 && outSessionId[len] != 0) {
        len++;
      }
      final sessionId = String.fromCharCodes(List.generate(len, (i) => outSessionId[i]));
      cmd.replyTo.send({'ok': true, 'session_id': sessionId});
    } else {
      cmd.replyTo.send({'ok': false, 'error': 'send_files_to_name returned $result'});
    }
  } finally {
    calloc.free(name);
    calloc.free(pathsJson);
    calloc.free(outSessionId);
  }
}

void _cmdTransferAction(
  PrivetFfi ffi,
  _FfiCommand cmd,
  int Function(Pointer<Utf8>) action,
) {
  final sessionId = cmd.args['session_id'] as String;
  print('[isolate] _cmdTransferAction: cmd=${cmd.cmd} sessionId=$sessionId');
  final sid = sessionId.toNativeUtf8();
  try {
    final result = action(sid);
    print('[isolate] _cmdTransferAction: result=$result');
    cmd.replyTo.send({'ok': result == 0});
  } finally {
    calloc.free(sid);
  }
}

void _cmdTrustAction(
  PrivetFfi ffi,
  _FfiCommand cmd,
  int Function(Pointer<Utf8>) action,
) {
  final fp = (cmd.args['fingerprint'] as String).toNativeUtf8();
  try {
    final result = action(fp);
    cmd.replyTo.send({'ok': result == 0});
  } finally {
    calloc.free(fp);
  }
}

void _cmdGetPeers(PrivetFfi ffi, _FfiCommand cmd) {
  final ptr = ffi.getPeers();
  final json = ffi.readAndFreeJson(ptr);
  if (json != null) {
    final data = jsonDecode(json);
    cmd.replyTo.send({'ok': true, 'data': data});
  } else {
    cmd.replyTo.send({'ok': false});
  }
}

void _cmdGetTrustedFingerprints(PrivetFfi ffi, _FfiCommand cmd) {
  final ptr = ffi.getTrustedFingerprints();
  final json = ffi.readAndFreeJson(ptr);
  if (json != null) {
    final data = jsonDecode(json);
    cmd.replyTo.send({'ok': true, 'data': data});
  } else {
    cmd.replyTo.send({'ok': false});
  }
}

void _cmdGetAcceptedFingerprints(PrivetFfi ffi, _FfiCommand cmd) {
  final ptr = ffi.getAcceptedFingerprints();
  final json = ffi.readAndFreeJson(ptr);
  if (json != null) {
    final data = jsonDecode(json);
    cmd.replyTo.send({'ok': true, 'data': data});
  } else {
    cmd.replyTo.send({'ok': false});
  }
}

void _cmdGetIdentity(PrivetFfi ffi, _FfiCommand cmd) {
  final ptr = ffi.getIdentity();
  final json = ffi.readAndFreeJson(ptr);
  cmd.replyTo.send({'ok': true, 'data': json});
}

// ---------------------------------------------------------------------------
// Known devices / network awareness command handlers
// ---------------------------------------------------------------------------

void _cmdGetCurrentNetworks(PrivetFfi ffi, _FfiCommand cmd) {
  final ptr = ffi.getCurrentNetworks();
  final json = ffi.readAndFreeJson(ptr);
  if (json != null) {
    final data = jsonDecode(json);
    cmd.replyTo.send({'ok': true, 'data': data});
  } else {
    cmd.replyTo.send({'ok': true, 'data': []});
  }
}

void _cmdProbeKnownDevices(PrivetFfi ffi, _FfiCommand cmd) {
  final ptr = ffi.probeKnownDevices();
  final json = ffi.readAndFreeJson(ptr);
  if (json != null) {
    final data = jsonDecode(json);
    cmd.replyTo.send({'ok': true, 'data': data});
  } else {
    cmd.replyTo.send({'ok': true, 'data': []});
  }
}

void _cmdGetKnownDevices(PrivetFfi ffi, _FfiCommand cmd) {
  final ptr = ffi.getKnownDevices();
  final json = ffi.readAndFreeJson(ptr);
  if (json != null) {
    final data = jsonDecode(json);
    cmd.replyTo.send({'ok': true, 'data': data});
  } else {
    cmd.replyTo.send({'ok': true, 'data': []});
  }
}

void _cmdAddKnownDeviceIp(PrivetFfi ffi, _FfiCommand cmd) {
  final args = cmd.args;
  final argsJson = jsonEncode(args).toNativeUtf8();
  try {
    final result = ffi.addKnownDeviceIp(argsJson);
    cmd.replyTo.send({'ok': result == 0});
  } finally {
    calloc.free(argsJson);
  }
}

void _cmdRemoveKnownDeviceIp(PrivetFfi ffi, _FfiCommand cmd) {
  final args = cmd.args;
  final argsJson = jsonEncode(args).toNativeUtf8();
  try {
    final result = ffi.removeKnownDeviceIp(argsJson);
    cmd.replyTo.send({'ok': result == 0});
  } finally {
    calloc.free(argsJson);
  }
}

void _cmdSetNetworkLabel(PrivetFfi ffi, _FfiCommand cmd) {
  final args = cmd.args;
  final argsJson = jsonEncode(args).toNativeUtf8();
  try {
    final result = ffi.setNetworkLabel(argsJson);
    cmd.replyTo.send({'ok': result == 0});
  } finally {
    calloc.free(argsJson);
  }
}

void _cmdGetTransferHistory(PrivetFfi ffi, _FfiCommand cmd) {
  final limit = cmd.args['limit'] as int? ?? 100;
  final offset = cmd.args['offset'] as int? ?? 0;
  final ptr = ffi.getTransferHistory(limit, offset);
  final json = ffi.readAndFreeJson(ptr);
  if (json != null) {
    final data = jsonDecode(json);
    cmd.replyTo.send({'ok': true, 'data': data});
  } else {
    cmd.replyTo.send({'ok': true, 'data': []});
  }
}

void _cmdGetTransferRecord(PrivetFfi ffi, _FfiCommand cmd) {
  final sessionId = (cmd.args['session_id'] as String).toNativeUtf8();
  try {
    final ptr = ffi.getTransferRecord(sessionId);
    final json = ffi.readAndFreeJson(ptr);
    if (json != null && json != 'null') {
      final data = jsonDecode(json);
      cmd.replyTo.send({'ok': true, 'data': data});
    } else {
      cmd.replyTo.send({'ok': true, 'data': null});
    }
  } finally {
    calloc.free(sessionId);
  }
}

void _cmdDeleteTransferRecord(PrivetFfi ffi, _FfiCommand cmd) {
  final sessionId = (cmd.args['session_id'] as String).toNativeUtf8();
  try {
    final result = ffi.deleteTransferRecord(sessionId);
    cmd.replyTo.send({'ok': result == 0});
  } finally {
    calloc.free(sessionId);
  }
}
