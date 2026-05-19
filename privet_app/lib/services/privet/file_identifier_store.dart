import 'dart:convert';
import 'dart:io';

import 'package:path_provider/path_provider.dart';

/// Stores file identifiers (Android content:// URIs) mapped by session_id.
/// Persisted as a JSON file so identifiers survive app restarts.
class FileIdentifierStore {
  FileIdentifierStore._();
  static final FileIdentifierStore instance = FileIdentifierStore._();

  Map<String, Map<String, String?>> _data = {}; // session_id → {cache_path: identifier}
  bool _loaded = false;

  Future<File> get _file async {
    final dir = await getApplicationDocumentsDirectory();
    return File('${dir.path}/privet/file_identifiers.json');
  }

  Future<void> _ensureLoaded() async {
    if (_loaded) return;
    _loaded = true;
    try {
      final file = await _file;
      if (await file.exists()) {
        final content = await file.readAsString();
        _data = Map<String, Map<String, String?>>.from(
          (jsonDecode(content) as Map<String, dynamic>).map(
            (k, v) => MapEntry(k, Map<String, String?>.from(
              (v as Map<String, dynamic>).map((k2, v2) => MapEntry(k2, v2 as String?)),
            )),
          ),
        );
      }
    } catch (_) {
      _data = {};
    }
  }

  Future<void> _save() async {
    try {
      final file = await _file;
      await file.parent.create(recursive: true);
      await file.writeAsString(jsonEncode(_data));
    } catch (_) {}
  }

  /// Record identifiers for a send session.
  Future<void> recordIdentifiers(String sessionId, Map<String, String?> pathToIdentifier) async {
    await _ensureLoaded();
    _data[sessionId] = pathToIdentifier;
    await _save();
  }

  /// Get identifier for a cache path in a given session.
  Future<String?> getIdentifier(String sessionId, String cachePath) async {
    await _ensureLoaded();
    return _data[sessionId]?[cachePath];
  }

  /// Get all path→identifier mappings for a session.
  Future<Map<String, String?>> getSessionIdentifiers(String sessionId) async {
    await _ensureLoaded();
    return _data[sessionId] ?? {};
  }

  /// Delete identifiers for a session.
  Future<void> deleteSession(String sessionId) async {
    await _ensureLoaded();
    _data.remove(sessionId);
    await _save();
  }
}
