import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// A file entry from SAF directory cache with both absolute and relative paths.
class CachedFileEntry {
  final String absolutePath;
  final String relativePath;

  const CachedFileEntry({required this.absolutePath, required this.relativePath});
}

/// Helper to pick and cache a directory on Android using SAF.
class ContentUriDirectoryHelper {
  static const _channel = MethodChannel('privet/file');

  /// Pick a directory via SAF, copy all files to cache, return cached entries.
  /// Returns empty list if user cancelled, null on error.
  static Future<List<CachedFileEntry>?> pickAndCacheDirectory() async {
    if (kIsWeb || !Platform.isAndroid) return null;
    try {
      final result = await _channel.invokeMethod<List<dynamic>>('pickDirectory');
      if (result == null) return null;
      // Parse "absolutePath|relativePath" pairs
      return result.cast<String>().map((s) {
        final sep = s.indexOf('|');
        if (sep > 0) {
          return CachedFileEntry(
            absolutePath: s.substring(0, sep),
            relativePath: s.substring(sep + 1),
          );
        }
        // Fallback: no relative path — use filename
        return CachedFileEntry(
          absolutePath: s,
          relativePath: s.split('/').last,
        );
      }).toList();
    } on MissingPluginException {
      return null;
    } catch (e) {
      debugPrint('[SAF] pickDirectory error: $e');
      return null;
    }
  }
}
