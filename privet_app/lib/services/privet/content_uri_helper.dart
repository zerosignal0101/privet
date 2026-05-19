import 'dart:io' show File, Platform;

import 'package:flutter/services.dart';

const _channel = MethodChannel('privet/file');

/// Android: copy a content:// URI to a temp file and return the file path.
/// Returns null if the URI is invalid or the permission was revoked.
Future<String?> copyContentUri(String uri) async {
  if (!Platform.isAndroid) return null;
  try {
    return await _channel.invokeMethod('copyContentUri', {'uri': uri});
  } catch (_) {
    return null;
  }
}

/// Android: check if a content:// URI is still accessible.
Future<bool> checkContentUri(String uri) async {
  if (!Platform.isAndroid) return false;
  try {
    final ok = await _channel.invokeMethod<bool>('checkContentUri', {'uri': uri});
    return ok ?? false;
  } catch (_) {
    return false;
  }
}

/// Try to recover a file path for sending.
/// 1) If the original cache path still exists, return it.
/// 2) If an Android content:// URI is available, re-cache it.
/// 3) Otherwise return null (user must re-pick).
Future<String?> recoverFilePath({
  required String? cachePath,
  required String? identifier,
}) async {
  if (cachePath != null && await File(cachePath).exists()) {
    return cachePath;
  }
  if (identifier != null && Platform.isAndroid) {
    final accessible = await checkContentUri(identifier);
    if (accessible) return copyContentUri(identifier);
  }
  return null;
}
