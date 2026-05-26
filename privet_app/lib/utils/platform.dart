import 'dart:io';

import 'package:path_provider/path_provider.dart';

/// Base directory for engine data (certificates, trust store, known devices,
/// transfer logs).
///
/// Matches `dirs::data_local_dir()` used by privet-cli:
///   - Windows: `%LOCALAPPDATA%`
///   - Linux:   `$XDG_DATA_HOME` → `~/.local/share`
///   - macOS:   `~/Library/Application Support`
///   - Mobile:  app sandbox documents directory
///
/// The caller appends `/privet/...` subdirectories.
Future<String> engineDataDir() async {
  if (!Platform.isAndroid && !Platform.isIOS) {
    if (Platform.isWindows) {
      final localAppData = Platform.environment['LOCALAPPDATA'];
      if (localAppData != null) return localAppData;
    } else if (Platform.isLinux) {
      final xdg = Platform.environment['XDG_DATA_HOME'];
      if (xdg != null) return xdg;
      final home = Platform.environment['HOME'];
      if (home != null) return '$home/.local/share';
    } else if (Platform.isMacOS) {
      final home = Platform.environment['HOME'];
      if (home != null) return '$home/Library/Application Support';
    }
  }
  // Mobile fallback — app sandbox
  final dir = await getApplicationDocumentsDirectory();
  return dir.path;
}
