import 'dart:io';

import 'transfer_history.dart';

/// A node in the file tree shown during send preparation and in transfer history.
class FileTreeNode {
  final String name; /// Display name (leaf component of the path)
  final String relativePath; /// Full relative path from the root
  final String? fullPath; /// Absolute path on disk (for opening files, null for virtual nodes)
  final int size; /// 0 for directory nodes
  final bool isDir; /// true for directory markers
  final List<FileTreeNode> children;

  const FileTreeNode({
    required this.name,
    required this.relativePath,
    this.fullPath,
    this.size = 0,
    this.isDir = false,
    this.children = const [],
  });

  /// Total number of files (non-dir) in this subtree.
  int get fileCount {
    if (!isDir) return 1;
    return children.fold(0, (sum, c) => sum + c.fileCount);
  }

  /// Total size of all files in this subtree.
  int get totalSize {
    if (!isDir) return size;
    return children.fold(0, (sum, c) => sum + c.totalSize);
  }
}

/// Build a tree from a flat list of relative paths with sizes.
/// Used for incoming transfer display where file sizes come from the Offer.
List<FileTreeNode> buildFileTreeFromSizedPaths(Map<String, int> pathSizes) {
  final pathMap = <String, _RecordEntry>{};
  for (final entry in pathSizes.entries) {
    pathMap[entry.key] = _RecordEntry(size: entry.value);
  }
  return _buildTreeFromMap(pathMap, '');
}

/// Build a tree from a flat list of relative paths.
/// Each path is split by '/' to create nested nodes.
/// [dirPaths] is an optional set of relative paths that should be treated as directories.
List<FileTreeNode> buildFileTreeFromPaths(List<String> relativePaths, {Set<String>? dirPaths}) {
  dirPaths ??= <String>{};
  final root = <String, List<String>>{};

  for (final path in relativePaths) {
    final parts = path.split('/');
    if (parts.isEmpty) continue;
    final fileName = parts.last;
    final dirParts = parts.sublist(0, parts.length - 1);
    final dirKey = dirParts.join('/');
    root.putIfAbsent(dirKey, () => []).add(fileName);
  }

  return _buildTreeNodes(root, '');
}

List<FileTreeNode> _buildTreeNodes(Map<String, List<String>> lookup, String prefix) {
  final result = <FileTreeNode>[];

  // Find direct children of this prefix
  final dirs = <String>{};
  final files = <String>[];

  for (final entry in lookup.entries) {
    final dirPath = entry.key;
    if (dirPath == prefix) {
      for (final fileName in entry.value) {
        files.add(fileName);
      }
    } else if (dirPath.startsWith(prefix) && prefix.length < dirPath.length) {
      final rest = dirPath.substring(prefix.isEmpty ? 0 : prefix.length + 1);
      if (!rest.contains('/')) {
        dirs.add(dirPath);
      }
    }
  }

  // Add directory nodes (sorted)
  final sortedDirs = dirs.toList()..sort();
  for (final dirPath in sortedDirs) {
    final dirName = dirPath.contains('/') ? dirPath.split('/').last : dirPath;
    final children = _buildTreeNodes(lookup, dirPath);
    result.add(FileTreeNode(
      name: dirName,
      relativePath: dirPath,
      isDir: true,
      children: children,
    ));
  }

  // Add file nodes (sorted)
  files.sort();
  for (final fileName in files) {
    final fullPath = prefix.isEmpty ? fileName : '$prefix/$fileName';
    result.add(FileTreeNode(
      name: fileName,
      relativePath: fullPath,
      isDir: false,
    ));
  }

  return result;
}

/// Build a tree from TransferFileRecord list, preserving absolute paths.
List<FileTreeNode> buildFileTreeFromRecords(List<TransferFileRecord> records) {
  // Group by relative path, building a map from relativePath → (fullPath, record)
  final pathMap = <String, _RecordEntry>{};
  for (final r in records) {
    final relPath = r.relativePath ?? r.path.split('/').last;
    pathMap[relPath] = _RecordEntry(
      fullPath: File(r.path).isAbsolute ? r.path : null,
      isDir: r.isDir,
      size: r.size,
    );
  }
  return _buildTreeFromMap(pathMap, '');
}

class _RecordEntry {
  final String? fullPath;
  final bool isDir;
  final int size;
  const _RecordEntry({this.fullPath, this.isDir = false, this.size = 0});
}

List<FileTreeNode> _buildTreeFromMap(Map<String, _RecordEntry> pathMap, String prefix) {
  // Group paths at the current level by their first path component.
  // e.g. ["colors", "colors/colors.json"] → first="colors", both grouped together.
  final groups = <String, List<String>>{};
  for (final relPath in pathMap.keys) {
    if (relPath == prefix) continue;
    // Non-empty prefix must match with trailing '/' to avoid treating
    // sibling paths like "colors.json" as children of "colors".
    if (prefix.isNotEmpty && !relPath.startsWith('$prefix/')) continue;
    final rest = prefix.isEmpty ? relPath : relPath.substring(prefix.length + 1);
    final first = rest.split('/').first;
    groups.putIfAbsent(first, () => []).add(relPath);
  }

  final result = <FileTreeNode>[];
  // Sort for deterministic order
  final sortedNames = groups.keys.toList()..sort();
  for (final name in sortedNames) {
    final fullPath = prefix.isEmpty ? name : '$prefix/$name';
    final subPaths = groups[name]!;
    final entry = pathMap[fullPath];

    // Determine if this is a directory:
    //   (a) it has children (subPaths differ from itself), OR
    //   (b) it's explicitly marked as a directory (e.g. an empty dir marker)
    // If neither, it's a regular file.
    final isDir = subPaths.any((p) => p != fullPath) || (entry?.isDir == true);

    if (isDir) {
      final children = _buildTreeFromMap(pathMap, fullPath);
      final dirSize = children.fold(0, (sum, c) => sum + c.size);
      result.add(FileTreeNode(
        name: name,
        relativePath: fullPath,
        fullPath: entry?.fullPath,
        size: dirSize,
        isDir: true,
        children: children,
      ));
    } else {
      result.add(FileTreeNode(
        name: name,
        relativePath: fullPath,
        fullPath: entry?.fullPath,
        size: entry?.size ?? 0,
        isDir: entry?.isDir ?? false,
      ));
    }
  }

  return result;
}
