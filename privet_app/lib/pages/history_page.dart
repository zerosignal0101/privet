import 'dart:io' show File, Platform;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:open_file/open_file.dart';

import 'send_preparation_page.dart';

import '../models/transfer_history.dart';
import '../models/file_tree.dart';
import '../services/privet/content_uri_helper.dart' show openContentUri, recoverFilePath;
import '../providers/providers.dart';
import '../widgets/file_tree_view.dart';

class HistoryPage extends ConsumerWidget {
  const HistoryPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final records = ref.watch(transferHistoryProvider);
    final settings = ref.watch(settingsProvider);
    final downloadDir = settings.downloadDir.isNotEmpty ? settings.downloadDir : null;
    debugPrint('[history] build: downloadDir="$downloadDir" records=${records.length}');

    return Scaffold(
      appBar: AppBar(
        title: const Text('History'),
        actions: [
          if (records.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.refresh),
              onPressed: () => ref.read(transferHistoryProvider.notifier).refresh(),
            ),
        ],
      ),
      body: records.isEmpty
          ? const Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.history, size: 64, color: Colors.grey),
                  SizedBox(height: 16),
                  Text('No transfer history yet',
                      style: TextStyle(color: Colors.grey, fontSize: 16)),
                ],
              ),
            )
          : RefreshIndicator(
              onRefresh: () => ref.read(transferHistoryProvider.notifier).refresh(),
              child: ListView.builder(
                itemCount: records.length,
                itemBuilder: (_, i) => _HistoryRecordTile(
                  record: records[i],
                  downloadDir: downloadDir,
                ),
              ),
            ),
    );
  }
}

class _HistoryRecordTile extends ConsumerWidget {
  final TransferHistoryRecord record;
  final String? downloadDir;

  const _HistoryRecordTile({required this.record, this.downloadDir});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final isReceive = record.direction == TransferDirection.receiving;
    final isFailed = record.state == TransferRecordState.failed;

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: ExpansionTile(
        leading: Icon(
          isReceive ? Icons.arrow_downward : Icons.arrow_upward,
          color: isFailed ? Colors.red : (isReceive ? Colors.blue : Colors.orange),
        ),
        title: Text(
          record.peerName.isNotEmpty ? record.peerName : 'Unknown device',
          style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w500),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Row(
              children: [
                _stateBadge(record.state, theme),
                const Spacer(),
                Text(record.fileCountText,
                    style: const TextStyle(fontSize: 11, color: Colors.grey)),
              ],
            ),
            Align(
              alignment: Alignment.centerRight,
              child: Text(_formatTime(record.completedAt),
                  style: const TextStyle(fontSize: 11, color: Colors.grey)),
            ),
          ],
        ),
        children: [
          if (record.error != null)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 4),
              child: Text(record.error!,
                  style: const TextStyle(fontSize: 12, color: Colors.red)),
            ),
          // Show hierarchical tree if there are directory structures.
          ..._buildFileList(context, record.files),
          // Resend/Forward + Delete
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
            child: Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: () => _resend(context, ref),
                    icon: const Icon(Icons.refresh, size: 16),
                    label: Text(isReceive ? 'Forward' : 'Resend'),
                  ),
                ),
                const SizedBox(width: 8),
                OutlinedButton.icon(
                  onPressed: () => _delete(context, ref),
                  icon: const Icon(Icons.delete_outline, size: 16),
                  label: const Text('Delete'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: Colors.red,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  void _delete(BuildContext context, WidgetRef ref) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete record?'),
        content: const Text('This removes the transfer from history.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          TextButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Delete')),
        ],
      ),
    );
    if (confirmed == true) {
      await ref.read(transferHistoryProvider.notifier).deleteRecord(record.sessionId);
    }
  }

  Widget _stateBadge(TransferRecordState state, ThemeData theme) {
    final (icon, color, label) = switch (state) {
      TransferRecordState.completed => (Icons.check_circle, Colors.green, 'Completed'),
      TransferRecordState.failed => (Icons.error, Colors.red, 'Failed'),
      TransferRecordState.cancelled => (Icons.cancel, Colors.grey, 'Cancelled'),
      TransferRecordState.rejected => (Icons.block, Colors.orange, 'Rejected'),
    };
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 14, color: color),
        const SizedBox(width: 4),
        Text(label, style: TextStyle(fontSize: 11, color: color)),
      ],
    );
  }

  Widget _fileTile(TransferFileRecord f, BuildContext context) {
    final fileName = f.path.split(Platform.pathSeparator).last;
    final bool isReceiveFile = record.direction == TransferDirection.receiving;

    if (isReceiveFile) {
      // Received file — path is absolute (new records) or relative (legacy records).
      // For legacy relative paths, fall back to downloadDir prefix.
      final filePath = File(f.path).isAbsolute
          ? f.path
          : (downloadDir != null ? '$downloadDir/${f.path}' : null);
      final exists = filePath != null ? File(filePath).existsSync() : false;
      debugPrint('[history] receive file: path="$filePath" exists=$exists');

      return ListTile(
        dense: true,
        leading: Icon(
          f.isDir ? Icons.folder : Icons.insert_drive_file,
          size: 18,
          color: exists ? null : Colors.grey,
        ),
        title: Text(fileName, style: const TextStyle(fontSize: 13)),
        subtitle: Text(
          exists ? _formatSize(f.size) : 'Moved / Missing',
          style: TextStyle(fontSize: 11,
              color: exists ? Colors.grey : Colors.orange),
        ),
        trailing: exists && !f.isDir
            ? IconButton(
                icon: const Icon(Icons.open_in_new, size: 16),
                tooltip: 'Open file',
                onPressed: () => OpenFile.open(filePath),
              )
            : null,
      );
    } else {
      // Sent file — path may be a cache path (file_picker) or a recovered content URI copy.
      final absPath = File(f.path).isAbsolute ? f.path : null;
      final exists = absPath != null && File(absPath).existsSync();
      final hasContentUri = f.identifier != null && Platform.isAndroid;
      debugPrint('[history] sent file: path="$absPath" exists=$exists hasContentUri=$hasContentUri');

      return ListTile(
        dense: true,
        leading: Icon(
          exists ? Icons.insert_drive_file : Icons.file_present,
          size: 18,
          color: exists ? null : Colors.grey,
        ),
        title: Text(
          fileName,
          style: TextStyle(fontSize: 13, color: exists ? null : Colors.grey),
        ),
        subtitle: Text(
          exists ? _formatSize(f.size) : (hasContentUri ? 'Content URI available' : 'File not accessible'),
          style: TextStyle(
            fontSize: 11,
            color: exists ? Colors.grey : Colors.orange,
          ),
        ),
        trailing: !f.isDir && (exists || hasContentUri)
            ? IconButton(
                icon: const Icon(Icons.open_in_new, size: 16),
                tooltip: 'Open file',
                onPressed: () {
                  if (absPath != null && File(absPath).existsSync()) {
                    OpenFile.open(absPath);
                  } else if (hasContentUri) {
                    openContentUri(f.identifier!);
                  }
                },
              )
            : null,
      );
    }
  }

  /// Build the file list — uses tree view for hierarchical structures.
  List<Widget> _buildFileList(BuildContext context, List<TransferFileRecord> files) {
    // Check if any file has a directory structure (relative path with '/')
    final hasHierarchy = files.any((f) =>
        (f.relativePath != null && f.relativePath!.contains('/')) ||
        (f.path.contains('/') && !File(f.path).isAbsolute));

    if (!hasHierarchy) {
      // Flat list — single-level display
      return files.map((f) => _fileTile(f, context)).toList();
    }

    // Build tree from records
    final treeNodes = buildFileTreeFromRecords(files);
    // Build lookup: absolute path → content:// URI for sent file fallback
    final pathToIdentifier = <String, String>{};
    for (final f in files) {
      if (f.identifier != null && File(f.path).isAbsolute) {
        pathToIdentifier[f.path] = f.identifier!;
      }
    }

    return [
      Padding(
        padding: const EdgeInsets.symmetric(horizontal: 8),
        child: FileTreeView(
          nodes: treeNodes,
          onOpenFile: (path) => _openFile(context, path, pathToIdentifier),
          formatSize: _formatSize,
        ),
      ),
    ];
  }

  void _openFile(BuildContext context, String path, Map<String, String> pathToIdentifier) {
    if (File(path).existsSync()) {
      OpenFile.open(path);
      return;
    }
    // Try content:// URI fallback for sent files
    final identifier = pathToIdentifier[path];
    if (identifier != null && Platform.isAndroid) {
      openContentUri(identifier);
      return;
    }
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('File not found')),
    );
  }

  void _resend(BuildContext context, WidgetRef ref) async {
    final bool isReceiveFile = record.direction == TransferDirection.receiving;

    // Build SendFileEntry list that preserves the original relativePath
    // (e.g. "colors/colors.json") so the send preparation page shows
    // the correct folder hierarchy.
    List<SendFileEntry> buildEntries(List<TransferFileRecord> files) {
      return files.map((f) {
        final p = File(f.path).isAbsolute
            ? f.path
            : (downloadDir != null ? '$downloadDir/${f.path}' : null);
        if (p == null || !File(p).existsSync()) return null;
        return SendFileEntry(
          absolutePath: p,
          relativePath: f.relativePath ?? p.split(Platform.pathSeparator).last,
          size: f.size,
          isDir: f.isDir,
        );
      }).whereType<SendFileEntry>().toList();
    }

    if (isReceiveFile) {
      // Forward received files
      final entries = buildEntries(record.files);

      if (!context.mounted) return;
      if (entries.isEmpty) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Received files not found on disk')),
        );
        return;
      }
      Navigator.push(
        context,
        MaterialPageRoute(
          builder: (_) => SendPreparationPage(
            initialEntries: entries,
            initialPeerAddress: record.peerAddress,
            initialPeerName: record.peerName,
            initialPeerFingerprint: record.peerFingerprint,
          ),
        ),
      );
      return;
    }

    // Resend: try to recover original files via identifier (content:// URI)
    final recovered = <SendFileEntry>[];
    int missingCount = 0;

    for (final f in record.files) {
      final path = await recoverFilePath(
        cachePath: f.path,
        identifier: f.identifier,
      );
      if (path != null) {
        recovered.add(SendFileEntry(
          absolutePath: path,
          relativePath: f.relativePath ?? path.split(Platform.pathSeparator).last,
          size: f.size,
          isDir: f.isDir,
        ));
      } else {
        missingCount++;
      }
    }

    if (!context.mounted) return;

    if (missingCount > 0 && recovered.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Original files are no longer accessible ($missingCount missing). '
              'Please select files again.'),
        ),
      );
    }

    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => SendPreparationPage(
          initialEntries: recovered.isNotEmpty ? recovered : null,
          initialPeerAddress: record.peerAddress,
          initialPeerName: record.peerName,
          initialPeerFingerprint: record.peerFingerprint,
        ),
      ),
    );
  }

  String _formatTime(DateTime? dt) {
    if (dt == null) return '';
    final now = DateTime.now();
    final diff = now.difference(dt);
    if (diff.inMinutes < 1) return 'just now';
    if (diff.inHours < 1) return '${diff.inMinutes}m ago';
    if (diff.inDays < 1) return '${diff.inHours}h ago';
    if (diff.inDays < 7) return '${diff.inDays}d ago';
    return '${dt.month}/${dt.day}';
  }

  String _formatSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
  }
}
