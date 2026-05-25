import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';
import 'package:open_file/open_file.dart';
import 'package:path_provider/path_provider.dart';

import '../providers/providers.dart';
import '../services/clipboard_service.dart';
import '../widgets/peer_picker_sheet.dart';
import '../widgets/file_tree_view.dart';
import '../models/file_tree.dart';
import '../services/privet/content_uri_dir_helper.dart';

/// Multi-file send preparation screen.
/// Allows adding files incrementally, changing recipient, then sending.
class SendPreparationPage extends ConsumerStatefulWidget {
  /// Pre-filled peer info (for resend from history).
  final String? initialPeerAddress;
  final String? initialPeerName;
  final String? initialPeerFingerprint;

  /// Pre-filled file paths (for resend from history).
  /// Each file/directory is scanned to compute relative paths.
  final List<String>? initialFilePaths;

  /// Pre-built file entries (from history Forward/Resend).
  /// Preserves original relative paths including folder hierarchy
  /// (e.g. "colors/colors.json") instead of deriving from file name.
  final List<SendFileEntry>? initialEntries;

  const SendPreparationPage({
    super.key,
    this.initialPeerAddress,
    this.initialPeerName,
    this.initialPeerFingerprint,
    this.initialFilePaths,
    this.initialEntries,
  });

  @override
  ConsumerState<SendPreparationPage> createState() => _SendPreparationPageState();
}

class _SendPreparationPageState extends ConsumerState<SendPreparationPage> {
  bool _initialised = false;

  /// Show a snackbar above the bottom bar so it doesn't block the send button.
  void _showSnackBar(String message, {Duration duration = const Duration(seconds: 2)}) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(message),
      duration: duration,
      behavior: SnackBarBehavior.floating,
      margin: EdgeInsets.only(
        left: 16,
        right: 16,
        bottom: MediaQuery.of(context).viewPadding.bottom + 80,
      ),
    ));
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      _initFromParams();
    });
  }

  void _initFromParams() {
    if (_initialised) return;
    _initialised = true;
    final n = ref.read(sendPreparationProvider.notifier);
    final s = ref.read(sendPreparationProvider);

    // Pre-built entries (from Forward/Resend) — preserves folder hierarchy
    if (widget.initialEntries != null && widget.initialEntries!.isNotEmpty && s.entries.isEmpty) {
      final existing = widget.initialEntries!
          .where((e) => File(e.absolutePath).existsSync())
          .toList();
      final missing = widget.initialEntries!.length - existing.length;
      n.addFileEntries(existing);
      if (missing > 0) {
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (mounted) {
            _showSnackBar('$missing file${missing > 1 ? "s were" : " was"} missing and removed');
          }
        });
      }
    } else if (widget.initialFilePaths != null && s.filePaths.isEmpty && widget.initialFilePaths!.isNotEmpty) {
      final existing = widget.initialFilePaths!
          .where((p) => File(p).existsSync())
          .toList();
      final missing = widget.initialFilePaths!.length - existing.length;
      n.addFiles(existing);
      if (missing > 0) {
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (mounted) {
            _showSnackBar('$missing file${missing > 1 ? "s were" : " was"} missing and removed');
          }
        });
      }
    }
    if (widget.initialPeerAddress != null && s.peerAddress == null) {
      ref.read(sendPreparationProvider.notifier).setPeer(
        widget.initialPeerAddress!,
        name: widget.initialPeerName,
        fingerprint: widget.initialPeerFingerprint,
      );
    }
  }

  Future<bool> _onWillPop() async {
    final s = ref.read(sendPreparationProvider);
    if (s.filePaths.isEmpty) {
      ref.read(sendPreparationProvider.notifier).reset();
      return true;
    }
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Discard file selection?'),
        content: const Text('You have selected files. Do you want to discard them?'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          TextButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Discard')),
        ],
      ),
    );
    if (confirmed == true) {
      ref.read(sendPreparationProvider.notifier).reset();
    }
    return confirmed ?? false;
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(sendPreparationProvider);

    // Resolve pending pairing to keep state fresh (deferred after build)
    final pairing = ref.watch(pairingProvider);
    if (state.pairingRequest != null && pairing.isEmpty) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) {
          ref.read(sendPreparationProvider.notifier).clearPairing();
        }
      });
    }

    final body = Column(
      children: [
        _RecipientSection(
          peerName: state.peerName,
          peerAddress: state.peerAddress,
          onChangeTap: () => _pickPeer(context, ref),
        ),
        const Divider(height: 1),

        // Pairing banner — read from pairingProvider directly
        if (pairing.isNotEmpty)
          _PairingCard(
            request: pairing.last,
            onTrust: () => ref.read(sendPreparationProvider.notifier).trustPeer(),
            onTrustAndAccept: () =>
                ref.read(sendPreparationProvider.notifier).trustAndAcceptPeer(),
            onReject: () =>
                ref.read(sendPreparationProvider.notifier).rejectPeer(),
          ),

        // Sending indicator with stop button
        if (state.sending)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            child: Row(
              children: [
                const SizedBox(width: 16, height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2)),
                const SizedBox(width: 12),
                const Expanded(
                  child: Text('Starting transfer...',
                      style: TextStyle(color: Colors.grey)),
                ),
                TextButton.icon(
                  onPressed: () => ref.read(sendPreparationProvider.notifier).cancelSend(),
                  icon: const Icon(Icons.stop, size: 16, color: Colors.red),
                  label: const Text('Stop', style: TextStyle(color: Colors.red, fontSize: 12)),
                  style: TextButton.styleFrom(padding: EdgeInsets.zero),
                ),
              ],
            ),
          ),

        // Error message
        if (state.sendError != null)
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 0),
            child: Text(state.sendError!,
                style: const TextStyle(color: Colors.red, fontSize: 13)),
          ),

        Expanded(
          child: state.filePaths.isEmpty
              ? ListView(
                  children: [
                    const SizedBox(height: 60),
                    Center(
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(Icons.note_add, size: 48,
                              color: Colors.grey.shade300),
                          const SizedBox(height: 12),
                          const Text('No files selected',
                              style: TextStyle(color: Colors.grey)),
                        ],
                      ),
                    ),
                    _buildAddButtons(ref),
                  ],
                )
              : state.entries.isNotEmpty
                  ? ListView(
                      children: [
                        // Tree view for expanded entries
                        _FileTreeSection(
                          entries: state.entries,
                          onRemove: (relPath) => ref.read(sendPreparationProvider.notifier).removeByRelativePath(relPath),
                        ),
                        // Add buttons at bottom
                        _buildAddButtons(ref),
                      ],
                    )
                  : ListView.builder(
                      itemCount: state.filePaths.length + 1,
                      itemBuilder: (_, i) {
                        if (i == state.filePaths.length) {
                          return _buildAddButtons(ref);
                        }
                        return _FileItem(
                          path: state.filePaths[i],
                          onRemove: () =>
                              ref.read(sendPreparationProvider.notifier).removeFile(i),
                        );
                      },
                    ),
        ),
        const Divider(height: 1),
        _BottomBar(
          fileCount: state.filePaths.length,
          sending: state.sending,
          onSend: state.isReady ? () => _send(context, ref) : null,
        ),
      ],
    );

    return Focus(
      autofocus: true,
      onKeyEvent: (node, event) {
        if (event is KeyDownEvent || event is KeyRepeatEvent) {
          final key = event.logicalKey;
          if (key == LogicalKeyboardKey.keyV &&
              (HardwareKeyboard.instance.isControlPressed ||
               HardwareKeyboard.instance.isMetaPressed)) {
            _pasteFromClipboard(ref);
            return KeyEventResult.handled;
          }
        }
        return KeyEventResult.ignored;
      },
      child: PopScope(
        canPop: false,
        onPopInvokedWithResult: (didPop, _) async {
          if (didPop) return;
          final shouldPop = await _onWillPop();
          if (shouldPop && context.mounted) Navigator.pop(context);
        },
        child: Scaffold(
          appBar: AppBar(title: const Text('Send Files')),
          body: body,
        ),
      ),
    );
  }

  void _pickPeer(BuildContext context, WidgetRef ref) {
    PeerPickerSheet.show(context, onSelected: (addr, {name, fingerprint}) {
      ref.read(sendPreparationProvider.notifier).setPeer(addr, name: name, fingerprint: fingerprint);
    });
  }

  Widget _buildAddButtons(WidgetRef ref) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () => _pickFiles(ref),
                  icon: const Icon(Icons.add, size: 18),
                  label: const Text('Add files'),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () => _pickFolder(ref),
                  icon: const Icon(Icons.create_new_folder, size: 18),
                  label: const Text('Add folder'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () => _pasteFromClipboard(ref),
                  icon: const Icon(Icons.content_paste, size: 18),
                  label: const Text('Paste'),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () => _createTextFile(ref),
                  icon: const Icon(Icons.text_fields, size: 18),
                  label: const Text('Create text'),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Future<void> _pasteFromClipboard(WidgetRef ref) async {
    try {
      // On Windows: first try file paths (files copied via Explorer)
      if (Platform.isWindows) {
        final paths = ClipboardService.readFilePaths();
        if (paths != null && paths.isNotEmpty) {
          ref.read(sendPreparationProvider.notifier).addFiles(paths);
          if (context.mounted) {
            _showSnackBar('Pasted ${paths.length} file(s) from clipboard');
          }
          return;
        }
      }

      // Fall back to text / image content
      final settings = ref.read(settingsProvider);
      final dir = settings.downloadDir.isNotEmpty
          ? settings.downloadDir
          : (await _defaultDownloadDir());

      final saved = await ClipboardService.saveToFile(dir);
      if (saved == null) {
        if (context.mounted) {
          _showSnackBar('Clipboard is empty or contains unsupported content');
        }
        return;
      }

      ref.read(sendPreparationProvider.notifier).addFiles([saved.absolutePath]);
      if (context.mounted) {
        _showSnackBar('Pasted: ${saved.relativePath}');
      }
    } catch (e) {
      if (context.mounted) {
        _showSnackBar('Failed to paste: $e');
      }
    }
  }

  Future<String> _defaultDownloadDir() async {
    final dir = await getApplicationDocumentsDirectory();
    return dir.path;
  }

  Future<void> _createTextFile(WidgetRef ref) async {
    final nameCtrl = TextEditingController();
    final contentCtrl = TextEditingController();
    final settings = ref.read(settingsProvider);
    final dir = settings.downloadDir.isNotEmpty
        ? settings.downloadDir
        : await _defaultDownloadDir();

    final result = await showDialog<({String name, String content})?>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Create Text File'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: nameCtrl,
              decoration: const InputDecoration(
                labelText: 'File name (optional)',
                hintText: 'Leave empty for auto-name',
                suffixText: '.txt',
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: contentCtrl,
              decoration: const InputDecoration(
                labelText: 'Content',
                border: OutlineInputBorder(),
              ),
              maxLines: 6,
              minLines: 3,
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(onPressed: () {
            final content = contentCtrl.text;
            if (content.trim().isEmpty) return;
            Navigator.pop(ctx, (name: nameCtrl.text, content: content));
          }, child: const Text('Create')),
        ],
      ),
    );

    if (result == null || result.content.trim().isEmpty) return;

    try {
      // Derive filename
      final rawName = result.name.trim();
      final String fileName;
      if (rawName.isNotEmpty) {
        // Sanitize: keep only safe chars
        final clean = rawName.replaceAll(RegExp(r'[^\w\-_. ()]'), '');
        fileName = clean.isNotEmpty ? clean : 'text';
      } else {
        fileName = ClipboardService.textFilename(result.content);
      }

      final (path: filePath, relativePath: relPath) = ClipboardService.uniqueFile(dir, '$fileName.txt');
      final file = File(filePath);
      await file.writeAsString(result.content);

      ref.read(sendPreparationProvider.notifier).addFiles([file.path]);
      if (context.mounted) {
        _showSnackBar('Created: $relPath');
      }
    } catch (e) {
      if (context.mounted) {
        _showSnackBar('Failed to create file: $e');
      }
    }
  }

  void _pickFiles(WidgetRef ref) async {
    final result = await FilePicker.platform.pickFiles(allowMultiple: true);
    if (result != null && result.files.isNotEmpty) {
      final paths = result.files.map((f) => f.path!).toList();
      final ids = <String, String?>{};
      for (int i = 0; i < result.files.length; i++) {
        final f = result.files[i];
        if (f.path != null && f.identifier != null) {
          ids[f.path!] = f.identifier;
        }
      }
      ref.read(sendPreparationProvider.notifier).addFiles(
        paths,
        identifiers: ids.isNotEmpty ? ids : null,
      );
    }
  }

  void _pickFolder(WidgetRef ref) async {
    if (Platform.isAndroid) {
      // Android: use native SAF picker (ACTION_OPEN_DOCUMENT_TREE) which
      // always returns a content:// URI, bypassing file_picker's MIUI path bug.
      // Files are copied to cache via ContentResolver on the native side.
      final entries = await ContentUriDirectoryHelper.pickAndCacheDirectory();
      debugPrint('[pickFolder] SAF picker result: ${entries?.length ?? 0} entries');
      if (entries != null && entries.isNotEmpty) {
        final sendEntries = entries.map((e) {
          int size = 0;
          try { size = File(e.absolutePath).lengthSync(); } catch (_) {}
          return SendFileEntry(
            absolutePath: e.absolutePath,
            relativePath: e.relativePath,
            size: size,
          );
        }).toList();
        ref.read(sendPreparationProvider.notifier).addFileEntries(sendEntries);
      } else if (entries != null && entries.isEmpty) {
        debugPrint('[pickFolder] user cancelled SAF picker');
      } else {
        if (context.mounted) {
          _showSnackBar('Could not access folder via SAF. Try selecting files individually.');
        }
      }
      return;
    }

    // Non-Android: use file_picker
    final dirPath = await FilePicker.platform.getDirectoryPath();
    if (dirPath != null) {
      ref.read(sendPreparationProvider.notifier).addFiles([dirPath]);
    }
  }

  Future<void> _send(BuildContext context, WidgetRef ref) async {
    final sessionId = await ref.read(sendPreparationProvider.notifier).send();
    if (!context.mounted) return;

    // User cancelled — keep the file list on the page so they can retry.
    if (sessionId == null && ref.read(sendPreparationProvider).sendError == 'Transfer cancelled') {
      return;
    }

    ref.read(sendPreparationProvider.notifier).reset();
    // Always switch to Home tab so user can see the transfer result
    ref.read(shellTabProvider.notifier).select(0);

    if (context.mounted) {
      Navigator.popUntil(context, (route) => route.isFirst);
    }

    if (context.mounted) {
      final err = ref.read(sendPreparationProvider).sendError;
      if (sessionId != null) {
        _showSnackBar('Transfer started', duration: const Duration(seconds: 1));
      } else if (err != null && err.isNotEmpty) {
        _showSnackBar('Send failed: $err', duration: const Duration(seconds: 3));
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Recipient section
// ---------------------------------------------------------------------------

class _RecipientSection extends StatelessWidget {
  final String? peerName;
  final String? peerAddress;
  final VoidCallback onChangeTap;

  const _RecipientSection({
    this.peerName,
    this.peerAddress,
    required this.onChangeTap,
  });

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: const Icon(Icons.person),
      title: Text(peerName ?? 'No recipient selected'),
      subtitle: peerAddress != null ? Text(peerAddress!) : null,
      trailing: TextButton(
        onPressed: onChangeTap,
        child: const Text('Change'),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// File item
// ---------------------------------------------------------------------------

class _FileItem extends StatelessWidget {
  final String path;
  final VoidCallback onRemove;

  const _FileItem({required this.path, required this.onRemove});

  @override
  Widget build(BuildContext context) {
    debugPrint('[FileItem] path="$path"');

    // Handle content:// URIs — cannot access via dart:io
    if (path.startsWith('content://')) {
      final name = path.split('/').last;
      return ListTile(
        leading: Icon(Icons.folder, color: Colors.amber.shade600, size: 22),
        title: Text(Uri.decodeComponent(name),
            overflow: TextOverflow.ellipsis, style: const TextStyle(fontSize: 14)),
        subtitle: const Text('Android content URI (cannot scan)',
            style: TextStyle(fontSize: 12, color: Colors.grey)),
        trailing: IconButton(
          icon: const Icon(Icons.close, size: 18),
          onPressed: onRemove,
        ),
      );
    }

    final entity = FileSystemEntity.typeSync(path);
    final exists = entity != FileSystemEntityType.notFound;
    final isDir = entity == FileSystemEntityType.directory;
    final name = path.split(Platform.pathSeparator).last;
    int size = 0;
    if (exists && !isDir) {
      try { size = File(path).lengthSync(); } catch (_) {}
    }
    debugPrint('[FileItem] pathType=$entity exists=$exists isDir=$isDir');

    return ListTile(
      leading: Icon(
        isDir ? Icons.folder : (exists ? Icons.insert_drive_file : Icons.error_outline),
        color: isDir ? Colors.amber.shade600 : (exists ? null : Colors.red),
        size: 22,
      ),
      title: Text(
        name,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(
          fontSize: 14,
          color: exists ? null : Colors.grey,
        ),
      ),
      subtitle: Text(
        isDir ? 'Folder selected (scanned on send)' : (exists ? _formatSize(size) : 'File not found'),
        style: TextStyle(
          fontSize: 12,
          color: exists ? Colors.grey : Colors.red.shade300,
        ),
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (exists && !isDir)
            IconButton(
              icon: const Icon(Icons.open_in_new, size: 18),
              tooltip: 'Open file',
              onPressed: () => OpenFile.open(path),
            ),
          IconButton(
            icon: const Icon(Icons.close, size: 18),
            onPressed: onRemove,
          ),
        ],
      ),
    );
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

// ---------------------------------------------------------------------------
// Bottom bar with send button
// ---------------------------------------------------------------------------

class _BottomBar extends StatelessWidget {
  final int fileCount;
  final bool sending;
  final VoidCallback? onSend;

  const _BottomBar({
    required this.fileCount,
    this.sending = false,
    required this.onSend,
  });

  @override
  Widget build(BuildContext context) {
    final bottomPad = MediaQuery.of(context).viewPadding.bottom + 8;
    return Padding(
      padding: EdgeInsets.fromLTRB(16, 8, 16, bottomPad),
      child: Row(
        children: [
          Text(
            '$fileCount file${fileCount != 1 ? 's' : ''} selected',
            style: const TextStyle(fontSize: 14),
          ),
          const Spacer(),
          FilledButton.icon(
            onPressed: sending ? null : onSend,
            icon: sending
                ? const SizedBox(
                    width: 18, height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                  )
                : const Icon(Icons.send, size: 18),
            label: Text(sending ? 'Sending...' : 'Send'),
          ),
        ],
      ),
    );
  }
}



// ---------------------------------------------------------------------------
// File tree section shown in the send preparation page
// ---------------------------------------------------------------------------

class _FileTreeSection extends StatelessWidget {
  final List<SendFileEntry> entries;
  final void Function(String relativePath) onRemove;

  const _FileTreeSection({required this.entries, required this.onRemove});

  @override
  Widget build(BuildContext context) {
    final treeNodes = _buildTree(entries);
    return FileTreeView(
      nodes: treeNodes,
      showRemoveButtons: true,
      onRemoveFile: onRemove,
      formatSize: _formatSize,
    );
  }

  /// Build a tree from the flat entries list, using `isDir` to mark directory nodes.
  List<FileTreeNode> _buildTree(List<SendFileEntry> entries) {
    // Collect file paths and directory markers
    final filePaths = <String>[];
    final dirSet = <String>{};
    for (final e in entries) {
      if (e.isDir) {
        dirSet.add(e.relativePath);
      } else {
        filePaths.add(e.relativePath);
      }
    }

    // Build tree with known directories clearly marked
    final lookup = <String, List<String>>{};
    for (final path in filePaths) {
      final parts = path.split('/');
      if (parts.isEmpty) continue;
      final fileName = parts.last;
      final dirParts = parts.sublist(0, parts.length - 1);
      final dirKey = dirParts.join('/');
      lookup.putIfAbsent(dirKey, () => []).add(fileName);
    }
    // Also add empty dirs so they appear in the lookup
    for (final dirPath in dirSet) {
      final parts = dirPath.split('/');
      for (int i = 0; i < parts.length; i++) {
        final prefix = parts.sublist(0, i).join('/');
        lookup.putIfAbsent(prefix, () => []);
      }
    }

    // Build size map and absolute path map: relativePath → (size, absolutePath)
    final sizeMap = <String, int>{};
    final absPathMap = <String, String>{};
    for (final e in entries) {
      sizeMap[e.relativePath] = e.size;
      absPathMap[e.relativePath] = e.absolutePath;
    }

    return _buildTreeNodes(lookup, '', dirSet, sizeMap, absPathMap);
  }

  List<FileTreeNode> _buildTreeNodes(Map<String, List<String>> lookup, String prefix, Set<String> dirSet, Map<String, int> sizeMap, Map<String, String> absPathMap) {
    final result = <FileTreeNode>[];
    final dirs = <String>{};
    final files = <String>[];

    for (final entry in lookup.entries) {
      final dirPath = entry.key;
      if (dirPath == prefix) {
        for (final fileName in entry.value) {
          final fullPath = prefix.isEmpty ? fileName : '$prefix/$fileName';
          // Check if it's a known directory marker or has a sub-path in dirSet
          if (dirSet.contains(fullPath)) {
            dirs.add(fullPath);
          } else {
            files.add(fileName);
          }
        }
      } else if (dirPath.startsWith(prefix) && prefix.length < dirPath.length) {
        final rest = dirPath.substring(prefix.isEmpty ? 0 : prefix.length + 1);
        if (!rest.contains('/')) {
          dirs.add(dirPath);
        }
      }
    }

    // Add directories (sorted)
    for (final dirPath in (dirs.toList()..sort())) {
      final dirName = dirPath.contains('/') ? dirPath.split('/').last : dirPath;
      final children = _buildTreeNodes(lookup, dirPath, dirSet, sizeMap, absPathMap);
      result.add(FileTreeNode(
        name: dirName,
        relativePath: dirPath,
        isDir: true,
        children: children,
      ));
    }

    // Add files (sorted)
    for (final fileName in (files..sort())) {
      final relPath = prefix.isEmpty ? fileName : '$prefix/$fileName';
      result.add(FileTreeNode(
        name: fileName,
        relativePath: relPath,
        fullPath: absPathMap[relPath],
        isDir: false,
        size: sizeMap[relPath] ?? 0,
      ));
    }

    return result;
  }

  static String _formatSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
  }
}

// ---------------------------------------------------------------------------
// Pairing card shown inside the preparation page
// ---------------------------------------------------------------------------

class _PairingCard extends StatelessWidget {
  final PairRequest request;
  final VoidCallback onTrust;
  final VoidCallback onTrustAndAccept;
  final VoidCallback onReject;

  const _PairingCard({
    required this.request,
    required this.onTrust,
    required this.onTrustAndAccept,
    required this.onReject,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      color: Colors.orange.shade50,
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.shield, size: 18, color: Colors.orange),
                const SizedBox(width: 8),
                Text('Pairing required',
                    style: TextStyle(fontWeight: FontWeight.bold,
                        color: Colors.orange.shade800)),
              ],
            ),
            const SizedBox(height: 4),
            Text('Trust this device to send files?',
                style: const TextStyle(fontSize: 13)),
            if (request.code.isNotEmpty)
              Text('Verification code: ${request.code}',
                  style: const TextStyle(fontSize: 12, color: Colors.grey)),
            const SizedBox(height: 8),
            Wrap(
              spacing: 6,
              runSpacing: 6,
              children: [
                TextButton.icon(
                  onPressed: onReject,
                  icon: const Icon(Icons.close, size: 14),
                  label: const Text('Reject', style: TextStyle(fontSize: 12)),
                ),
                OutlinedButton.icon(
                  onPressed: onTrust,
                  icon: const Icon(Icons.verified, size: 14),
                  label: const Text('Trust', style: TextStyle(fontSize: 12)),
                ),
                FilledButton.icon(
                  onPressed: onTrustAndAccept,
                  icon: const Icon(Icons.star, size: 14),
                  label: const Text('Trust & Accept',
                      style: TextStyle(fontSize: 12)),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
