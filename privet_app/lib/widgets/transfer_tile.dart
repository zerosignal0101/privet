import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/transfer.dart';
import '../models/transfer_history.dart';
import '../models/file_tree.dart';
import '../providers/providers.dart';
import '../services/privet/privet_service.dart';
import 'file_tree_view.dart';

/// Unified transfer tile for all states:
/// negotiating, waitingAcceptance, transferring, completed, failed, cancelled.
class TransferTile extends ConsumerStatefulWidget {
  final ActiveTransfer transfer;

  const TransferTile({super.key, required this.transfer});

  @override
  ConsumerState<TransferTile> createState() => _TransferTileState();
}

class _TransferTileState extends ConsumerState<TransferTile> {
  int _countdown = -1;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    if (widget.transfer.isCompleted || widget.transfer.isFailed) {
      _startCountdown();
    }
  }

  @override
  void didUpdateWidget(TransferTile oldWidget) {
    super.didUpdateWidget(oldWidget);
    final nowCompleted = widget.transfer.isCompleted && !oldWidget.transfer.isCompleted;
    final nowFailed = widget.transfer.isFailed && !oldWidget.transfer.isFailed;
    if (nowCompleted || nowFailed) {
      _startCountdown();
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  void _startCountdown() {
    _timer?.cancel();
    setState(() => _countdown = 5);
    _timer = Timer.periodic(const Duration(seconds: 1), (t) {
      if (_countdown <= 1) {
        t.cancel();
        setState(() => _countdown = -1);
      } else {
        setState(() => _countdown -= 1);
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final t = widget.transfer;
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: _buildContent(context, t),
    );
  }

  Widget _buildContent(BuildContext context, ActiveTransfer t) {
    final theme = Theme.of(context);

    switch (t.state) {
      case TransferState.negotiating:
        return _buildNegotiating(t);
      case TransferState.waitingAcceptance:
        return _buildAwaitingAccept(t);
      case TransferState.transferring:
      case TransferState.paused:
      case TransferState.completing:
        return _buildProgress(t, theme);
      case TransferState.completed:
        return _buildCompleted(t, theme);
      case TransferState.failed:
        return _buildFailed(t, theme);
      case TransferState.cancelled:
        return _buildCancelled(t);
    }
  }

  Widget _buildNegotiating(ActiveTransfer t) {
    return ListTile(
      leading: const SizedBox(
        width: 24, height: 24,
        child: CircularProgressIndicator(strokeWidth: 2),
      ),
      title: Text('${_directionIcon(t.direction)} Connecting...'),
      subtitle: Text(t.peerName ?? 'Unknown'),
      trailing: IconButton(
        icon: const Icon(Icons.stop_circle_outlined, color: Colors.red),
        tooltip: 'Cancel',
        onPressed: () => ref.read(activeTransfersProvider.notifier)
            .cancelTransfer(t.sessionId),
      ),
    );
  }

  Widget _buildAwaitingAccept(ActiveTransfer t) {
    final fileCount = t.files.length;
    final totalSize = t.files.fold<int>(0, (sum, f) => sum + f.size);

    // Check if there's a hierarchy to display
    final hasHierarchy = t.files.any((f) => f.relativePath.contains('/'));
    final treeNodes = hasHierarchy ? buildFileTreeFromPaths(t.files.map((f) => f.relativePath).toList()) : <FileTreeNode>[];

    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        ListTile(
          leading: const Icon(Icons.help_outline, color: Colors.orange),
          title: Text('Accept transfer${fileCount > 0 ? " ($fileCount files)" : ""}?'),
          subtitle: Text(_formatSize(totalSize)),
          trailing: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              IconButton(
                icon: const Icon(Icons.close, color: Colors.red),
                tooltip: 'Reject',
                onPressed: () => ref.read(activeTransfersProvider.notifier)
                    .rejectTransfer(t.sessionId),
              ),
              IconButton(
                icon: const Icon(Icons.check, color: Colors.green),
                tooltip: 'Accept',
                onPressed: () => ref.read(activeTransfersProvider.notifier)
                    .acceptTransfer(t.sessionId),
          ),
          if (t.peerFingerprint != null)
            IconButton(
              icon: Icon(Icons.star, color: Colors.blue.shade600),
              tooltip: 'Always accept from this device',
              onPressed: () {
                ref.read(activeTransfersProvider.notifier)
                    .acceptTransfer(t.sessionId);
                PrivetService.instance
                    .trustAndAcceptPeer(t.peerFingerprint!);
                ref.read(acceptedListProvider.notifier).refresh();
              },
            ),
        ],
      ),
    ),
    if (hasHierarchy && treeNodes.isNotEmpty)
      Padding(
        padding: const EdgeInsets.only(left: 16, right: 16, bottom: 8),
        child: FileTreeView(
          nodes: treeNodes,
          formatSize: _formatSize,
        ),
      ),
  ],
);
  }

  Widget _buildProgress(ActiveTransfer t, ThemeData theme) {
    final p = t.progress;
    final percent = p.percent.clamp(0.0, 100.0);
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Row(
            children: [
              Text(_directionIcon(t.direction),
                  style: const TextStyle(fontSize: 16)),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  t.peerName ?? 'Transfer',
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(fontWeight: FontWeight.w500),
                ),
              ),
              Text(
                '${percent.toStringAsFixed(1)}%',
                style: theme.textTheme.bodyMedium?.copyWith(
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(width: 4),
              IconButton(
                icon: const Icon(Icons.stop_circle_outlined, size: 20,
                    color: Colors.red),
                tooltip: 'Cancel transfer',
                onPressed: () => ref.read(activeTransfersProvider.notifier)
                    .cancelTransfer(t.sessionId),
                visualDensity: VisualDensity.compact,
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(),
              ),
            ],
          ),
          const SizedBox(height: 8),
          LinearProgressIndicator(
            value: percent / 100,
            backgroundColor: Colors.grey.shade200,
          ),
          const SizedBox(height: 6),
          Row(
            children: [
              Text(p.speedText,
                  style: const TextStyle(fontSize: 12, color: Colors.grey)),
              const Spacer(),
              Text(
                '${_formatBytes(p.bytesTransferred)} / ${p.sizeText}',
                style: const TextStyle(fontSize: 12, color: Colors.grey),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildCompleted(ActiveTransfer t, ThemeData theme) {
    return ListTile(
      leading: const Icon(Icons.check_circle, color: Colors.green),
      title: const Text('Transfer complete'),
      subtitle: Text(t.peerName ?? ''),
      trailing: _countdown > 0
          ? Text('$_countdown', style: TextStyle(color: Colors.grey.shade500))
          : null,
    );
  }

  Widget _buildFailed(ActiveTransfer t, ThemeData theme) {
    return ListTile(
      leading: const Icon(Icons.error, color: Colors.red),
      title: const Text('Transfer failed'),
      subtitle: Text(t.peerName ?? ''),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (_countdown > 0)
            Padding(
              padding: const EdgeInsets.only(right: 8),
              child: Text('$_countdown',
                  style: TextStyle(color: Colors.grey.shade500)),
            ),
          if (t.direction == TransferDirection.sending)
            TextButton(
              onPressed: () {
                // Resend — will be handled by navigation
              },
              child: const Text('Resend'),
            ),
        ],
      ),
    );
  }

  Widget _buildCancelled(ActiveTransfer t) {
    return ListTile(
      leading: const Icon(Icons.cancel, color: Colors.grey),
      title: const Text('Transfer cancelled'),
      subtitle: Text(t.peerName ?? ''),
    );
  }

  String _directionIcon(TransferDirection d) =>
      d == TransferDirection.sending ? '↑' : '↓';

  String _formatSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
  }
}
