import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/transfer.dart';
import '../providers/providers.dart';

class TransferPage extends ConsumerWidget {
  final String sessionId;

  const TransferPage({super.key, required this.sessionId});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final progressMap = ref.watch(transferProgressProvider);
    final progress = progressMap[sessionId];

    return Scaffold(
      appBar: AppBar(title: const Text('Transfer')),
      body: Center(
        child: progress == null
            ? const Text('Waiting for transfer data...')
            : _TransferView(progress: progress),
      ),
    );
  }
}

class _TransferView extends StatelessWidget {
  final TransferProgress progress;

  const _TransferView({required this.progress});

  @override
  Widget build(BuildContext context) {
    final percent = progress.percent.clamp(0.0, 100.0);
    final isComplete = percent >= 100.0;

    return Padding(
      padding: const EdgeInsets.all(32),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          // Circular progress
          SizedBox(
            width: 200,
            height: 200,
            child: Stack(
              fit: StackFit.expand,
              children: [
                CircularProgressIndicator(
                  value: percent / 100,
                  strokeWidth: 12,
                  backgroundColor: Colors.grey.shade200,
                  valueColor: AlwaysStoppedAnimation<Color>(
                    isComplete ? Colors.green : Theme.of(context).primaryColor,
                  ),
                ),
                Center(
                  child: Text(
                    '${percent.toStringAsFixed(1)}%',
                    style: Theme.of(context).textTheme.headlineMedium,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 32),

          // Speed
          Text(
            progress.speedText,
            style: Theme.of(context).textTheme.titleLarge,
          ),
          const SizedBox(height: 8),

          // Size
          Text(
            '${_formatBytes(progress.bytesTransferred)} / ${progress.sizeText}',
            style: Theme.of(context).textTheme.bodyLarge,
          ),
          const SizedBox(height: 32),

          if (isComplete)
            FilledButton.icon(
              onPressed: () => Navigator.pop(context),
              icon: const Icon(Icons.check),
              label: const Text('Done'),
            ),
        ],
      ),
    );
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
