import 'package:flutter/material.dart';

import '../providers/providers.dart';

/// Show pairing dialog for a given PairRequest.
Future<void> showPairingDialog(
  BuildContext context,
  PairRequest request,
  Future<void> Function(String) onTrust,
  Future<void> Function(String) onTrustAndAccept,
) async {
  await showDialog(
    context: context,
    barrierDismissible: false,
    builder: (ctx) => _PairingDialog(
      request: request,
      onTrust: onTrust,
      onTrustAndAccept: onTrustAndAccept,
    ),
  );
}

class _PairingDialog extends StatefulWidget {
  final PairRequest request;
  final Future<void> Function(String) onTrust;
  final Future<void> Function(String) onTrustAndAccept;

  const _PairingDialog({
    required this.request,
    required this.onTrust,
    required this.onTrustAndAccept,
  });

  @override
  State<_PairingDialog> createState() => _PairingDialogState();
}

class _PairingDialogState extends State<_PairingDialog> {
  bool _loading = false;

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Pairing Request'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text('Device: ${widget.request.peer.name}'),
          const SizedBox(height: 16),
          Text(
            'Verify this code matches on both devices:',
            style: Theme.of(context).textTheme.bodySmall,
          ),
          const SizedBox(height: 8),
          Text(
            widget.request.code,
            style: const TextStyle(
              fontSize: 36,
              fontWeight: FontWeight.bold,
              letterSpacing: 8,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Fingerprint: ${widget.request.peer.displayFingerprint}',
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: _loading ? null : () => Navigator.pop(context),
          child: const Text('Reject'),
        ),
        const SizedBox(width: 8),
        OutlinedButton(
          onPressed: _loading
              ? null
              : () async {
                  setState(() => _loading = true);
                  await widget.onTrust(widget.request.peer.fingerprint);
                  if (mounted) Navigator.pop(context);
                },
          child: _loading
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Trust'),
        ),
        const SizedBox(width: 8),
        FilledButton(
          onPressed: _loading
              ? null
              : () async {
                  setState(() => _loading = true);
                  await widget.onTrustAndAccept(widget.request.peer.fingerprint);
                  if (mounted) Navigator.pop(context);
                },
          child: _loading
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Trust & Accept'),
        ),
      ],
    );
  }
}
