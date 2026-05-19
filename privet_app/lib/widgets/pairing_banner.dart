import 'package:flutter/material.dart';

import '../providers/providers.dart';

/// Extracted from home_page.dart — shows a pairing request from an unknown peer.
class PairingBanner extends StatelessWidget {
  final PairRequest request;
  final VoidCallback onTrust;
  final VoidCallback onTrustAndAccept;
  final VoidCallback onDismiss;

  const PairingBanner({
    super.key,
    required this.request,
    required this.onTrust,
    required this.onTrustAndAccept,
    required this.onDismiss,
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
            Text(
              'Pairing Request from ${request.peer.name}',
              style: const TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 4),
            Text('Verification code: ${request.code}'),
            const SizedBox(height: 8),
            Wrap(
              spacing: 6,
              runSpacing: 6,
              alignment: WrapAlignment.end,
              children: [
                TextButton.icon(
                  onPressed: onDismiss,
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
                  label: const Text('Trust & Accept', style: TextStyle(fontSize: 12)),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
