/// Direction of a transfer (from the perspective of this device).
enum TransferDirection {
  sending(0),
  receiving(1);

  final int value;
  const TransferDirection(this.value);

  static TransferDirection fromValue(int value) {
    switch (value) {
      case 0: return TransferDirection.sending;
      case 1: return TransferDirection.receiving;
      default: return TransferDirection.sending;
    }
  }
}

/// Terminal state of a completed transfer record.
enum TransferRecordState {
  completed,
  failed,
  cancelled,
  rejected;

  static TransferRecordState fromString(String s) {
    switch (s) {
      case 'Completed': return TransferRecordState.completed;
      case 'Failed': return TransferRecordState.failed;
      case 'Cancelled': return TransferRecordState.cancelled;
      case 'Rejected': return TransferRecordState.rejected;
      default: return TransferRecordState.failed;
    }
  }
}

/// A file entry in a transfer history record.
class TransferFileRecord {
  final String path;           // Absolute path (for opening files)
  final String? relativePath;  // Relative path from protocol (for tree display)
  final String? identifier; // Android content:// URI
  final int size;
  final bool isDir;

  const TransferFileRecord({
    required this.path,
    this.relativePath,
    this.identifier,
    this.size = 0,
    this.isDir = false,
  });

  factory TransferFileRecord.fromJson(Map<String, dynamic> json) =>
      TransferFileRecord(
        path: json['path'] as String? ?? '',
        relativePath: json['relative_path'] as String?,
        identifier: json['identifier'] as String?,
        size: json['size'] as int? ?? 0,
        isDir: json['is_dir'] as bool? ?? false,
      );
}

/// A completed (or failed) transfer from history.
class TransferHistoryRecord {
  final String sessionId;
  final TransferDirection direction;
  final String peerFingerprint;
  final String peerName;
  final String? peerAddress;
  final List<TransferFileRecord> files;
  final int totalBytes;
  final int bytesTransferred;
  final DateTime? startedAt;
  final DateTime? completedAt;
  final TransferRecordState state;
  final String? error;

  const TransferHistoryRecord({
    required this.sessionId,
    required this.direction,
    this.peerFingerprint = '',
    this.peerName = '',
    this.peerAddress,
    this.files = const [],
    this.totalBytes = 0,
    this.bytesTransferred = 0,
    this.startedAt,
    this.completedAt,
    required this.state,
    this.error,
  });

  factory TransferHistoryRecord.fromJson(Map<String, dynamic> json) {
    final rawFiles = json['files'] as List<dynamic>? ?? [];
    final rawDirection = json['direction'] as String? ?? 'Sending';

    return TransferHistoryRecord(
      sessionId: json['session_id'] as String? ?? '',
      direction: rawDirection == 'Receiving'
          ? TransferDirection.receiving
          : TransferDirection.sending,
      peerFingerprint: json['peer_fingerprint'] as String? ?? '',
      peerName: json['peer_name'] as String? ?? '',
      peerAddress: json['peer_address'] as String?,
      files: rawFiles
          .map((f) => TransferFileRecord.fromJson(f as Map<String, dynamic>))
          .toList(),
      totalBytes: json['total_bytes'] as int? ?? 0,
      bytesTransferred: json['bytes_transferred'] as int? ?? 0,
      startedAt: json['started_at'] != null
          ? DateTime.fromMillisecondsSinceEpoch(
              (json['started_at'] as int) * 1000, isUtc: true)
          : null,
      completedAt: json['completed_at'] != null
          ? DateTime.fromMillisecondsSinceEpoch(
              (json['completed_at'] as int) * 1000, isUtc: true)
          : null,
      state: TransferRecordState.fromString(json['state'] as String? ?? 'Failed'),
      error: json['error'] as String?,
    );
  }

  String get fileCountText {
    if (files.isEmpty) return '0 files';
    final dirs = files.where((f) => f.isDir).length;
    final regular = files.length - dirs;
    final parts = <String>[];
    if (regular > 0) parts.add('$regular file${regular > 1 ? 's' : ''}');
    if (dirs > 0) parts.add('$dirs folder${dirs > 1 ? 's' : ''}');
    return parts.isEmpty ? '0 files' : parts.join(', ');
  }

  String get sizeText {
    final bytes = totalBytes;
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
  }
}
