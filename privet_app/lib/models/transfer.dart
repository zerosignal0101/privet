class SessionId {
  final String uuid;
  const SessionId(this.uuid);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is SessionId && runtimeType == other.runtimeType && uuid == other.uuid;

  @override
  int get hashCode => uuid.hashCode;

  @override
  String toString() => uuid;
}

class TransferProgress {
  final int totalBytes;
  final int bytesTransferred;
  final double currentSpeedBps;
  final double percent;

  const TransferProgress({
    required this.totalBytes,
    required this.bytesTransferred,
    required this.currentSpeedBps,
    required this.percent,
  });

  String get speedText {
    if (currentSpeedBps <= 0) return '--';
    if (currentSpeedBps < 1024) return '${currentSpeedBps.toStringAsFixed(0)} B/s';
    if (currentSpeedBps < 1024 * 1024) {
      return '${(currentSpeedBps / 1024).toStringAsFixed(1)} KB/s';
    }
    return '${(currentSpeedBps / (1024 * 1024)).toStringAsFixed(1)} MB/s';
  }

  String get sizeText {
    if (totalBytes < 1024) return '$totalBytes B';
    if (totalBytes < 1024 * 1024) return '${(totalBytes / 1024).toStringAsFixed(1)} KB';
    if (totalBytes < 1024 * 1024 * 1024) {
      return '${(totalBytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(totalBytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
  }
}

enum TransferState {
  negotiating,
  waitingAcceptance,
  transferring,
  paused,
  completing,
  completed,
  failed,
  cancelled,
}

class FileEntry {
  final String relativePath;
  final int size;
  final bool isDir;

  const FileEntry({
    required this.relativePath,
    required this.size,
    required this.isDir,
  });

  factory FileEntry.fromJson(Map<String, dynamic> json) => FileEntry(
        relativePath: json['relative_path'] as String? ?? '',
        size: json['size'] as int? ?? 0,
        isDir: json['is_dir'] as bool? ?? false,
      );
}
