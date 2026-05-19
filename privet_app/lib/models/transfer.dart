import 'transfer_history.dart';

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

/// An active (in-progress, awaiting, or just-completed) transfer.
class ActiveTransfer {
  final String sessionId;
  final TransferDirection direction;
  final TransferProgress progress;
  final String? peerName;
  final String? peerFingerprint;
  final List<FileEntry> files;
  final TransferState state;

  const ActiveTransfer({
    required this.sessionId,
    required this.direction,
    required this.progress,
    this.peerName,
    this.peerFingerprint,
    this.files = const [],
    required this.state,
  });

  ActiveTransfer copyWith({
    TransferProgress? progress,
    TransferState? state,
    String? peerName,
    String? peerFingerprint,
  }) =>
      ActiveTransfer(
        sessionId: sessionId,
        direction: direction,
        progress: progress ?? this.progress,
        peerName: peerName ?? this.peerName,
        peerFingerprint: peerFingerprint ?? this.peerFingerprint,
        files: files,
        state: state ?? this.state,
      );

  String get fileCountText {
    if (files.isEmpty) return '';
    final count = files.length;
    return '$count file${count > 1 ? 's' : ''}';
  }

  bool get isCompleted => state == TransferState.completed;
  bool get isFailed => state == TransferState.failed;
  bool get isTransferring => state == TransferState.transferring;
  bool get isAwaitingAccept => state == TransferState.waitingAcceptance;

  String get directionIcon {
    return direction == TransferDirection.sending ? '↑' : '↓';
  }
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
