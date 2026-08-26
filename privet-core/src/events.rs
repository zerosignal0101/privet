//! EngineEvent：仅 reason/result/progress/状态码 + 公开 id；无码/密钥/签名/哈希。

use privet_transfer::PausedReason;

#[derive(Debug, Clone)]
pub enum EngineEvent {
    // 发现
    DeviceDiscovered {
        device_fingerprint: String,
        device_name: String,
    },
    DeviceLost {
        device_fingerprint: String,
    },
    // 配对
    PairingRequested {
        device_fingerprint: String,
    },
    PairingResult {
        device_fingerprint: String,
        success: bool,
        error: Option<String>,
    },
    // 传送
    TransferPreparing {
        transfer_id: String,
    },
    TransferPreparingProgress {
        transfer_id: String,
        scanned_bytes: u64,
        total_bytes: u64,
    },
    TransferOffered {
        transfer_id: String,
        file_count: u64,
        total_bytes: u64,
    },
    TransferProgress {
        transfer_id: String,
        verified_bytes: u64,
        total_bytes: u64,
    },
    TransferReconnecting {
        transfer_id: String,
        attempt: u32,
        backoff_ms: u64,
    },
    TransferResumed {
        transfer_id: String,
    },
    TransferPaused {
        transfer_id: String,
        reason: PausedReason,
    },
    TransferCompleted {
        transfer_id: String,
    },
    TransferCancelled {
        transfer_id: String,
    },
    TransferFailed {
        transfer_id: String,
        error_code: String,
        retryable: bool,
        part_kept: bool,
    },
    // 入站连接
    IncomingConnection {
        device_fingerprint: String,
    },
}

/// 事件订阅句柄（broadcast 接收端）。
pub type EventSubscriber = tokio::sync::broadcast::Receiver<EngineEvent>;
