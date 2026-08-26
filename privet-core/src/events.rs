
use privet_transfer::PausedReason;

#[derive(Debug, Clone)]
pub enum EngineEvent {
    DeviceDiscovered {
        device_fingerprint: String,
        device_name: String,
    },
    DeviceLost {
        device_fingerprint: String,
    },
    PairingRequested {
        device_fingerprint: String,
    },
    PairingResult {
        device_fingerprint: String,
        success: bool,
        error: Option<String>,
    },
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
    IncomingConnection {
        device_fingerprint: String,
    },
}

pub type EventSubscriber = tokio::sync::broadcast::Receiver<EngineEvent>;
