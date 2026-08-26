
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::state::TransferState;

#[derive(Debug, Clone)]
pub enum TransferEvent {
    Preparing {
        transfer_id: String,
    },
    PreparingProgress {
        transfer_id: String,
        scanned_bytes: u64,
        total_bytes: u64,
    },
    Offered {
        transfer_id: String,
        file_count: u64,
        total_bytes: u64,
    },
    Accepted {
        transfer_id: String,
        accept: bool,
    },
    Progress {
        transfer_id: String,
        verified_bytes: u64,
        total_bytes: u64,
    },
    SendingDone {
        transfer_id: String,
    },
    Verified {
        transfer_id: String,
        ok: bool,
    },
    Completed {
        transfer_id: String,
    },
    Cancelled {
        transfer_id: String,
    },
    Resumed {
        transfer_id: String,
    },
    Paused {
        transfer_id: String,
        reason: crate::state::PausedReason,
    },
    Failed {
        transfer_id: String,
        error_code: String,
        retryable: bool,
        part_kept: bool,
    },
    StateChanged {
        transfer_id: String,
        state: TransferState,
    },
}

#[async_trait]
pub trait TransferEventSink: Send + Sync {
    async fn emit(&self, event: TransferEvent);
}

pub struct NoopEventSink;
#[async_trait]
impl TransferEventSink for NoopEventSink {
    async fn emit(&self, _event: TransferEvent) {}
}

pub struct InMemoryEventSink {
    tx: mpsc::UnboundedSender<TransferEvent>,
}

impl InMemoryEventSink {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<TransferEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }
}

impl Default for InMemoryEventSink {
    fn default() -> Self {
        let (s, _) = Self::new();
        s
    }
}

#[async_trait]
impl TransferEventSink for InMemoryEventSink {
    async fn emit(&self, event: TransferEvent) {
        let _ = self.tx.send(event);
    }
}
