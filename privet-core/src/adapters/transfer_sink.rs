//! TransferEvent -> EngineEvent 桥接（无数据/哈希内容）+ 传送历史写。

use async_trait::async_trait;
use privet_storage::history::{self, FileRow, TransferDirection, TransferStatus};
use privet_transfer::events::{TransferEvent, TransferEventSink};
use tokio::sync::broadcast;

use crate::EngineEvent;

pub struct CoreTransferEventSink {
    tx: broadcast::Sender<EngineEvent>,
}

impl CoreTransferEventSink {
    pub fn new(tx: broadcast::Sender<EngineEvent>) -> Self {
        Self { tx }
    }
}

#[async_trait]
impl TransferEventSink for CoreTransferEventSink {
    async fn emit(&self, event: TransferEvent) {
        let e = match event {
            TransferEvent::Preparing { transfer_id } => {
                EngineEvent::TransferPreparing { transfer_id }
            }
            TransferEvent::PreparingProgress {
                transfer_id,
                scanned_bytes,
                total_bytes,
            } => EngineEvent::TransferPreparingProgress {
                transfer_id,
                scanned_bytes,
                total_bytes,
            },
            TransferEvent::Offered {
                transfer_id,
                file_count,
                total_bytes,
            } => {
                tracing::info!(
                    transfer_id = %transfer_id,
                    file_count,
                    total_bytes,
                    "transfer_offered"
                );
                EngineEvent::TransferOffered {
                    transfer_id,
                    file_count,
                    total_bytes,
                }
            }
            TransferEvent::Progress {
                transfer_id,
                verified_bytes,
                total_bytes,
            } => EngineEvent::TransferProgress {
                transfer_id,
                verified_bytes,
                total_bytes,
            },
            TransferEvent::Completed { transfer_id } => {
                tracing::info!(transfer_id = %transfer_id, "transfer completed");
                EngineEvent::TransferCompleted { transfer_id }
            }
            TransferEvent::Cancelled { transfer_id } => {
                tracing::info!(transfer_id = %transfer_id, "transfer cancelled");
                EngineEvent::TransferCancelled { transfer_id }
            }
            TransferEvent::Paused {
                transfer_id,
                reason,
            } => EngineEvent::TransferPaused {
                transfer_id,
                reason,
            },
            TransferEvent::Resumed { transfer_id } => EngineEvent::TransferResumed { transfer_id },
            TransferEvent::Failed {
                transfer_id,
                error_code,
                retryable,
                part_kept,
            } => {
                tracing::info!(
                    transfer_id = %transfer_id,
                    error_code = %error_code,
                    retryable,
                    "transfer failed"
                );
                EngineEvent::TransferFailed {
                    transfer_id,
                    error_code,
                    retryable,
                    part_kept,
                }
            }
            _ => return, // Accepted/SendingDone/Verified/StateChanged: discarded
        };
        match self.tx.send(e) {
            Ok(n) => tracing::debug!(subscribers = n, "engine event published"),
            Err(_) => tracing::warn!("engine event publish: no subscribers (dropped)"),
        }
    }
}

// ===== 传送历史写 =====

#[allow(clippy::too_many_arguments)]
pub fn record_history_start(
    conn: &rusqlite::Connection,
    transfer_id: &str,
    direction: TransferDirection,
    peer_device_fingerprint: Option<&str>,
    peer_name: Option<&str>,
    root_name: &str,
    file_count: u64,
    total_bytes: u64,
    send_intent: &str,
) -> crate::Result<()> {
    let t = history::NewTransfer {
        transfer_id,
        direction,
        peer_device_fingerprint,
        peer_name,
        root_name: if root_name.is_empty() {
            None
        } else {
            Some(root_name)
        },
        file_count,
        total_bytes,
        status: TransferStatus::Partial,
        started_ts: now_secs(),
        save_dir: None,
        send_intent
    };
    Ok(history::insert_history(conn, &t)?)
}

pub fn record_history_complete(
    conn: &rusqlite::Connection,
    transfer_id: &str,
    files: &[FileRow],
) -> crate::Result<()> {
    Ok(history::complete_history(
        conn,
        transfer_id,
        files,
        now_secs(),
    )?)
}

pub fn record_history_partial(conn: &rusqlite::Connection, transfer_id: &str) -> crate::Result<()> {
    Ok(history::mark_partial(conn, transfer_id)?)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use privet_transfer::events::TransferEvent;
    use privet_transfer::PausedReason;
    use std::sync::{Arc, Mutex};
    use tokio::sync::broadcast;

    #[derive(Clone)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for CaptureWriter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn offered_emit_logs_transfer_offered() {
        let cap = CaptureWriter(Arc::new(Mutex::new(Vec::new())));
        let sub = tracing_subscriber::fmt()
            .with_writer(cap.clone())
            .with_max_level(tracing::Level::INFO)
            .with_target(false)
            .finish();
        let (tx, _rx) = broadcast::channel::<crate::EngineEvent>(16);
        let sink = CoreTransferEventSink::new(tx);
        tracing::subscriber::with_default(sub, || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(sink.emit(TransferEvent::Offered {
                transfer_id: "t-offer".into(),
                file_count: 2,
                total_bytes: 1000,
            }));
        });
        let s = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        assert!(
            s.contains("transfer_offered"),
            "expected log marker, got: {s}"
        );
        assert!(s.contains("t-offer"), "expected transfer_id in log: {s}");
    }

    #[tokio::test]
    async fn progress_bridges() {
        let (tx, mut rx) = broadcast::channel::<crate::EngineEvent>(16);
        let sink = CoreTransferEventSink::new(tx);
        sink.emit(TransferEvent::Progress {
            transfer_id: "t".into(),
            verified_bytes: 10,
            total_bytes: 100,
        })
        .await;
        let got = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            got,
            crate::EngineEvent::TransferProgress { transfer_id, verified_bytes: 10, total_bytes: 100 } if transfer_id == "t"
        ));
    }

    #[tokio::test]
    async fn paused_bridges_with_reason() {
        let (tx, mut rx) = broadcast::channel::<crate::EngineEvent>(16);
        let sink = CoreTransferEventSink::new(tx);
        sink.emit(TransferEvent::Paused {
            transfer_id: "t".into(),
            reason: PausedReason::DiskFull,
        })
        .await;
        let got = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            got,
            crate::EngineEvent::TransferPaused {
                reason: PausedReason::DiskFull,
                ..
            }
        ));
    }

    #[test]
    fn history_start_then_complete() {
        let conn = privet_storage::migration::open_and_migrate(":memory:").unwrap();
        // 须先建 trust entry（histroy 的 FK 引用）
        conn.execute(
            "INSERT INTO trust_store(device_fingerprint, peer_spki, peer_device_name, trust_state, first_paired_ts, last_seen_ts)
             VALUES('dev1', X'01', 'peer', 'Trusted', 100, 100)",
            [],
        )
        .unwrap();
        super::record_history_start(
            &conn,
            "t1",
            TransferDirection::Receive,
            Some("dev1"),
            Some("peer"),
            "root",
            3,
            1000,
            "{}".into()
        )
        .unwrap();
        super::record_history_complete(&conn, "t1", &[]).unwrap();
    }
}
