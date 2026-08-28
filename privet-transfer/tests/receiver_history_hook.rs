//! Verifies the receiver engine fires the ReceiveHistory hooks exactly once
//! on the happy path: on_offer before the offer event, on_complete after the
//! file lands (before the terminal event).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use privet_protocol::{
    control_frame::Payload as CP, data_frame::Payload as DP, ControlFrame, ControlMessage,
    DataFrame, FileEntry, FileSetBatch, FileSetSummary, InlineFile, TransferOffer,
};
use privet_transfer::channel::{LoopbackControlChannel, LoopbackDataChannel};
use privet_transfer::config::TransferEngineConfig;
use privet_transfer::events::{InMemoryEventSink, NoopEventSink, TransferEvent};
use privet_transfer::part_store::FsPartStore;
use privet_transfer::receiver::{run_receiver, ReceivedFileRecord, ReceiveHistory, ReceiverInputs};
use privet_transfer::{ControlChannel, DataChannel};
use std::time::Duration;

async fn recv_timeout<C: privet_transfer::ControlChannel>(c: &mut C) -> ControlFrame {
    tokio::time::timeout(Duration::from_secs(3), c.recv())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn happy_path_fires_offer_then_complete() {
    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_path_buf();
    let store = FsPartStore::new(save.clone());
    let (mut ctl_a, ctl_b) = LoopbackControlChannel::pair(64);
    let (mut dat_a, dat_b) = LoopbackDataChannel::pair(64);
    let data = vec![7u8; 1024];
    let hash = hex::encode(privet_crypto::hash::blake3(&data));

    let offers = Arc::new(AtomicU32::new(0));
    let completes = Arc::new(AtomicU32::new(0));
    let completed_records = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let o = offers.clone();
    let c = completes.clone();
    let cr = completed_records.clone();
    let history = ReceiveHistory {
        on_offer: Box::new(move |tid: &str, _root: Option<String>, _fc: u64, _tb: u64| {
            assert_eq!(tid, "t1");
            o.fetch_add(1, Ordering::SeqCst);
        }),
        on_fileset: Box::new(move |tid: &str, entries: Vec<FileEntry>| {
            assert_eq!(tid, "t1");
            // The manifest is known before data flows: one file.
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].relative_path, "hook.bin");
        }),
        on_complete: Box::new(move |tid: &str, records: Vec<ReceivedFileRecord>| {
            assert_eq!(tid, "t1");
            c.fetch_add(1, Ordering::SeqCst);
            cr.lock().unwrap().extend(records.into_iter().map(|r| r.relative_path));
        }),
    };

    let inputs = ReceiverInputs {
        control: Box::new(ctl_b),
        data: vec![Box::new(dat_b)],
        store: Box::new(store),
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig {
            save_dir: save.clone(),
            ..Default::default()
        },
        accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
        registry: None,
        history: Some(history),
    };
    let h = tokio::spawn(run_receiver(inputs));

    ctl_a
        .send(ControlFrame {
            payload: Some(CP::TransferOffer(TransferOffer {
                transfer_id: "t1".into(),
                summary: Some(FileSetSummary {
                    root_name: String::new(),
                    file_count: 1,
                    total_bytes: data.len() as u64,
                    dir_count: 0,
                }),
                resume_supported: true,
                proto_version: 1,
            })),
        })
        .await
        .unwrap();
    ctl_a
        .send(ControlFrame {
            payload: Some(CP::FileSetBatch(FileSetBatch {
                transfer_id: "t1".into(),
                files: vec![FileEntry {
                    file_id: "f0".into(),
                    relative_path: "hook.bin".into(),
                    size: data.len() as u64,
                    mtime_ms: 0,
                    hash_type: "blake3".into(),
                    hash_value: hash.clone(),
                }],
                dirs: vec![],
                is_last: true,
            })),
        })
        .await
        .unwrap();
    let _ = recv_timeout(&mut ctl_a).await; // TransferAccept
    dat_a
        .send(
            DataFrame {
                payload: Some(DP::InlineFile(InlineFile {
                    file_id: "f0".into(),
                    relative_path: "hook.bin".into(),
                    mtime_ms: 0,
                    hash_type: "blake3".into(),
                    hash_value: hash,
                    data: data.clone(),
                })),
            },
            None,
        )
        .await
        .unwrap();
    ctl_a
        .send(ControlFrame {
            payload: Some(CP::Control(ControlMessage {
                msg: Some(privet_protocol::control_message::Msg::Complete(
                    privet_protocol::TransferComplete {
                        transfer_id: "t1".into(),
                    },
                )),
            })),
        })
        .await
        .unwrap();
    let v = recv_timeout(&mut ctl_a).await;
    assert!(matches!(
        v.payload,
        Some(CP::Control(ControlMessage {
            msg: Some(privet_protocol::control_message::Msg::Verified(_))
        }))
    ));
    h.await.unwrap().unwrap();
    assert_eq!(std::fs::read(save.join("hook.bin")).unwrap(), data);
    assert_eq!(offers.load(Ordering::SeqCst), 1, "on_offer called once");
    assert_eq!(completes.load(Ordering::SeqCst), 1, "on_complete called once");
    assert_eq!(*completed_records.lock().unwrap(), vec!["hook.bin".to_string()]);
}

/// A cancel queued while data is flowing must interrupt the receiver promptly
/// (the data-handling poll), not wait for the 500ms idle timeout — the
/// regression where the tile's cancel button did nothing during a transfer.
#[tokio::test]
async fn cancel_during_data_flow_interrupts_receiver_promptly() {
    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_path_buf();
    let store = FsPartStore::new(save.clone());
    let (mut ctl_a, ctl_b) = LoopbackControlChannel::pair(64);
    let (mut dat_a, dat_b) = LoopbackDataChannel::pair(64);
    let data = vec![7u8; 1024];
    let hash = hex::encode(privet_crypto::hash::blake3(&data));

    let reg = Arc::new(privet_transfer::control::TransferRegistry::new());
    let inputs = ReceiverInputs {
        control: Box::new(ctl_b),
        data: vec![Box::new(dat_b)],
        store: Box::new(store),
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig {
            save_dir: save.clone(),
            ..Default::default()
        },
        accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
        registry: Some(reg.clone()),
        history: None,
    };
    let h = tokio::spawn(run_receiver(inputs));

    ctl_a
        .send(ControlFrame {
            payload: Some(CP::TransferOffer(TransferOffer {
                transfer_id: "t1".into(),
                summary: Some(FileSetSummary {
                    root_name: String::new(),
                    file_count: 1,
                    total_bytes: data.len() as u64,
                    dir_count: 0,
                }),
                resume_supported: true,
                proto_version: 1,
            })),
        })
        .await
        .unwrap();
    ctl_a
        .send(ControlFrame {
            payload: Some(CP::FileSetBatch(FileSetBatch {
                transfer_id: "t1".into(),
                files: vec![FileEntry {
                    file_id: "f0".into(),
                    relative_path: "hook.bin".into(),
                    size: data.len() as u64,
                    mtime_ms: 0,
                    hash_type: "blake3".into(),
                    hash_value: hash.clone(),
                }],
                dirs: vec![],
                is_last: true,
            })),
        })
        .await
        .unwrap();
    let _ = recv_timeout(&mut ctl_a).await; // TransferAccept
    // The receiver registered "t1" before answering, so queue the cancel before
    // any data flows: it must be picked up by the data-handling poll.
    assert!(reg.send("t1", privet_transfer::control::TransferCommand::Cancel));
    dat_a
        .send(
            DataFrame {
                payload: Some(DP::InlineFile(InlineFile {
                    file_id: "f0".into(),
                    relative_path: "hook.bin".into(),
                    mtime_ms: 0,
                    hash_type: "blake3".into(),
                    hash_value: hash,
                    data: data.clone(),
                })),
            },
            None,
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(200), h)
        .await
        .expect("receiver must honour a queued cancel during data flow")
        .unwrap()
        .expect("receiver returns Ok on cancel");
    // The receiver also told the sender it cancelled.
    let frame = recv_timeout(&mut ctl_a).await;
    assert!(matches!(
        frame.payload,
        Some(CP::Control(ControlMessage {
            msg: Some(privet_protocol::control_message::Msg::Cancel(_))
        }))
    ));
}

/// A sender that cancels mid-transfer writes a Cancel control frame and then
/// ends the data stream (drops it / closes the connection). The receiver used
/// to return on the data-stream error BEFORE reading the Cancel frame, so a
/// sender cancel produced no terminal event — the GUI tile froze at its last
/// progress and History never refreshed to show the 'partial' row. The
/// receiver must instead drain the Cancel frame and terminate as Cancelled,
/// leaving the history row 'partial' (on_complete never called).
#[tokio::test]
async fn sender_cancel_mid_data_emits_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_path_buf();
    let store = FsPartStore::new(save.clone());
    let (mut ctl_a, ctl_b) = LoopbackControlChannel::pair(64);
    let (dat_a, dat_b) = LoopbackDataChannel::pair(64);
    let data = vec![7u8; 1024];
    let hash = hex::encode(privet_crypto::hash::blake3(&data));

    let (event_sink, mut events) = InMemoryEventSink::new();
    let history = ReceiveHistory {
        on_offer: Box::new(|_, _, _, _| {}),
        on_fileset: Box::new(|_, _| {}),
        on_complete: Box::new(|_, _| panic!("a cancelled receive must not complete history")),
    };

    let inputs = ReceiverInputs {
        control: Box::new(ctl_b),
        data: vec![Box::new(dat_b)],
        store: Box::new(store),
        events: Box::new(event_sink),
        config: TransferEngineConfig {
            save_dir: save.clone(),
            ..Default::default()
        },
        accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
        registry: None,
        history: Some(history),
    };
    let h = tokio::spawn(run_receiver(inputs));

    ctl_a
        .send(ControlFrame {
            payload: Some(CP::TransferOffer(TransferOffer {
                transfer_id: "t1".into(),
                summary: Some(FileSetSummary {
                    root_name: String::new(),
                    file_count: 1,
                    total_bytes: data.len() as u64,
                    dir_count: 0,
                }),
                resume_supported: true,
                proto_version: 1,
            })),
        })
        .await
        .unwrap();
    ctl_a
        .send(ControlFrame {
            payload: Some(CP::FileSetBatch(FileSetBatch {
                transfer_id: "t1".into(),
                files: vec![FileEntry {
                    file_id: "f0".into(),
                    relative_path: "hook.bin".into(),
                    size: data.len() as u64,
                    mtime_ms: 0,
                    hash_type: "blake3".into(),
                    hash_value: hash,
                }],
                dirs: vec![],
                is_last: true,
            })),
        })
        .await
        .unwrap();
    let _ = recv_timeout(&mut ctl_a).await; // TransferAccept

    // The sender cancels: end the data stream first so the receiver's data
    // loop hits the EOF/error before any control poll, then deliver the Cancel
    // frame the sender's cancel path writes. The file is still incomplete, so
    // the transfer MUST terminate as Cancelled — not hang, not silently die.
    drop(dat_a);
    ctl_a
        .send(ControlFrame {
            payload: Some(CP::Control(ControlMessage {
                msg: Some(privet_protocol::control_message::Msg::Cancel(
                    privet_protocol::Cancel {
                        transfer_id: "t1".into(),
                        reason: "user".into(),
                    },
                )),
            })),
        })
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(3), h)
        .await
        .expect("receiver must terminate promptly when the sender cancels")
        .expect("receiver task panicked")
        .expect("a peer cancel must return cleanly, not as a transfer error");

    let mut saw_cancelled = false;
    while let Ok(ev) = events.try_recv() {
        if let TransferEvent::Cancelled { transfer_id } = ev {
            assert_eq!(transfer_id, "t1");
            saw_cancelled = true;
        }
    }
    assert!(saw_cancelled, "receiver must emit a Cancelled event on a sender cancel");
}

/// The data stream ending with NO Cancel frame means the peer vanished (hard
/// transport loss). The receive must still terminate with a Cancelled event —
/// a partial receive used to end silently (only the discarded
/// Verified/StateChanged events fired), so the tile froze and History never
/// refreshed. The history row stays 'partial' (on_complete never called).
#[tokio::test]
async fn data_loss_without_cancel_still_terminates_receiver() {
    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_path_buf();
    let store = FsPartStore::new(save.clone());
    let (mut ctl_a, ctl_b) = LoopbackControlChannel::pair(64);
    let (dat_a, dat_b) = LoopbackDataChannel::pair(64);
    let data = vec![7u8; 1024];
    let hash = hex::encode(privet_crypto::hash::blake3(&data));

    let (event_sink, mut events) = InMemoryEventSink::new();
    let history = ReceiveHistory {
        on_offer: Box::new(|_, _, _, _| {}),
        on_fileset: Box::new(|_, _| {}),
        on_complete: Box::new(|_, _| panic!("an interrupted receive must not complete history")),
    };

    let inputs = ReceiverInputs {
        control: Box::new(ctl_b),
        data: vec![Box::new(dat_b)],
        store: Box::new(store),
        events: Box::new(event_sink),
        config: TransferEngineConfig {
            save_dir: save.clone(),
            ..Default::default()
        },
        accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
        registry: None,
        history: Some(history),
    };
    let h = tokio::spawn(run_receiver(inputs));

    ctl_a
        .send(ControlFrame {
            payload: Some(CP::TransferOffer(TransferOffer {
                transfer_id: "t1".into(),
                summary: Some(FileSetSummary {
                    root_name: String::new(),
                    file_count: 1,
                    total_bytes: data.len() as u64,
                    dir_count: 0,
                }),
                resume_supported: true,
                proto_version: 1,
            })),
        })
        .await
        .unwrap();
    ctl_a
        .send(ControlFrame {
            payload: Some(CP::FileSetBatch(FileSetBatch {
                transfer_id: "t1".into(),
                files: vec![FileEntry {
                    file_id: "f0".into(),
                    relative_path: "hook.bin".into(),
                    size: data.len() as u64,
                    mtime_ms: 0,
                    hash_type: "blake3".into(),
                    hash_value: hash,
                }],
                dirs: vec![],
                is_last: true,
            })),
        })
        .await
        .unwrap();
    let _ = recv_timeout(&mut ctl_a).await; // TransferAccept

    // The peer vanishes: both streams end without any Cancel frame.
    drop(dat_a);
    drop(ctl_a);

    let _result = tokio::time::timeout(Duration::from_secs(3), h)
        .await
        .expect("receiver must terminate promptly on transport loss")
        .expect("receiver task panicked")
        .expect("a lost receive must return cleanly, not as a transfer error");

    let mut saw_cancelled = false;
    while let Ok(ev) = events.try_recv() {
        if let TransferEvent::Cancelled { transfer_id } = ev {
            assert_eq!(transfer_id, "t1");
            saw_cancelled = true;
        }
    }
    assert!(saw_cancelled, "receiver must emit a Cancelled event when the peer vanishes");
}
