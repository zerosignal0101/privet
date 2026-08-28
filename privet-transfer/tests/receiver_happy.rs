use privet_protocol::{
    control_frame::Payload as CP, data_frame::Payload as DP, ControlFrame, ControlMessage,
    DataFrame, FileEntry, FileSetBatch, FileSetSummary, InlineFile, TransferOffer,
};
use privet_transfer::channel::{LoopbackControlChannel, LoopbackDataChannel};
use privet_transfer::config::TransferEngineConfig;
use privet_transfer::events::NoopEventSink;
use privet_transfer::part_store::FsPartStore;
use privet_transfer::receiver::{run_receiver, ReceiverInputs};
use privet_transfer::{ControlChannel, DataChannel};
use std::time::Duration;

async fn recv_timeout<C: privet_transfer::ControlChannel>(c: &mut C) -> ControlFrame {
    tokio::time::timeout(Duration::from_secs(3), c.recv())
        .await
        .unwrap()
        .unwrap()
}

fn offer(tid: &str, fc: u64, tb: u64) -> TransferOffer {
    TransferOffer {
        transfer_id: tid.into(),
        summary: Some(FileSetSummary {
            root_name: String::new(),
            file_count: fc,
            total_bytes: tb,
            dir_count: 0,
        }),
        resume_supported: true,
        proto_version: 1,
    }
}

#[tokio::test]
async fn receiver_inline_file_lands_directly() {
    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_path_buf();
    let store = FsPartStore::new(save.clone());
    let (mut ctl_a, ctl_b) = LoopbackControlChannel::pair(64);
    let (mut dat_a, dat_b) = LoopbackDataChannel::pair(64);
    let data = vec![42u8; 65536];
    let hash = hex::encode(privet_crypto::hash::blake3(&data));

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
        history: None,
    };
    let h = tokio::spawn(run_receiver(inputs));

    ctl_a
        .send(ControlFrame {
            payload: Some(CP::TransferOffer(offer("t1", 1, data.len() as u64))),
        })
        .await
        .unwrap();
    let batch = FileSetBatch {
        transfer_id: "t1".into(),
        files: vec![FileEntry {
            file_id: "f0".into(),
            relative_path: "inline.bin".into(),
            size: data.len() as u64,
            mtime_ms: 0,
            hash_type: "blake3".into(),
            hash_value: hash.clone(),
        }],
        dirs: vec![],
        is_last: true,
    };
    ctl_a
        .send(ControlFrame {
            payload: Some(CP::FileSetBatch(batch)),
        })
        .await
        .unwrap();
    let accept_frame = recv_timeout(&mut ctl_a).await;
    assert!(matches!(accept_frame.payload, Some(CP::TransferAccept(_))));
    dat_a
        .send(
            DataFrame {
                payload: Some(DP::InlineFile(InlineFile {
                    file_id: "f0".into(),
                    relative_path: "inline.bin".into(),
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
    let verified = recv_timeout(&mut ctl_a).await;
    match verified.payload {
        Some(CP::Control(ControlMessage {
            msg: Some(privet_protocol::control_message::Msg::Verified(v)),
        })) => {
            assert!(v.ok, "verify failed: {}", v.error);
        }
        _ => panic!("expected TransferVerified, got {:?}", verified.payload),
    }
    h.await.unwrap().unwrap();
    assert_eq!(std::fs::read(save.join("inline.bin")).unwrap(), data);
}

#[tokio::test]
async fn receiver_empty_file_inline() {
    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_path_buf();
    let store = FsPartStore::new(save.clone());
    let (mut ctl_a, ctl_b) = LoopbackControlChannel::pair(64);
    let (mut dat_a, dat_b) = LoopbackDataChannel::pair(64);
    let hash = hex::encode(privet_crypto::hash::blake3(b""));

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
        history: None,
    };
    let h = tokio::spawn(run_receiver(inputs));

    ctl_a
        .send(ControlFrame {
            payload: Some(CP::TransferOffer(offer("t1", 1, 0))),
        })
        .await
        .unwrap();
    ctl_a
        .send(ControlFrame {
            payload: Some(CP::FileSetBatch(FileSetBatch {
                transfer_id: "t1".into(),
                files: vec![FileEntry {
                    file_id: "f0".into(),
                    relative_path: "empty.bin".into(),
                    size: 0,
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
    let _ = recv_timeout(&mut ctl_a).await;
    dat_a
        .send(
            DataFrame {
                payload: Some(DP::InlineFile(InlineFile {
                    file_id: "f0".into(),
                    relative_path: "empty.bin".into(),
                    mtime_ms: 0,
                    hash_type: "blake3".into(),
                    hash_value: hash,
                    data: vec![],
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
    assert!(save.join("empty.bin").exists());
    assert_eq!(std::fs::read(save.join("empty.bin")).unwrap(), b"");
}
