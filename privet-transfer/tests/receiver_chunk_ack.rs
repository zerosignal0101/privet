
use privet_protocol::{
    control_frame::Payload as CPayload, data_frame::Payload as DPayload, ChunkHeader, ControlFrame,
    ControlMessage, DataFrame, FileEntry, FileSetBatch, FileSetSummary, SegmentManifest,
    TransferOffer,
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
async fn receiver_emits_chunk_ack_after_64_chunks() {
    let save = tempfile::tempdir().unwrap();
    let store = FsPartStore::new(save.path().to_path_buf());
    let (mut ctl_a, ctl_b) = LoopbackControlChannel::pair(256);
    let (mut dat_a, dat_b) = LoopbackDataChannel::pair(256);
    let chunk_size = 1024u64;
    let chunk_count = 70u64;

    let inputs = ReceiverInputs {
        control: Box::new(ctl_b),
        data: vec![Box::new(dat_b)],
        store: Box::new(store),
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig {
            save_dir: save.path().to_path_buf(),
            ..Default::default()
        },
        accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
        registry: None,
    };
    let rh = tokio::spawn(run_receiver(inputs));

    // 1. Offer
    ctl_a
        .send(ControlFrame {
            payload: Some(CPayload::TransferOffer(offer(
                "t1",
                1,
                chunk_count * chunk_size,
            ))),
        })
        .await
        .unwrap();

    // 2. FileSetBatch
    ctl_a
        .send(ControlFrame {
            payload: Some(CPayload::FileSetBatch(FileSetBatch {
                transfer_id: "t1".into(),
                files: vec![FileEntry {
                    file_id: "f0".into(),
                    relative_path: "a.bin".into(),
                    size: chunk_count * chunk_size,
                    mtime_ms: 0,
                    hash_type: "blake3".into(),
                    hash_value: String::new(),
                }],
                dirs: vec![],
                is_last: true,
            })),
        })
        .await
        .unwrap();

    // 3. Accept
    let accept = recv_timeout(&mut ctl_a).await;
    assert!(matches!(accept.payload, Some(CPayload::TransferAccept(_))));

    // 4. SegmentManifest
    let mut chunk_hashes = Vec::new();
    for i in 0..chunk_count {
        let data = vec![(i % 251) as u8; chunk_size as usize];
        chunk_hashes.push(hex::encode(privet_crypto::hash::blake3(&data)));
    }
    let segment_hash_value = privet_transfer::integrity::segment_root(&chunk_hashes);
    ctl_a
        .send(ControlFrame {
            payload: Some(CPayload::SegmentManifest(SegmentManifest {
                file_id: "f0".into(),
                segment_id: 0,
                hash_type: "blake3".into(),
                chunk_hash_values: chunk_hashes.clone(),
                segment_hash_value,
            })),
        })
        .await
        .unwrap();

    // 5. Send 70 chunks
    for i in 0..chunk_count {
        let data = vec![(i % 251) as u8; chunk_size as usize];
        dat_a
            .send(
                DataFrame {
                    payload: Some(DPayload::ChunkHeader(ChunkHeader {
                        file_id: "f0".into(),
                        segment_id: 0,
                        chunk_index: i,
                        offset: i * chunk_size,
                        length: chunk_size,
                    })),
                },
                Some(&data),
            )
            .await
            .unwrap();
    }

    // 6. Complete
    ctl_a
        .send(ControlFrame {
            payload: Some(CPayload::Control(ControlMessage {
                msg: Some(privet_protocol::control_message::Msg::Complete(
                    privet_protocol::TransferComplete {
                        transfer_id: "t1".into(),
                    },
                )),
            })),
        })
        .await
        .unwrap();

    // 7. Await receiver (it processes all chunks + Complete, sends ChunkAck + Verified)
    tokio::time::timeout(Duration::from_secs(5), rh)
        .await
        .expect("receiver must complete")
        .unwrap()
        .unwrap();

    // 8. Drain ctl_a for ChunkAck (receiver sent it during processing)
    let mut has_ack = false;
    while let Ok(Ok(f)) = tokio::time::timeout(Duration::from_millis(100), ctl_a.recv()).await {
        if matches!(f.payload, Some(CPayload::ChunkAck(_))) {
            has_ack = true;
        }
    }

    assert!(
        has_ack,
        "receiver must emit at least one ChunkAck after 64 verified chunks"
    );
}
