//! fail-closed: incomplete transfers + file-level BLAKE3 verification.
//! - Tests completion gate (manifests_segment_count, all_set, verify_segment_root).
//! - Tests file-level BLAKE3 before .part rename (R12).

use privet_protocol::control_frame::Payload as CPayload;
use privet_protocol::control_message::Msg;
use privet_protocol::data_frame::Payload as DPayload;
use privet_protocol::{
    ChunkHeader, ControlFrame, ControlMessage, DataFrame, DirEntry, FileEntry, FileSetBatch,
    FileSetSummary, SegmentManifest, TransferComplete, TransferOffer,
};
use privet_transfer::channel::{
    ControlChannel, DataChannel, LoopbackControlChannel, LoopbackDataChannel,
};
use privet_transfer::config::TransferEngineConfig;
use privet_transfer::events::NoopEventSink;
use privet_transfer::integrity::segment_root;
use privet_transfer::part_store::FsPartStore;
use privet_transfer::receiver::{run_receiver, ReceiverInputs};
use std::time::Duration;
use tempfile::tempdir;

fn make_receiver_inputs(
    control: Box<LoopbackControlChannel>,
    data: Box<LoopbackDataChannel>,
    save_dir: &std::path::Path,
) -> ReceiverInputs {
    ReceiverInputs {
        control,
        data: vec![data],
        store: Box::new(FsPartStore::new(save_dir.to_path_buf())),
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig {
            save_dir: save_dir.to_path_buf(),
            ..Default::default()
        },
        accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
        registry: None,
    }
}

#[tokio::test]
async fn incomplete_file_missing_last_chunk_returns_verify_failed() {
    let (mut ctl_send, ctl_recv) = LoopbackControlChannel::pair(64);
    let (mut dat_send, dat_recv) = LoopbackDataChannel::pair(64);
    let save = tempdir().unwrap();

    // Phase 1: TransferOffer
    ctl_send
        .send(ControlFrame {
            payload: Some(CPayload::TransferOffer(TransferOffer {
                transfer_id: "t1".into(),
                summary: Some(FileSetSummary {
                    root_name: String::new(),
                    file_count: 1,
                    total_bytes: 8,
                    dir_count: 1,
                }),
                resume_supported: true,
                proto_version: 1,
            })),
        })
        .await
        .unwrap();

    // Phase 2: FileSetBatch with one 8-byte file
    let correct_blake3 = hex::encode(privet_crypto::hash::blake3(b"ABCDABCD"));
    ctl_send
        .send(ControlFrame {
            payload: Some(CPayload::FileSetBatch(FileSetBatch {
                transfer_id: "t1".into(),
                files: vec![FileEntry {
                    file_id: "f1".into(),
                    size: 8,
                    hash_type: "blake3".into(),
                    hash_value: correct_blake3,
                    relative_path: "f1.bin".into(),
                    mtime_ms: 0,
                }],
                dirs: vec![DirEntry {
                    relative_path: String::new(),
                }],
                is_last: true,
            })),
        })
        .await
        .unwrap();

    // Phase 3: SegmentManifest for segment 0 with 2 chunks
    let chunk_data = b"ABCD";
    let hash_hex = hex::encode(privet_crypto::hash::blake3(chunk_data));
    ctl_send
        .send(ControlFrame {
            payload: Some(CPayload::SegmentManifest(SegmentManifest {
                file_id: "f1".into(),
                segment_id: 0,
                hash_type: "blake3".into(),
                chunk_hash_values: vec![hash_hex.clone(), hash_hex],
                segment_hash_value: "root_placeholder".into(),
            })),
        })
        .await
        .unwrap();

    // Phase 4: send only chunk 0 (missing chunk 1)
    let header = ChunkHeader {
        file_id: "f1".into(),
        segment_id: 0,
        chunk_index: 0,
        offset: 0,
        length: 4,
    };
    dat_send
        .send(
            DataFrame {
                payload: Some(DPayload::ChunkHeader(header)),
            },
            Some(&chunk_data[..]),
        )
        .await
        .unwrap();

    // Phase 5: send Complete
    ctl_send
        .send(ControlFrame {
            payload: Some(CPayload::Control(ControlMessage {
                msg: Some(Msg::Complete(TransferComplete {
                    transfer_id: "t1".into(),
                })),
            })),
        })
        .await
        .unwrap();

    // Run receiver
    let r_inputs = make_receiver_inputs(Box::new(ctl_recv), Box::new(dat_recv), save.path());
    let result = tokio::time::timeout(Duration::from_secs(10), run_receiver(r_inputs)).await;

    match result {
        Ok(Err(e)) => {
            let msg = e.to_string();
            assert!(
                msg.contains("missing") || msg.contains("VerifyFailed") || msg.contains("verify"),
                "expected VerifyFailed for incomplete file, got: {msg}"
            );
        }
        Ok(Ok(())) => panic!("receiver returned Ok for incomplete transfer (fail-open)"),
        Err(_) => panic!("test timed out"),
    }
}

#[tokio::test]
async fn wrong_file_blake3_rejected_at_finalize() {
    // Even with all chunks correct, a file-level BLAKE3 mismatch must fail.
    let (mut ctl_send, ctl_recv) = LoopbackControlChannel::pair(64);
    let (mut dat_send, dat_recv) = LoopbackDataChannel::pair(64);
    let save = tempdir().unwrap();

    // TransferOffer
    ctl_send
        .send(ControlFrame {
            payload: Some(CPayload::TransferOffer(TransferOffer {
                transfer_id: "t2".into(),
                summary: Some(FileSetSummary {
                    root_name: String::new(),
                    file_count: 1,
                    total_bytes: 8,
                    dir_count: 1,
                }),
                resume_supported: true,
                proto_version: 1,
            })),
        })
        .await
        .unwrap();

    // Compute correct hashes
    let chunk_data = b"ABCD";
    let chunk_hash_hex = hex::encode(privet_crypto::hash::blake3(chunk_data));
    // segment_root concatenates chunk hash hex strings and hashes the result
    let seg_root_hex = segment_root(&[chunk_hash_hex.clone(), chunk_hash_hex.clone()]);

    // FileSetBatch with deliberately WRONG blake3 hash
    let wrong_blake3 =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    ctl_send
        .send(ControlFrame {
            payload: Some(CPayload::FileSetBatch(FileSetBatch {
                transfer_id: "t2".into(),
                files: vec![FileEntry {
                    file_id: "f1".into(),
                    size: 8,
                    hash_type: "blake3".into(),
                    hash_value: wrong_blake3,
                    relative_path: "f1.bin".into(),
                    mtime_ms: 0,
                }],
                dirs: vec![DirEntry {
                    relative_path: String::new(),
                }],
                is_last: true,
            })),
        })
        .await
        .unwrap();

    // SegmentManifest with CORRECT segment root hash
    ctl_send
        .send(ControlFrame {
            payload: Some(CPayload::SegmentManifest(SegmentManifest {
                file_id: "f1".into(),
                segment_id: 0,
                hash_type: "blake3".into(),
                chunk_hash_values: vec![chunk_hash_hex.clone(), chunk_hash_hex],
                segment_hash_value: seg_root_hex,
            })),
        })
        .await
        .unwrap();

    // Send BOTH chunks (correct data)
    for i in 0u64..2 {
        let header = ChunkHeader {
            file_id: "f1".into(),
            segment_id: 0,
            chunk_index: i,
            offset: i * 4,
            length: 4,
        };
        dat_send
            .send(
                DataFrame {
                    payload: Some(DPayload::ChunkHeader(header)),
                },
                Some(&chunk_data[..]),
            )
            .await
            .unwrap();
    }

    // Complete
    ctl_send
        .send(ControlFrame {
            payload: Some(CPayload::Control(ControlMessage {
                msg: Some(Msg::Complete(TransferComplete {
                    transfer_id: "t2".into(),
                })),
            })),
        })
        .await
        .unwrap();

    let r_inputs = make_receiver_inputs(Box::new(ctl_recv), Box::new(dat_recv), save.path());
    let result = tokio::time::timeout(Duration::from_secs(10), run_receiver(r_inputs)).await;

    match result {
        Ok(Err(e)) => {
            let msg = e.to_string();
            assert!(
                msg.contains("BLAKE3") || msg.contains("VerifyFailed"),
                "expected VerifyFailed for BLAKE3 mismatch, got: {msg}"
            );
        }
        Ok(Ok(())) => panic!("receiver returned Ok despite wrong file-level BLAKE3 (fail-open)"),
        Err(_) => panic!("test timed out"),
    }
}
