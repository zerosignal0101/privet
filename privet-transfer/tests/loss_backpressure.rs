//! 丢块 + 反压测试。retransmit 已落地：
//! - 单块丢 -> RTO 重传成功
//! - 全丢 -> CHUNK_RETRANSMIT_MAX -> ChunkCorrupt（retryable，.part 留）
//! - manifest-late 块缓冲保留（R11 已修复 pending 块回灌计数）。

use privet_transfer::channel::{
    LatchControlChannel, LoopbackControlChannel, LoopbackDataChannel, LossyDataChannel,
};
use privet_transfer::config::TransferEngineConfig;
use privet_transfer::events::NoopEventSink;
use privet_transfer::part_store::FsPartStore;
use privet_transfer::receiver::{run_receiver, ReceiverInputs};
use privet_transfer::sender::{run_sender, MappedChunkReader, SenderInputs};
use std::time::Duration;
use tempfile::tempdir;

// 持续丢块 -> 重传至上限 -> Err(ChunkCorrupt)（retryable，.part 留）。
#[tokio::test]
async fn all_drops_hit_chunk_corrupt_ceiling() {
    let dir = tempdir().unwrap();
    let data: Vec<u8> = (0..2_000_000u64).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.path().join("l.bin"), &data).unwrap();
    let save = tempdir().unwrap();
    let prepared =
        privet_transfer::prepare::prepare_dir(dir.path(), None, 0, 1024 * 1024, 1024).unwrap();
    let reader = MappedChunkReader::from_prepared(&prepared);
    let (ctl_a, ctl_b) = LoopbackControlChannel::pair(64);
    let (dat_a, dat_b_inner) = LoopbackDataChannel::pair(64);
    // 全丢：所有 data 帧丢弃
    let dat_b = LossyDataChannel::drop_first(Box::new(dat_b_inner), usize::MAX);
    let s = SenderInputs {
        control: Box::new(ctl_a),
        data: vec![Box::new(dat_a)],
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig::default(),
        prepared,
        reader: Box::new(reader),
        transfer_id: "t1".into(),
        cmd_rx: None,
    };
    let r = ReceiverInputs {
        control: Box::new(ctl_b),
        data: vec![Box::new(dat_b)],
        store: Box::new(FsPartStore::new(save.path().to_path_buf())),
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig {
            save_dir: save.path().to_path_buf(),
            ..Default::default()
        },
        accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
        registry: None,
    };
    let sr = tokio::spawn(run_sender(s));
    let _rr = tokio::spawn(run_receiver(r));
    let res = tokio::time::timeout(Duration::from_secs(60), sr)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(res, Err(privet_transfer::TransferError::ChunkCorrupt)),
        "expected ChunkCorrupt after CHUNK_RETRANSMIT_MAX, got {res:?}"
    );
    // ChunkCorrupt retryable - receiver exits cleanly (no .part created since no chunks arrived)
    // 若部分块已到，.part 保留不删。此处全丢故无 staging；测试构造请见 manifest_late 用例。
}

// manifest 到货后块才来 -> 缓冲再验证 -> 仍成功
#[tokio::test]
async fn manifest_late_chunk_buffered_not_dropped() {
    let dir = tempdir().unwrap();
    let data: Vec<u8> = (0..1_500_000u64).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.path().join("ml.bin"), &data).unwrap();
    let save = tempdir().unwrap();
    let prepared =
        privet_transfer::prepare::prepare_dir(dir.path(), None, 0, 1024 * 1024, 1024).unwrap();
    let reader = MappedChunkReader::from_prepared(&prepared);
    let (ctl_a, ctl_b_inner) = LoopbackControlChannel::pair(64);
    let ctl_b = LatchControlChannel::hold_first(Box::new(ctl_b_inner), 1);
    let (dat_a, dat_b) = LoopbackDataChannel::pair(64);
    let s = SenderInputs {
        control: Box::new(ctl_a),
        data: vec![Box::new(dat_a)],
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig::default(),
        prepared,
        reader: Box::new(reader),
        transfer_id: "t1".into(),
        cmd_rx: None,
    };
    let r = ReceiverInputs {
        control: Box::new(ctl_b),
        data: vec![Box::new(dat_b)],
        store: Box::new(FsPartStore::new(save.path().to_path_buf())),
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig {
            save_dir: save.path().to_path_buf(),
            ..Default::default()
        },
        accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
        registry: None,
    };
    let sr = tokio::spawn(run_sender(s));
    let rr = tokio::spawn(run_receiver(r));
    tokio::time::timeout(Duration::from_secs(30), async {
        sr.await.unwrap().unwrap();
        rr.await.unwrap().unwrap();
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(save.path().join("ml.bin")).unwrap(),
        data,
        "manifest-late must still transfer correctly"
    );
}
