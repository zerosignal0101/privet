//! retransmit 已落地：丢第一块 -> RTO 重发 -> 传送成功。

use privet_transfer::channel::{LoopbackControlChannel, LoopbackDataChannel, LossyDataChannel};
use privet_transfer::config::TransferEngineConfig;
use privet_transfer::events::NoopEventSink;
use privet_transfer::part_store::FsPartStore;
use privet_transfer::receiver::{run_receiver, ReceiverInputs};
use privet_transfer::sender::{run_sender, MappedChunkReader, SenderInputs};
use std::time::Duration;
use tempfile::tempdir;

#[tokio::test]
async fn dropped_chunk_retransmitted_and_completes() {
    let dir = tempdir().unwrap();
    let data: Vec<u8> = (0..1_000_000u64).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.path().join("f.bin"), &data).unwrap();
    let save = tempdir().unwrap();
    let prepared =
        privet_transfer::prepare::prepare_dir(dir.path(), None, 0, 1024 * 1024, 1024).unwrap();
    let reader = MappedChunkReader::from_prepared(&prepared);
    let (ctl_a, ctl_b) = LoopbackControlChannel::pair(64);
    let (dat_a, dat_b_inner) = LoopbackDataChannel::pair(64);
    // 丢第一块 -> sender RTO 重传后成功
    let dat_b = LossyDataChannel::drop_first(Box::new(dat_b_inner), 1);
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
        std::fs::read(save.path().join("f.bin")).unwrap(),
        data,
        "retransmit must complete the file"
    );
}
