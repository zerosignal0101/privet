
use privet_transfer::channel::{LoopbackControlChannel, LoopbackDataChannel};
use privet_transfer::config::TransferEngineConfig;
use privet_transfer::events::NoopEventSink;
use privet_transfer::part_store::FsPartStore;
use privet_transfer::receiver::{run_receiver, ReceiverInputs};
use privet_transfer::sender::{run_sender, MappedChunkReader, SenderInputs};
use std::time::Duration;
use tempfile::tempdir;

#[tokio::test]
async fn pool_with_multiple_channels_transfers_successfully() {
    let dir = tempdir().unwrap();
    let data: Vec<u8> = (0..1_500_000u64).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.path().join("f.bin"), &data).unwrap();
    let save = tempdir().unwrap();
    let prepared =
        privet_transfer::prepare::prepare_dir(dir.path(), None, 0, 1024 * 1024, 1024).unwrap();
    let reader = MappedChunkReader::from_prepared(&prepared);
    let (ctl_a, ctl_b) = LoopbackControlChannel::pair(64);
    let (dat_a1, dat_b1) = LoopbackDataChannel::pair(64);
    let (dat_a2, dat_b2) = LoopbackDataChannel::pair(64);
    let s = SenderInputs {
        control: Box::new(ctl_a),
        data: vec![Box::new(dat_a1), Box::new(dat_a2)],
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig::default(),
        prepared,
        reader: Box::new(reader),
        transfer_id: "t1".into(),
        cmd_rx: None,
    };
    let r = ReceiverInputs {
        control: Box::new(ctl_b),
        data: vec![Box::new(dat_b1), Box::new(dat_b2)],
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
        "pool with multiple channels must transfer correctly"
    );
}
