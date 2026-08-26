use privet_transfer::channel::{LoopbackControlChannel, LoopbackDataChannel};
use privet_transfer::config::TransferEngineConfig;
use privet_transfer::events::NoopEventSink;
use privet_transfer::part_store::FsPartStore;
use privet_transfer::receiver::{run_receiver, ReceiverInputs};
use privet_transfer::sender::{run_sender, MappedChunkReader, SenderInputs};
use std::time::Duration;
use tempfile::tempdir;

#[tokio::test]
async fn sender_receiver_roundtrip_chunked_file() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let data: Vec<u8> = (0..2_621_440u64).map(|i| (i % 251) as u8).collect();
    std::fs::write(root.join("big.bin"), &data).unwrap();

    let save = tempdir().unwrap();
    let (ctl_a, ctl_b) = LoopbackControlChannel::pair(64);
    let (dat_a, dat_b) = LoopbackDataChannel::pair(64);

    let prepared = privet_transfer::prepare::prepare_dir(root, None, 0, 1024 * 1024, 1024).unwrap();
    let reader = MappedChunkReader::from_prepared(&prepared);

    let s_inputs = SenderInputs {
        control: Box::new(ctl_a),
        data: vec![Box::new(dat_a)],
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig::default(),
        prepared,
        reader: Box::new(reader),
        transfer_id: "t1".into(),
        cmd_rx: None,
    };
    let r_inputs = ReceiverInputs {
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

    let sr = tokio::spawn(run_sender(s_inputs));
    let rr = tokio::spawn(run_receiver(r_inputs));
    tokio::time::timeout(Duration::from_secs(30), async {
        sr.await.unwrap().unwrap();
        rr.await.unwrap().unwrap();
    })
    .await
    .unwrap();
    let got = std::fs::read(save.path().join("big.bin")).unwrap();
    assert_eq!(got.len(), data.len());
    assert_eq!(got, data);
}
