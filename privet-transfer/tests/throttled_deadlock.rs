//! Backpressure regression tests for throttled data channels.

use privet_transfer::channel::{LoopbackControlChannel, LoopbackDataChannel, ThrottledDataChannel};
use privet_transfer::config::TransferEngineConfig;
use privet_transfer::events::NoopEventSink;
use privet_transfer::part_store::FsPartStore;
use privet_transfer::receiver::{run_receiver, ReceiverInputs};
use privet_transfer::sender::{run_sender, MappedChunkReader, SenderInputs};
use std::time::Duration;
use tempfile::tempdir;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,privet_transfer=debug".into()),
        )
        .with_test_writer()
        .try_init();
}

#[tokio::test]
async fn throttled_deadlock_32chunks_completes() {
    init_tracing();
    let dir = tempdir().unwrap();
    let root = dir.path();
    // 32 MiB = 32 chunks × 1 MiB each
    let data: Vec<u8> = (0..32u64 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let file_path = root.join("big.bin");
    std::fs::write(&file_path, &data).unwrap();

    let save = tempdir().unwrap();
    let (ctl_a, ctl_b) = LoopbackControlChannel::pair(128);
    let (dat_a, dat_b) = LoopbackDataChannel::pair(128);

    let throttled = ThrottledDataChannel::new(Box::new(dat_b), Duration::from_millis(200));

    let prepared = privet_transfer::prepare::prepare_dir(root, None, 0, 1024 * 1024, 1024).unwrap();
    let reader = MappedChunkReader::from_prepared(&prepared);

    let s_inputs = SenderInputs {
        control: Box::new(ctl_a),
        data: vec![Box::new(dat_a)],
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig::default(), // CHUNK_ACK_INTERVAL=16
        prepared,
        reader: Box::new(reader),
        transfer_id: "t-dl-regression".into(),
        cmd_rx: None,
    };
    let r_inputs = ReceiverInputs {
        control: Box::new(ctl_b),
        data: vec![Box::new(throttled)],
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
    tokio::time::timeout(Duration::from_secs(60), async {
        sr.await.unwrap().unwrap();
        rr.await.unwrap().unwrap();
    })
    .await
    .expect("throttled deadlock regression: transfer completed within 60s");
    let got = std::fs::read(save.path().join("big.bin")).unwrap();
    assert_eq!(got.len(), data.len());
    assert_eq!(got, data);
}

#[tokio::test]
async fn throttled_deadlock_64chunks_completes() {
    init_tracing();
    let dir = tempdir().unwrap();
    let root = dir.path();
    let data: Vec<u8> = (0..64u64 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let file_path = root.join("bigger.bin");
    std::fs::write(&file_path, &data).unwrap();

    let save = tempdir().unwrap();
    let (ctl_a, ctl_b) = LoopbackControlChannel::pair(128);
    let (dat_a, dat_b) = LoopbackDataChannel::pair(128);
    let throttled = ThrottledDataChannel::new(Box::new(dat_b), Duration::from_millis(200));

    let prepared = privet_transfer::prepare::prepare_dir(root, None, 0, 1024 * 1024, 1024).unwrap();
    let reader = MappedChunkReader::from_prepared(&prepared);

    let s_inputs = SenderInputs {
        control: Box::new(ctl_a),
        data: vec![Box::new(dat_a)],
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig::default(),
        prepared,
        reader: Box::new(reader),
        transfer_id: "t-dl-64".into(),
        cmd_rx: None,
    };
    let r_inputs = ReceiverInputs {
        control: Box::new(ctl_b),
        data: vec![Box::new(throttled)],
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
    tokio::time::timeout(Duration::from_secs(90), async {
        sr.await.unwrap().unwrap();
        rr.await.unwrap().unwrap();
    })
    .await
    .expect("throttled 64-chunk transfer must complete within 90s");
    let got = std::fs::read(save.path().join("bigger.bin")).unwrap();
    assert_eq!(got, data);
}
