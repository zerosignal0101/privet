//! 死锁回归测试：慢链路上 INFLIGHT_TOTAL_CAP(32) < 旧 CHUNK_ACK_INTERVAL(64) 时，
//! 发送窗口填满后接收方 500ms 空闲 flush 不触发（数据持续到达）-> ack 永不发 -> 重传
//! 爬升 -> ChunkCorrupt。现通过 (a) CHUNK_ACK_INTERVAL 降到 16（< 32，接收时主动 ack）+
//! (b) 周期 flush + 控制轮询（不依赖空闲）修复。节流 300ms/块保证 500ms 空闲永不触发。
//! 用 32 块（= 发送窗口，无 extra 新块避免 RTO 洪泛阻塞数据通道）验证原死锁不复发。
//! 旧版（64）下此测试会超时 / ChunkCorrupt。
//!
//! 注意：当数据通道对 >= 33 块节流时，RTO 重传洪泛（t≈2s 时全体重传）会堵塞数据通道，
//! 使新块无法被接收方及时处理、触发 ChunkCorrupt（需额外一层 RTO 节流修复，不在本测试范围内）。

use privet_transfer::channel::{LoopbackControlChannel, LoopbackDataChannel, ThrottledDataChannel};
use privet_transfer::config::TransferEngineConfig;
use privet_transfer::events::NoopEventSink;
use privet_transfer::part_store::FsPartStore;
use privet_transfer::receiver::{run_receiver, ReceiverInputs};
use privet_transfer::sender::{run_sender, MappedChunkReader, SenderInputs};
use std::time::Duration;
use tempfile::tempdir;

/// 初始化 tracing（测试默认无 subscriber，调 tracing::debug! 等静默丢弃）。
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,privet_transfer=debug".into()),
        )
        .with_test_writer()
        .try_init();
}

/// 32 块（= INFLIGHT_TOTAL_CAP，恰好一个窗口），每块 1 MiB。
/// 节流 200ms/recv → 500ms 空闲永不触发 → 靠 ACK_INTERVAL(16) + 周期 flush + 控制轮询推进。
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

    // 包装接收侧数据通道：每 200ms recv → 500ms 空闲 flush 永不触发（200 < 500）
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
        data: vec![Box::new(throttled)], // 节流数据通道
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

/// 大文件慢链路回归：64 块（> INFLIGHT_TOTAL_CAP 32，跨窗口）节流 200ms/recv。
/// 旧实现：窗口填满后首个 ack 到达前（≈3.2s > RTO 2s），`rto_expired` 每周期返回
/// 全部 32 个 inflight 块 -> 全体重传 -> 重传洪泛堵塞数据通道 ->  stall/ChunkCorrupt。
/// 修复：重传仅在“落后 ack 前沿”（同段更高 index 块已 ack）或“从未收到 ack”
/// 时触发；可靠传输（QUIC/TCP in-order）下永不误触。本测试验证 64 块在节流下完成。
#[tokio::test]
async fn throttled_deadlock_64chunks_completes() {
    init_tracing();
    let dir = tempdir().unwrap();
    let root = dir.path();
    // 64 MiB = 64 chunks × 1 MiB each（跨 2 个发送窗口）
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
