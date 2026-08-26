//! prepare 过程中的流式 PreparingProgress。

use privet_transfer::events::{InMemoryEventSink, TransferEvent};
use tempfile::tempdir;

#[tokio::test]
async fn preparing_progress_streams_during_scan() {
    let dir = tempdir().unwrap();
    // 5 个不同大小的文件
    for (name, size) in &[
        ("a.bin", 1000),
        ("b.bin", 2000),
        ("c.bin", 3000),
        ("d.bin", 4000),
        ("e.bin", 5000),
    ] {
        let data = vec![0u8; *size];
        std::fs::write(dir.path().join(name), &data).unwrap();
    }

    let (sink, mut rx) = InMemoryEventSink::new();
    let _prepared =
        privet_transfer::prepare_dir_streaming(dir.path(), None, 0, 1024 * 1024, 1024, &sink, "t1")
            .await
            .unwrap();

    // 收集 PreparingProgress 事件
    let mut progress: Vec<(u64, u64)> = Vec::new();
    while let Ok(Some(e)) = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await
    {
        if let TransferEvent::PreparingProgress {
            scanned_bytes,
            total_bytes,
            ..
        } = e
        {
            progress.push((scanned_bytes, total_bytes));
        }
    }

    assert!(
        progress.len() >= 2,
        "expected at least 2 PreparingProgress events, got {}",
        progress.len()
    );

    // 单调递增 scanned_bytes
    for w in progress.windows(2) {
        assert!(
            w[0].0 <= w[1].0,
            "scanned_bytes must be non-decreasing: {:?}",
            w
        );
    }

    // 不超过 total_bytes
    let total = progress.last().unwrap().1;
    for (scanned, _) in &progress {
        assert!(
            *scanned <= total,
            "scanned_bytes {scanned} must not exceed total {total}"
        );
    }

    // 最终等于 total_bytes
    let (last_scanned, last_total) = progress.last().unwrap();
    assert_eq!(
        last_scanned, last_total,
        "final scanned_bytes must equal total_bytes"
    );

    // total_bytes 是 5 文件总大小
    assert_eq!(total, 1000 + 2000 + 3000 + 4000 + 5000);
}
