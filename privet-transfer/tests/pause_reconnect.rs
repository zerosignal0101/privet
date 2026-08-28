use privet_transfer::channel::{LoopbackControlChannel, LoopbackDataChannel};
use privet_transfer::config::TransferEngineConfig;
use privet_transfer::events::NoopEventSink;
use privet_transfer::part_store::{FsPartStore, PartStore};
use privet_transfer::receiver::{run_receiver, ReceiverInputs};
use privet_transfer::sender::{run_sender, ChunkReader, MappedChunkReader, SenderInputs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

struct CountingReader {
    inner: Box<dyn ChunkReader>,
    count: Arc<AtomicU64>,
}
impl ChunkReader for CountingReader {
    fn read_chunk(
        &self,
        file_id: &str,
        offset: u64,
        length: usize,
    ) -> privet_transfer::Result<Vec<u8>> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.inner.read_chunk(file_id, offset, length)
    }
}

#[tokio::test]
async fn reconnect_resumes_from_bitmask() {
    let dir = tempdir().unwrap();
    let data: Vec<u8> = (0..2_000_000u64).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.path().join("rc.bin"), &data).unwrap();
    let save = tempdir().unwrap();

    let prepared1 =
        privet_transfer::prepare::prepare_dir(dir.path(), None, 0, 1024 * 1024, 1024).unwrap();
    let reader1 = MappedChunkReader::from_prepared(&prepared1);
    let (c1a, c1b) = LoopbackControlChannel::pair(64);
    let (d1a, d1b) = LoopbackDataChannel::pair(1);
    let s1 = SenderInputs {
        control: Box::new(c1a),
        data: vec![Box::new(d1a)],
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig::default(),
        prepared: prepared1,
        reader: Box::new(reader1),
        transfer_id: "t1".into(),
        cmd_rx: None,
    };
    let r1 = ReceiverInputs {
        control: Box::new(c1b),
        data: vec![Box::new(d1b)],
        store: Box::new(FsPartStore::new(save.path().to_path_buf())),
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig {
            save_dir: save.path().to_path_buf(),
            ..Default::default()
        },
        accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
        registry: None,
        history: None,
    };
    let sr1 = tokio::spawn(run_sender(s1));
    let rr1 = tokio::spawn(run_receiver(r1));
    tokio::time::sleep(Duration::from_millis(300)).await;
    sr1.abort();
    rr1.abort();
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let _ = sr1.await;
        let _ = rr1.await;
    })
    .await;

    let prepared2 =
        privet_transfer::prepare::prepare_dir(dir.path(), None, 0, 1024 * 1024, 1024).unwrap();
    let reader2 = MappedChunkReader::from_prepared(&prepared2);
    let (c2a, c2b) = LoopbackControlChannel::pair(64);
    let (d2a, d2b) = LoopbackDataChannel::pair(64);
    let s2 = SenderInputs {
        control: Box::new(c2a),
        data: vec![Box::new(d2a)],
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig::default(),
        prepared: prepared2,
        reader: Box::new(reader2),
        transfer_id: "t1".into(),
        cmd_rx: None,
    };
    let r2 = ReceiverInputs {
        control: Box::new(c2b),
        data: vec![Box::new(d2b)],
        store: Box::new(FsPartStore::new(save.path().to_path_buf())),
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig {
            save_dir: save.path().to_path_buf(),
            ..Default::default()
        },
        accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
        registry: None,
        history: None,
    };
    let sr2 = tokio::spawn(run_sender(s2));
    let rr2 = tokio::spawn(run_receiver(r2));
    tokio::time::timeout(Duration::from_secs(20), async {
        sr2.await.unwrap().unwrap();
        rr2.await.unwrap().unwrap();
    })
    .await
    .unwrap();
    assert_eq!(std::fs::read(save.path().join("rc.bin")).unwrap(), data);
}

#[tokio::test]
async fn reconnect_skips_via_resume_bitmask() {
    let dir = tempdir().unwrap();
    let data: Vec<u8> = (0..2_000_000u64).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.path().join("rc.bin"), &data).unwrap();
    let save = tempdir().unwrap();

    let store = FsPartStore::new(save.path().to_path_buf());
    let cs = privet_protocol::constants::DEFAULT_CHUNK_SIZE;
    let chunk0_hash = hex::encode(privet_crypto::hash::blake3(&data[..cs]));
    let chunk1_hash = hex::encode(privet_crypto::hash::blake3(&data[cs..]));
    store
        .init_part_meta("t2", "rc.bin", "f0", 2_000_000, 0, "unused_file_hash")
        .unwrap();
    store
        .write_segment_meta(
            "t2",
            "rc.bin",
            "f0",
            0,
            "unused_root_hash",
            &[chunk0_hash, chunk1_hash],
        )
        .unwrap();
    store.pwrite_part("t2", "rc.bin", 0, &data[..cs]).unwrap();

    let bitmasks = privet_transfer::receiver::build_resume_bitmasks(save.path(), "t2").unwrap();
    assert!(
        !bitmasks.is_empty(),
        "resume bitmask must be non-empty after partial receive"
    );

    let prepared2 =
        privet_transfer::prepare::prepare_dir(dir.path(), None, 0, 1024 * 1024, 1024).unwrap();
    let reader2 = MappedChunkReader::from_prepared(&prepared2);
    let read_count = Arc::new(AtomicU64::new(0));
    let counting_reader = CountingReader {
        inner: Box::new(reader2),
        count: read_count.clone(),
    };
    let (c2a, c2b) = LoopbackControlChannel::pair(64);
    let (d2a, d2b) = LoopbackDataChannel::pair(64);
    let (event_sink, mut event_rx) = privet_transfer::events::InMemoryEventSink::new();
    let sr2 = tokio::spawn(run_sender(SenderInputs {
        control: Box::new(c2a),
        data: vec![Box::new(d2a)],
        events: Box::new(event_sink),
        config: TransferEngineConfig::default(),
        prepared: prepared2,
        reader: Box::new(counting_reader),
        transfer_id: "t2".into(),
        cmd_rx: None,
    }));
    let rr2 = tokio::spawn(run_receiver(ReceiverInputs {
        control: Box::new(c2b),
        data: vec![Box::new(d2b)],
        store: Box::new(FsPartStore::new(save.path().to_path_buf())),
        events: Box::new(NoopEventSink),
        config: TransferEngineConfig {
            save_dir: save.path().to_path_buf(),
            ..Default::default()
        },
        accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
        registry: None,
        history: None,
    }));
    tokio::time::timeout(Duration::from_secs(20), async {
        sr2.await.unwrap().unwrap();
        rr2.await.unwrap().unwrap();
    })
    .await
    .unwrap();

    let reads = read_count.load(Ordering::SeqCst);
    assert!(
        reads < 2,
        "expected read_chunk < 2 (resume skipped chunk 0), got {reads}"
    );

    let has_baseline = tokio::time::timeout(Duration::from_secs(1), async {
        use privet_transfer::events::TransferEvent;
        while let Some(ev) = event_rx.recv().await {
            if let TransferEvent::Progress { verified_bytes, .. } = ev {
                return verified_bytes >= 1_000_000;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(
        has_baseline,
        "sender must emit Progress with resume baseline"
    );
    assert_eq!(std::fs::read(save.path().join("rc.bin")).unwrap(), data);
}
