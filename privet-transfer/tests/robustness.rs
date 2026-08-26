use privet_transfer::channel::{LoopbackControlChannel, LoopbackDataChannel, ReorderDataChannel};
use privet_transfer::config::TransferEngineConfig;
use privet_transfer::events::NoopEventSink;
use privet_transfer::part_store::FsPartStore;
use privet_transfer::receiver::{run_receiver, ReceiverInputs};
use privet_transfer::sender::{run_sender, MappedChunkReader, SenderInputs};
use std::time::Duration;
use tempfile::tempdir;

async fn roundtrip(
    root: &std::path::Path,
    files: &[(&str, &[u8])],
) -> (tempfile::TempDir, std::path::PathBuf) {
    let save = tempdir().unwrap();
    let save_path = save.path().to_path_buf();
    for (rel, data) in files {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, data).unwrap();
    }
    let prepared = privet_transfer::prepare::prepare_dir(root, None, 0, 1024 * 1024, 1024).unwrap();
    let reader = MappedChunkReader::from_prepared(&prepared);
    let (ctl_a, ctl_b) = LoopbackControlChannel::pair(64);
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
    (save, save_path)
}

#[tokio::test]
async fn out_of_order_arrival_assembles_correctly() {
    let dir = tempdir().unwrap();
    let data: Vec<u8> = (0..3_000_000u64).map(|i| (i % 251) as u8).collect();
    let root = dir.path();
    std::fs::write(root.join("o.bin"), &data).unwrap();

    let prepared = privet_transfer::prepare::prepare_dir(root, None, 0, 1024 * 1024, 1024).unwrap();
    let reader = MappedChunkReader::from_prepared(&prepared);
    let (ctl_a, ctl_b) = LoopbackControlChannel::pair(64);
    let (dat_a, dat_b_inner) = LoopbackDataChannel::pair(64);
    let dat_b = ReorderDataChannel::buffer_and_reverse(Box::new(dat_b_inner), 3);
    let save = tempdir().unwrap();
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
    assert_eq!(std::fs::read(save.path().join("o.bin")).unwrap(), data);
}

#[test]
fn large_file_5gib_segment_layout() {
    let size: u64 = 5 * 1024 * 1024 * 1024;
    let layout = privet_protocol::layout::derive_segment_layout_default(size);
    assert_eq!(layout.len(), 5, "5GiB -> 5 segments");
    assert_eq!(layout[0].chunk_count, 1024);
    let small = 5 * 1024 * 1024 + 1;
    let sl = privet_protocol::layout::derive_segment_layout(small, 1024 * 1024, 1024);
    assert_eq!(sl[0].chunk_count, 6);
}

#[tokio::test]
async fn many_small_files_all_inline() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let contents: Vec<Vec<u8>> = (0..200).map(|i| vec![(i % 256) as u8; 1024]).collect();
    for (i, c) in contents.iter().enumerate() {
        std::fs::write(root.join(format!("f{i}.bin")), c).unwrap();
    }
    let prepared =
        privet_transfer::prepare::prepare_dir(&root, None, 0, 1024 * 1024, 1024).unwrap();
    assert!(prepared.files.iter().all(|f| f.inline));
    let reader = MappedChunkReader::from_prepared(&prepared);
    let (ctl_a, ctl_b) = LoopbackControlChannel::pair(256);
    let (dat_a, dat_b) = LoopbackDataChannel::pair(256);
    let save = tempdir().unwrap();
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
    tokio::time::timeout(Duration::from_secs(60), async {
        sr.await.unwrap().unwrap();
        rr.await.unwrap().unwrap();
    })
    .await
    .unwrap();
    for (i, c) in contents.iter().enumerate() {
        assert_eq!(
            std::fs::read(save.path().join(format!("f{i}.bin"))).unwrap(),
            *c
        );
    }
}

#[tokio::test]
async fn inline_boundary_65536_and_65537() {
    let dir = tempdir().unwrap();
    let exactly = vec![9u8; 65536];
    std::fs::write(dir.path().join("exact.bin"), &exactly).unwrap();
    let (_tdir, save) = roundtrip(dir.path(), &[("exact.bin", &exactly)]).await;
    assert_eq!(std::fs::read(save.join("exact.bin")).unwrap(), exactly);

    let dir2 = tempdir().unwrap();
    let one_more = vec![9u8; 65537];
    std::fs::write(dir2.path().join("one.bin"), &one_more).unwrap();
    let (_tdir2, save2) = roundtrip(dir2.path(), &[("one.bin", &one_more)]).await;
    assert_eq!(std::fs::read(save2.join("one.bin")).unwrap(), one_more);
}
