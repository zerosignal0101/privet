//! Preparing + FileSetBatch 流式
use privet_protocol::FileSetSummary;
use privet_transfer::fileset::{build_offer, FileSetAccumulator, FileSetBatcher};
use privet_transfer::prepare::{is_within_file_limit, prepare_dir, prepare_single_file};
use std::fs;
use tempfile::tempdir;

fn write(root: &std::path::Path, rel: &str, data: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, data).unwrap();
}

#[test]
fn prepare_single_file_hashes() {
    let dir = tempdir().unwrap();
    let data = b"hello world";
    write(dir.path(), "a.txt", data);
    let pf = prepare_single_file(dir.path(), "a.txt", 1, 1024, 1024).unwrap();
    assert_eq!(pf.relative_path, "a.txt");
    assert_eq!(pf.size, data.len() as u64);
    assert_eq!(pf.file_hash, hex::encode(privet_crypto::hash::blake3(data)));
    assert!(pf.segments.is_empty() || pf.segments[0].chunk_hashes.len() == 1);
}

#[test]
fn prepare_dir_inlines_small_and_segments_large() {
    let dir = tempdir().unwrap();
    write(dir.path(), "small.txt", b"tiny");
    let big = vec![7u8; 2 * 1024 * 1024]; // 2MiB -> 2 块
    write(dir.path(), "big.bin", &big);
    write(dir.path(), "sub/inner.txt", b"inner");
    fs::create_dir_all(dir.path().join("emptydir")).unwrap();

    let set = prepare_dir(dir.path(), None, 1, 1024 * 1024, 1024).unwrap();
    assert_eq!(set.files.len(), 3);
    // "sub" and "emptydir"
    assert!(set.dirs.iter().any(|d| d.relative_path == "emptydir"));
    let big_entry = set
        .files
        .iter()
        .find(|f| f.relative_path == "big.bin")
        .unwrap();
    assert_eq!(big_entry.size, big.len() as u64);
    let big_segs = set
        .files
        .iter()
        .find(|f| f.relative_path == "big.bin")
        .unwrap();
    assert_eq!(big_segs.segments.len(), 1);
    assert_eq!(big_segs.segments[0].chunk_hashes.len(), 2);
}

#[test]
fn prepare_root_name_validated() {
    let dir = tempdir().unwrap();
    write(dir.path(), "a.txt", b"x");
    let err = prepare_dir(dir.path(), Some("../"), 1, 1024, 1024).unwrap_err();
    assert!(matches!(err, privet_transfer::TransferError::PathUnsafe(_)));
    let set = prepare_dir(dir.path(), Some("Pics"), 1, 1024, 1024).unwrap();
    assert_eq!(set.summary.root_name, "Pics");
}

#[test]
fn batcher_frames_set_last_and_id() {
    let dir = tempdir().unwrap();
    let mut files = Vec::new();
    for i in 0..10 {
        let rel = format!("f{i}");
        write(dir.path(), &rel, b"x");
        files.push(prepare_single_file(dir.path(), &rel, i, 1024 * 1024, 1024).unwrap());
    }
    let mut batcher = FileSetBatcher::new("t1".into());
    for f in &files {
        batcher.push(f);
    }
    let frames = batcher.finish();
    assert_eq!(frames.len(), 1);
    assert!(frames[0].is_last);
    assert_eq!(frames[0].transfer_id, "t1");
    assert_eq!(frames[0].files.len(), 10);
}

#[test]
fn accumulator_rebuilds_and_validates_summary() {
    let dir = tempdir().unwrap();
    write(dir.path(), "a.txt", b"aaa");
    write(dir.path(), "b.txt", b"bb");
    let set = prepare_dir(dir.path(), None, 1, 1024 * 1024, 1024).unwrap();
    let offer = build_offer("t1", &set);
    assert_eq!(offer.transfer_id, "t1");
    let summary = offer.summary.as_ref().unwrap();
    assert_eq!(summary.file_count, 2);
    assert!(offer.resume_supported);

    let mut batcher = FileSetBatcher::new("t1".into());
    for f in &set.files {
        batcher.push(f);
    }
    let frames = batcher.finish();

    let mut acc = FileSetAccumulator::new(summary);
    for f in &frames[..frames.len() - 1] {
        acc.ingest(f).unwrap();
        assert!(!acc.is_complete());
    }
    acc.ingest(frames.last().unwrap()).unwrap();
    assert!(acc.is_complete());
}

#[test]
fn accumulator_manifest_mismatch_on_wrong_count() {
    let summary = FileSetSummary {
        root_name: String::new(),
        file_count: 5,
        total_bytes: 0,
        dir_count: 0,
    };
    let mut acc = FileSetAccumulator::new(&summary);
    let f = privet_protocol::FileSetBatch {
        transfer_id: "t".into(),
        files: vec![],
        dirs: vec![],
        is_last: true,
    };
    let err = acc.ingest(&f).unwrap_err();
    assert!(matches!(
        err,
        privet_transfer::TransferError::ManifestMismatch(_)
    ));
}

#[test]
fn too_many_files_rejected() {
    assert!(is_within_file_limit(
        privet_transfer::MAX_FILES_PER_TRANSFER
    ));
    assert!(!is_within_file_limit(
        privet_transfer::MAX_FILES_PER_TRANSFER + 1
    ));
}
