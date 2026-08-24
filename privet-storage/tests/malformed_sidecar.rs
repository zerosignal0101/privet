//! DoS hardening: rebuild_verified_bitmap must not panic/OOM on malformed sidecar data.

use privet_storage::resume::rebuild_verified_bitmap;
use privet_storage::sidecar::{part_meta_path, write_part_meta_initial};
use privet_storage::{PartMeta, PartSegment, StorageError};

fn write_meta(save_dir: &std::path::Path, meta: &PartMeta) {
    let mp = part_meta_path(save_dir, "t1", "a.bin").unwrap();
    write_part_meta_initial(&mp, meta).unwrap();
}

#[test]
fn mismatched_chunk_count_does_not_panic() {
    // chunk_count says 10 but chunk_hashes only has 3 entries → must not index OOB
    let dir = tempfile::tempdir().unwrap();
    let meta = PartMeta {
        transfer_id: "t1".into(),
        file_id: "f1".into(),
        relative_path: "a.bin".into(),
        size: 100,
        mtime_ms: 0,
        hash_type: "blake3".into(),
        hash_value: "hash".into(),
        segments: vec![PartSegment {
            segment_id: 0,
            offset: 0,
            length: 100,
            chunk_count: 10,
            chunk_size: 10,
            hash_type: "blake3".into(),
            segment_hash_value: String::new(),
            chunk_hash_values: vec!["h0".into(), "h1".into(), "h2".into()],
        }],
    };
    write_meta(dir.path(), &meta);
    let out = rebuild_verified_bitmap(dir.path(), "t1", "a.bin");
    assert!(out.is_err(), "expected Err on mismatched chunk_count");
    assert!(
        matches!(out, Err(StorageError::Corrupt(_))),
        "expected Corrupt error"
    );
}

#[test]
fn absurd_chunk_size_does_not_oom() {
    let dir = tempfile::tempdir().unwrap();
    let meta = PartMeta {
        transfer_id: "t1".into(),
        file_id: "f1".into(),
        relative_path: "a.bin".into(),
        size: u64::MAX,
        mtime_ms: 0,
        hash_type: "blake3".into(),
        hash_value: "hash".into(),
        segments: vec![PartSegment {
            segment_id: 0,
            offset: 0,
            length: u64::MAX,
            chunk_count: 1,
            chunk_size: u32::MAX,
            hash_type: "blake3".into(),
            segment_hash_value: String::new(),
            chunk_hash_values: vec!["h0".into()],
        }],
    };
    write_meta(dir.path(), &meta);
    let out = rebuild_verified_bitmap(dir.path(), "t1", "a.bin");
    assert!(
        out.is_err(),
        "expected Err on absurd chunk_size, got {:?}",
        out
    );
}
