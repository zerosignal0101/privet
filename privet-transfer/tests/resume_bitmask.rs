//! resume bitmask built from existing .part + sidecar is non-empty.

use privet_storage::sidecar::{
    build_initial_meta, part_meta_path, part_path, write_part_meta_initial,
};
use privet_transfer::receiver::build_resume_bitmasks;

fn write_file(p: &std::path::Path, data: &[u8]) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

#[test]
fn resume_bitmask_from_existing_part() {
    let dir = tempfile::tempdir().unwrap();
    let save = dir.path();

    // Write a .part file with known content
    let content = b"AAAA";
    let part_p = part_path(save, "t1", "a.bin").unwrap();
    write_file(&part_p, content);

    // Write sidecar with matching hash
    let hash = hex::encode(privet_crypto::hash::blake3(content));
    let mut meta = build_initial_meta("t1", "f1", "a.bin", 4, 0, "placeholder_hash");
    meta.segments[0].chunk_hash_values = vec![hash];
    let meta_p = part_meta_path(save, "t1", "a.bin").unwrap();
    write_part_meta_initial(&meta_p, &meta).unwrap();

    // Build resume bitmasks
    let bitmasks = build_resume_bitmasks(save, "t1").unwrap();
    assert!(!bitmasks.is_empty(), "expected non-empty resume bitmasks");
    assert_eq!(bitmasks[0].file_id, "f1");
    assert_eq!(bitmasks[0].segment_id, 0);
    // The single chunk is verified -> bit 0 set
    assert!(!bitmasks[0].bitmask.is_empty(), "bitmask bytes present");
    // At least one bit set (chunk 0 verified)
    assert!(
        bitmasks[0].bitmask.iter().any(|&b| b != 0),
        "verified chunk bit set"
    );
}

#[test]
fn empty_staging_produces_empty_resume() {
    let dir = tempfile::tempdir().unwrap();
    let bitmasks = build_resume_bitmasks(dir.path(), "ghost_tid").unwrap();
    assert!(bitmasks.is_empty(), "no staging -> empty resume");
}
