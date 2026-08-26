//! 续传已验证位图 + manifest 变更。
use privet_transfer::part_store::{FsPartStore, PartStore};
use privet_transfer::resume::manifest_changed;
use tempfile::tempdir;

#[test]
fn resume_bitmask_only_verified_chunks_set() {
    let dir = tempdir().unwrap();
    let save = dir.path();
    let st = FsPartStore::new(save.to_path_buf());
    st.init_part_meta("t1", "a.bin", "f1", 8, 0, "full")
        .unwrap();
    st.pwrite_part("t1", "a.bin", 0, b"AAAABBBB").unwrap();
    let h0 = hex::encode(privet_crypto::hash::blake3(b"AAAABBBB"));
    st.write_segment_meta("t1", "a.bin", "f1", 0, "root", &[h0])
        .unwrap();
    let bm = st.rebuild_resume_bitmask("t1", "a.bin").unwrap();
    assert_eq!(bm.len(), 1);
    assert_eq!(bm[0].bitmask, vec![0b01]);
}

#[test]
fn manifest_changed_when_size_or_hash_differ() {
    let dir = tempdir().unwrap();
    let save = dir.path();
    let st = FsPartStore::new(save.to_path_buf());
    st.init_part_meta("t1", "a.bin", "f1", 100, 0, "oldhash")
        .unwrap();
    let mp = privet_storage::sidecar::part_meta_path(st.save_dir(), "t1", "a.bin").unwrap();
    let meta = privet_storage::sidecar::read_part_meta(&mp).unwrap();
    assert!(manifest_changed(&meta, 200, "newhash"));
    assert!(!manifest_changed(&meta, 100, "oldhash"));
}
