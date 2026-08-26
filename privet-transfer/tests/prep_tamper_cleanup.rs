//! Preparing 进度 + rename 前篡改 + staging 清理
use privet_transfer::config::CollisionPolicy;
use privet_transfer::part_store::{FsPartStore, PartStore};
use tempfile::tempdir;

#[test]
fn tamper_before_rename_caught() {
    let dir = tempdir().unwrap();
    let save = dir.path().to_path_buf();
    let st = FsPartStore::new(save.clone());
    st.init_part_meta(
        "t1",
        "a.bin",
        "f1",
        4,
        0,
        &hex::encode(privet_crypto::hash::blake3(b"AAAA")),
    )
    .unwrap();
    st.pwrite_part("t1", "a.bin", 0, b"AAAA").unwrap();
    let h0 = hex::encode(privet_crypto::hash::blake3(b"AAAA"));
    st.write_segment_meta("t1", "a.bin", "f1", 0, "root", &[h0])
        .unwrap();
    st.pwrite_part("t1", "a.bin", 0, b"XXXX").unwrap();
    let part_data = st.read_part_range("t1", "a.bin", 0, 4).unwrap();
    let recomputed = hex::encode(privet_crypto::hash::blake3(&part_data));
    assert_ne!(
        recomputed,
        hex::encode(privet_crypto::hash::blake3(b"AAAA"))
    );
}

#[test]
fn staging_cleanup_after_complete() {
    let dir = tempdir().unwrap();
    let save = dir.path();
    let st = FsPartStore::new(save.to_path_buf());
    st.init_part_meta("t1", "a.txt", "f1", 3, 0, "h").unwrap();
    st.pwrite_part("t1", "a.txt", 0, b"new").unwrap();
    st.finalize_part("t1", "a.txt", &save.join("a.txt"), CollisionPolicy::Rename)
        .unwrap();
    st.cleanup_staging("t1").unwrap();
    assert!(!save.join(".privet/t1").exists());
    assert!(!save.join(".privet").exists());
}
