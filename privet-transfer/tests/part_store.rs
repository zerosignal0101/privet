//! PartStore（.part/sidecar/resume/finalize/碰撞/落地根/清理）
use privet_transfer::config::CollisionPolicy;
use privet_transfer::part_store::{FinalizeOutcome, FsPartStore, PartStore};
use std::fs;
use tempfile::TempDir;

fn store() -> (TempDir, FsPartStore) {
    let dir = tempfile::tempdir().unwrap();
    let save = dir.path().to_path_buf();
    (dir, FsPartStore::new(save))
}

#[test]
fn pwrite_and_read_range() {
    let (_tdir, st) = store();
    st.pwrite_part("t1", "a/b.txt", 0, b"hello").unwrap();
    st.pwrite_part("t1", "a/b.txt", 5, b" world").unwrap();
    let r = st.read_part_range("t1", "a/b.txt", 0, 11).unwrap();
    assert_eq!(&r, b"hello world");
}

#[test]
fn write_segment_meta_then_resume_rebuilds() {
    let (_tdir, st) = store();
    st.init_part_meta("t1", "a.bin", "f1", 8, 0, "fullhash")
        .unwrap();
    st.pwrite_part("t1", "a.bin", 0, b"AAAABBBB").unwrap();
    // 默认分段 1MiB/块，8 字节文件 -> 1 块
    let h0 = hex::encode(privet_crypto::hash::blake3(b"AAAABBBB"));
    st.write_segment_meta("t1", "a.bin", "f1", 0, "root0", &[h0])
        .unwrap();
    let bm = st.rebuild_resume_bitmask("t1", "a.bin").unwrap();
    assert_eq!(bm.len(), 1);
    assert_eq!(bm[0].segment_id, 0);
    // 1 块全部验证 -> bit 0 set
    assert_eq!(bm[0].bitmask, vec![0b01]);
}

#[test]
fn finalize_renames_and_deletes_meta() {
    let (_tdir, st) = store();
    st.init_part_meta("t1", "a.txt", "f1", 5, 0, "h").unwrap();
    st.pwrite_part("t1", "a.txt", 0, b"hello").unwrap();
    let final_path = st.save_dir().join("a.txt");
    let out = st
        .finalize_part("t1", "a.txt", &final_path, CollisionPolicy::Rename)
        .unwrap();
    assert!(matches!(out, FinalizeOutcome::Landed));
    assert_eq!(fs::read(&final_path).unwrap(), b"hello");
}

#[test]
fn collision_rename_finds_free_name() {
    let (_tdir, st) = store();
    fs::write(st.save_dir().join("a.txt"), b"old").unwrap();
    st.init_part_meta("t1", "a.txt", "f1", 3, 0, "h").unwrap();
    st.pwrite_part("t1", "a.txt", 0, b"new").unwrap();
    let out = st
        .finalize_part(
            "t1",
            "a.txt",
            &st.save_dir().join("a.txt"),
            CollisionPolicy::Rename,
        )
        .unwrap();
    assert!(matches!(out, FinalizeOutcome::Landed));
    assert_eq!(fs::read(st.save_dir().join("a.txt")).unwrap(), b"old");
    assert_eq!(fs::read(st.save_dir().join("a(1).txt")).unwrap(), b"new");
}

#[test]
fn collision_skip_does_not_land() {
    let (_tdir, st) = store();
    fs::write(st.save_dir().join("a.txt"), b"old").unwrap();
    st.init_part_meta("t1", "a.txt", "f1", 3, 0, "h").unwrap();
    st.pwrite_part("t1", "a.txt", 0, b"new").unwrap();
    let out = st
        .finalize_part(
            "t1",
            "a.txt",
            &st.save_dir().join("a.txt"),
            CollisionPolicy::Skip,
        )
        .unwrap();
    assert!(matches!(out, FinalizeOutcome::Skipped));
    assert_eq!(fs::read(st.save_dir().join("a.txt")).unwrap(), b"old");
    assert!(!st.save_dir().join(".privet/t1/a.txt.part").exists());
}

#[test]
fn collision_overwrite_replaces() {
    let (_tdir, st) = store();
    fs::write(st.save_dir().join("a.txt"), b"old").unwrap();
    st.init_part_meta("t1", "a.txt", "f1", 3, 0, "h").unwrap();
    st.pwrite_part("t1", "a.txt", 0, b"new").unwrap();
    let out = st
        .finalize_part(
            "t1",
            "a.txt",
            &st.save_dir().join("a.txt"),
            CollisionPolicy::Overwrite,
        )
        .unwrap();
    assert!(matches!(out, FinalizeOutcome::Landed));
    assert_eq!(fs::read(st.save_dir().join("a.txt")).unwrap(), b"new");
}

#[test]
fn cleanup_staging_removes_transfer_dir() {
    let (_tdir, st) = store();
    st.init_part_meta("t1", "a.txt", "f1", 3, 0, "h").unwrap();
    st.pwrite_part("t1", "a.txt", 0, b"new").unwrap();
    // finalize first to move the .part out, then cleanup removes staging
    st.finalize_part(
        "t1",
        "a.txt",
        &st.save_dir().join("a.txt"),
        CollisionPolicy::Rename,
    )
    .unwrap();
    st.cleanup_staging("t1").unwrap();
    assert!(!st.save_dir().join(".privet/t1").exists());
}

#[test]
fn finalize_root_mkdir_with_root_name() {
    let (_tdir, st) = store();
    st.mkdir_finalize_root(st.save_dir(), Some("Pics")).unwrap();
    assert!(st.save_dir().join("Pics").is_dir());
    st.mkdir_finalize_root(st.save_dir(), None).unwrap();
    assert!(st.save_dir().is_dir());
}

#[test]
fn delete_part_removes_both() {
    let (_tdir, st) = store();
    st.init_part_meta("t1", "a.txt", "f1", 3, 0, "h").unwrap();
    st.pwrite_part("t1", "a.txt", 0, b"data").unwrap();
    st.delete_part("t1", "a.txt").unwrap();
    assert!(!st.save_dir().join(".privet/t1/a.txt.part").exists());
    assert!(!st.save_dir().join(".privet/t1/a.txt.part.meta").exists());
}
