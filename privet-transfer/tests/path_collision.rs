//! 路径安全 + root_name + 空目录 + 碰撞矩阵
use privet_protocol::path::sanitize_relative_path;
use privet_transfer::config::CollisionPolicy;
use privet_transfer::part_store::{FsPartStore, PartStore};
use std::fs;
use tempfile::tempdir;

#[test]
fn path_unsafe_relative_rejected() {
    for bad in ["../x", "/abs", "C:foo", "a\0b", ""] {
        assert!(sanitize_relative_path(bad).is_err());
    }
}

#[test]
fn root_name_landing() {
    let dir = tempdir().unwrap();
    let save = dir.path();
    let st = FsPartStore::new(save.to_path_buf());
    st.mkdir_finalize_root(save, Some("Pics")).unwrap();
    assert!(save.join("Pics").is_dir());
}

#[test]
fn collision_rename_new_name() {
    let dir = tempdir().unwrap();
    let save = dir.path();
    fs::write(save.join("a.txt"), b"old").unwrap();
    let st = FsPartStore::new(save.to_path_buf());
    st.init_part_meta("t1", "a.txt", "f1", 3, 0, "h").unwrap();
    st.pwrite_part("t1", "a.txt", 0, b"new").unwrap();
    let out = st
        .finalize_part("t1", "a.txt", &save.join("a.txt"), CollisionPolicy::Rename)
        .unwrap();
    assert!(matches!(
        out,
        privet_transfer::part_store::FinalizeOutcome::Landed
    ));
    assert_eq!(fs::read(save.join("a.txt")).unwrap(), b"old");
    assert_eq!(fs::read(save.join("a(1).txt")).unwrap(), b"new");
}
