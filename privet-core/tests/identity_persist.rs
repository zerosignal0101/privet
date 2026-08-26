//! 身份持久化（load-or-create 0600）+ Engine::start 修 identity bug。
use privet_core::{Engine, EngineConfig};
use tempfile::TempDir;

#[test]
fn identity_persists_across_engine_instances() {
    let dir = TempDir::new().unwrap();
    let id_path = dir.path().join("identity.bin");
    let cfg = EngineConfig {
        identity_path: Some(id_path.clone()),
        db_path: dir.path().join("p.db"),
        save_dir: dir.path().to_path_buf(),
        ..Default::default()
    };
    let e1 = Engine::new(cfg.clone());
    let did1 = e1.identity().fingerprint();
    let fp1 = e1.identity().fingerprint();

    // 第二次构造：载入同一 keystore，device_id/fingerprint 不变。
    let e2 = Engine::new(cfg);
    assert_eq!(e2.identity().fingerprint(), did1);
    assert_eq!(e2.identity().fingerprint(), fp1);
    // 文件已落盘（0600）。
    assert!(id_path.exists());
}

#[test]
fn identity_ephemeral_when_path_none() {
    let dir = TempDir::new().unwrap();
    let cfg = EngineConfig {
        db_path: dir.path().join("p.db"),
        save_dir: dir.path().to_path_buf(),
        identity_path: None,
        ..Default::default()
    };
    let e1 = Engine::new(cfg.clone());
    let e2 = Engine::new(cfg);
    // 无 keystore -> 每次新身份。
    assert_ne!(e1.identity().fingerprint(), e2.identity().fingerprint());
}
