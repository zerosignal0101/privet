use privet_core::{Engine, EngineConfig};
use tempfile::TempDir;

#[tokio::test]
async fn engine_construct_start_shutdown() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = EngineConfig {
        db_path: tmp.path().join("e2e.db"),
        save_dir: tmp.path().to_path_buf(),
        device_name: "e2e-test".into(),
        ..Default::default()
    };
    // Don't bind the fixed discovery/transport ports: a dev privetd (or another
    // test) may already hold 47808/47809. This test only exercises start/shutdown.
    cfg.discovery.udp_port = 0;
    cfg.transport.quic_port = 0;
    cfg.transport.tcp_port = 0;

    let mut engine = Engine::new(cfg);
    assert!(!engine.is_cancelled());

    let _rx = engine.subscribe();

    engine.start().await.unwrap();
    assert!(!engine.is_cancelled());

    engine.shutdown().await.unwrap();
    assert!(engine.is_cancelled());
}
