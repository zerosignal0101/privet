//! Engine::pair_initiate + set_pending_pair_code + serve 配对 e2e over loopback QUIC。
use std::time::Duration;
use tempfile::TempDir;

use privet_core::ops::ServeOptions;
use privet_core::pairing::SystemPairingClock;
use privet_core::{Engine, EngineConfig};
use privet_security::code::PairingCode;
use privet_security::session::PairingOutcome;
use privet_transfer::CollisionPolicy;

fn engine(dir: &TempDir, name: &str) -> Engine {
    let mut cfg = EngineConfig {
        device_name: name.into(),
        db_path: dir.path().join(format!("{name}.db")),
        save_dir: dir.path().join(name),
        identity_path: Some(dir.path().join(format!("{name}.bin"))),
        ..Default::default()
    };
    cfg.transport.mode = privet_transport::TransportMode::Quic;
    std::fs::create_dir_all(cfg.save_dir.as_path()).ok();
    Engine::new(cfg)
}

#[tokio::test]
async fn pair_initiate_and_accept_succeed_over_quic() {
    let dir = TempDir::new().unwrap();
    let mut receiver = engine(&dir, "recv");
    receiver.start().await.unwrap();
    let sender = engine(&dir, "send");

    let clock = SystemPairingClock;
    let code = PairingCode::generate_decimal(&clock).unwrap();
    let code_str = code.code().to_string();

    let serve = receiver
        .serve(ServeOptions {
            save_dir: dir.path().join("recv"),
            accept_all_trusted: false,
            on_collision: CollisionPolicy::Rename,
            accept_policy: privet_core::AcceptPolicy::AutoAccept,
        })
        .await
        .unwrap();
    receiver.set_pending_pair_code(code);

    // 绑 0.0.0.0：接收所有接口；本地测试须用 127.0.0.1 连接。
    let mut addr = serve.quic_addr;
    addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let outcome = tokio::time::timeout(Duration::from_secs(15), async {
        sender.pair_initiate(addr, code_str).await
    })
    .await
    .expect("pair timeout")
    .expect("pair failed");
    assert!(matches!(outcome, PairingOutcome::Paired { .. }));

    // 双方互信。
    assert!(sender
        .list_trusted()
        .unwrap()
        .iter()
        .any(|r| r.device_fingerprint == receiver.identity().fingerprint()));
    assert!(receiver
        .list_trusted()
        .unwrap()
        .iter()
        .any(|r| r.device_fingerprint == sender.identity().fingerprint()));

    serve.shutdown().await;
    let _ = receiver.shutdown().await;
}
