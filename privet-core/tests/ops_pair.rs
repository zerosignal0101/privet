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
    // Don't bind the fixed discovery/transport ports: a dev privetd (or another
    // test) may already hold 47808/47809. The handshake connects to the actual
    // bound ports from `serve`, so ephemeral ports work here.
    cfg.discovery.udp_port = 0;
    cfg.transport.quic_port = 0;
    cfg.transport.tcp_port = 0;
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

    let mut quic_addr = serve.quic_addr;
    quic_addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let mut tcp_addr = serve.tcp_addr;
    tcp_addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let outcome = tokio::time::timeout(Duration::from_secs(15), async {
        sender
            .pair_initiate_with_ports(quic_addr, tcp_addr, code_str)
            .await
    })
    .await
    .expect("pair timeout")
    .expect("pair failed");
    assert!(matches!(outcome, PairingOutcome::Paired { .. }));

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

    let addresses = privet_storage::addresses::recent_known(
        &sender.db_conn().unwrap(),
        &receiver.identity().fingerprint(),
        1,
    )
    .unwrap();
    assert_eq!(addresses[0].quic_port, quic_addr.port());
    assert_eq!(addresses[0].tcp_port, tcp_addr.port());

    serve.shutdown().await;
    let _ = receiver.shutdown().await;
}
