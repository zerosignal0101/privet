use std::time::Duration;
use tempfile::TempDir;

use privet_core::ops::{PeerTarget, ServeOptions};
use privet_core::{Engine, EngineConfig};
use privet_transfer::CollisionPolicy;
use privet_transport::TransportMode;

fn engine(dir: &TempDir, name: &str) -> Engine {
    let mut cfg = EngineConfig {
        device_name: name.into(),
        db_path: dir.path().join(format!("{name}.db")),
        save_dir: dir.path().join(name),
        identity_path: Some(dir.path().join(format!("{name}.bin"))),
        ..Default::default()
    };
    cfg.transport.mode = TransportMode::Quic;
    std::fs::create_dir_all(cfg.save_dir.as_path()).ok();
    Engine::new(cfg)
}

#[tokio::test]
async fn send_to_serve_lands_file_over_quic() {
    let dir = TempDir::new().unwrap();
    let sender = engine(&dir, "send");

    let mut receiver = engine(&dir, "recv");
    let spki = sender.identity().spki_der().to_vec();
    let fp = sender.identity().fingerprint();
    {
        let conn = privet_storage::migration::open_and_migrate(dir.path().join("recv.db")).unwrap();
        privet_storage::trust::insert_paired(
            &conn,
            &privet_storage::trust::PeerTrust {
                device_fingerprint: &fp,
                peer_spki: &spki,
                peer_device_name: "alice",
                share_with_peers: false,
                first_paired_ts: 100,
                last_seen_ts: 100,
            },
            &privet_storage::trust::PeerAddress {
                subnet_cidr: "127.0.0.0/8",
                gateway_ip: None,
                addr: "127.0.0.1",
                quic_port: 0,
                tcp_port: 0,
                source: "self",
                last_seen_ts: 100,
            },
        )
        .unwrap();
        drop(conn);
    }

    receiver.start().await.unwrap();
    let save = dir.path().join("recv");
    std::fs::create_dir_all(save.join(".privet")).ok();
    let serve = receiver
        .serve(ServeOptions {
            save_dir: save.clone(),
            accept_all_trusted: true,
            on_collision: CollisionPolicy::Rename,
            accept_policy: privet_core::AcceptPolicy::AutoAccept,
        })
        .await
        .unwrap();

    let src = dir.path().join("hello.txt");
    std::fs::write(&src, b"hello world from privet").unwrap();

    let mut target_addr = serve.quic_addr;
    target_addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let outcome = tokio::time::timeout(Duration::from_secs(15), async {
        sender
            .send(
                vec![src.clone()],
                &PeerTarget::ByAddr(target_addr),
                None,
                None,
            )
            .await
    })
    .await
    .expect("send timeout")
    .expect("send failed");
    assert_eq!(outcome.file_count, 1);
    assert!(outcome.total_bytes > 0);

    let landed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let p = save.join("hello.txt");
            if p.exists() {
                break std::fs::read(&p).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("land timeout");
    assert_eq!(landed, b"hello world from privet");

    let rows = sender.history(None, 10).unwrap();
    assert!(rows
        .iter()
        .any(|r| r.direction == "send" && r.status == "completed"));

    serve.shutdown().await;
    let _ = receiver.shutdown().await;
}

/// A runtime policy update takes effect without restarting the listener.
#[tokio::test]
async fn runtime_accept_all_trusted_toggle_makes_resolver_autoaccept() {
    let dir = TempDir::new().unwrap();
    let sender = engine(&dir, "snd");

    let mut receiver = engine(&dir, "rcv");
    let spki = sender.identity().spki_der().to_vec();
    let fp = sender.identity().fingerprint();
    {
        let conn = privet_storage::migration::open_and_migrate(dir.path().join("rcv.db")).unwrap();
        privet_storage::trust::insert_paired(
            &conn,
            &privet_storage::trust::PeerTrust {
                device_fingerprint: &fp,
                peer_spki: &spki,
                peer_device_name: "alice",
                share_with_peers: false,
                first_paired_ts: 100,
                last_seen_ts: 100,
            },
            &privet_storage::trust::PeerAddress {
                subnet_cidr: "127.0.0.0/8",
                gateway_ip: None,
                addr: "127.0.0.1",
                quic_port: 0,
                tcp_port: 0,
                source: "self",
                last_seen_ts: 100,
            },
        )
        .unwrap();
        drop(conn);
    }

    receiver.start().await.unwrap();
    let save = dir.path().join("rcv");
    std::fs::create_dir_all(save.join(".privet")).ok();

    let serve = receiver
        .serve(ServeOptions {
            save_dir: save.clone(),
            accept_all_trusted: false,
            on_collision: CollisionPolicy::Rename,
            accept_policy: privet_core::AcceptPolicy::Resolver(receiver.offer_resolver_arc()),
        })
        .await
        .unwrap();

    receiver.runtime().set_accept_all_trusted(true);

    let src = dir.path().join("data.bin");
    std::fs::write(&src, b"runtime-toggle works").unwrap();

    let mut target_addr = serve.quic_addr;
    target_addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let outcome = tokio::time::timeout(Duration::from_secs(15), async {
        sender
            .send(
                vec![src.clone()],
                &PeerTarget::ByAddr(target_addr),
                None,
                None,
            )
            .await
    })
    .await
    .expect("send timeout")
    .expect("send failed");
    assert_eq!(outcome.file_count, 1);

    let landed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let p = save.join("data.bin");
            if p.exists() {
                break std::fs::read(&p).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("land timeout");
    assert_eq!(landed, b"runtime-toggle works");

    serve.shutdown().await;
    let _ = receiver.shutdown().await;
}
