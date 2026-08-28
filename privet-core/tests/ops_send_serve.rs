use std::time::Duration;
use tempfile::TempDir;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
}

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
    // Tests in this binary run concurrently and each engine binds sockets; use
    // ephemeral ports and disable LAN discovery so the fixed defaults (47808/47809)
    // don't collide between tests.
    cfg.discovery.udp_port = 0;
    cfg.transport.quic_port = 0;
    cfg.transport.tcp_port = 0;
    std::fs::create_dir_all(cfg.save_dir.as_path()).ok();
    Engine::new(cfg)
}

#[tokio::test]
async fn send_to_serve_lands_file_over_quic() {
    init_tracing();
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

    // History detail exposes the send source path. prepare_single_file stores
    // the as-given absolute path (root.join(rel)), so compare against `src`
    // itself rather than canonicalize() (which adds a verbatim prefix on Windows).
    let detail = sender
        .history_detail(&outcome.transfer_id)
        .unwrap()
        .expect("completed send has a detail row");
    let expected_src = src.to_string_lossy();
    assert_eq!(
        detail.files[0].source_path.as_deref(),
        Some(expected_src.as_ref()),
        "send detail source_path must be the source path"
    );

    // The receiver must have recorded the inbound transfer in its own history,
    // with the saved file path resolvable from save_dir + relative_path.
    let recv_rows = receiver.history(None, 10).unwrap();
    let recv = recv_rows
        .iter()
        .find(|r| r.direction == "receive" && r.status == "completed")
        .expect("receiver recorded the completed inbound transfer");
    let recv_detail = receiver
        .history_detail(&recv.transfer_id)
        .unwrap()
        .expect("receive detail row exists");
    assert_eq!(recv_detail.files.len(), 1);
    assert_eq!(recv_detail.files[0].relative_path, "hello.txt");
    assert_eq!(
        recv_detail.save_dir.as_deref(),
        Some(save.to_str().unwrap()),
        "receive history carries the landing directory"
    );

    serve.shutdown().await;
    let _ = receiver.shutdown().await;
}

/// Reproduces the reported bug: the receiver cancels a mid-flight transfer.
/// The sender's history must NOT be recorded as 'completed' — it stays 'partial'
/// (resumable, matching the receiver's own row), and the send detail still lists
/// the file rows with their source paths (previously that detail could come back
/// empty, which the GUI surfaced as "no file list").
#[tokio::test]
async fn receiver_cancel_mid_flight_leaves_send_partial() {
    init_tracing();
    let dir = TempDir::new().unwrap();
    // The send runs on a spawned task while the same engine is queried for
    // history afterward, so share it through an Arc.
    let sender = std::sync::Arc::new(engine(&dir, "send"));

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

    // Large enough that the transfer is still mid-flight when the cancel lands.
    let src = dir.path().join("big.bin");
    std::fs::write(&src, vec![7u8; 64 * 1024 * 1024]).unwrap();

    let tid = "t-cancel-mid".to_string();
    let mut target_addr = serve.quic_addr;
    target_addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    let mut events = sender.subscribe();
    let send_engine = sender.clone();
    let src_for_send = src.clone();
    let tid_for_send = tid.clone();
    let send_task = tokio::spawn(async move {
        send_engine
            .send_with_id(
                vec![src_for_send],
                &PeerTarget::ByAddr(target_addr),
                None,
                None,
                tid_for_send,
            )
            .await
    });

    // Wait until the transfer is actually flowing (first progress event), then
    // cancel on the RECEIVER — the exact reported scenario. Gating on progress
    // avoids a race where the cancel lands before data flows.
    let mut reached_flight = false;
    while let Ok(ev) = tokio::time::timeout(Duration::from_secs(20), events.recv()).await {
        match ev {
            Ok(privet_core::EngineEvent::TransferProgress { transfer_id, .. })
                if transfer_id == tid =>
            {
                reached_flight = true;
                break;
            }
            Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
    assert!(reached_flight, "transfer should reach mid-flight before cancel");

    receiver.cancel_transfer(&tid).await.unwrap();

    // The send must complete without error: a cancellation is not reported as a
    // failure (the daemon would otherwise publish a spurious `transfer_failed`).
    let outcome = tokio::time::timeout(Duration::from_secs(15), send_task)
        .await
        .expect("send task timeout")
        .expect("send task join failed")
        .expect("cancelled send must not surface as an error");
    assert_eq!(outcome.transfer_id, tid);

    // The sender's history row must NOT be 'completed'.
    let rows = sender.history(None, 10).unwrap();
    let send_row = rows
        .iter()
        .find(|r| r.direction == "send" && r.transfer_id == tid)
        .expect("sender recorded the send");
    assert_eq!(
        send_row.status, "partial",
        "a receiver-cancelled send must be recorded as 'partial', not 'completed'"
    );

    // The send detail must still list the file rows (with source paths) — the
    // "history shows no file list" regression.
    let detail = sender
        .history_detail(&tid)
        .unwrap()
        .expect("send detail row exists");
    assert_eq!(detail.files.len(), 1);
    assert_eq!(
        detail.files[0].source_path.as_deref(),
        Some(src.to_string_lossy().as_ref())
    );

    // The receiver records the same transfer as 'partial' (consistent).
    let recv_rows = receiver.history(None, 10).unwrap();
    let recv_row = recv_rows
        .iter()
        .find(|r| r.direction == "receive" && r.transfer_id == tid)
        .expect("receiver recorded the inbound transfer");
    assert_eq!(recv_row.status, "partial");

    // The receiver's detail must list the file rows even though the transfer
    // was cancelled mid-flight. Previously the receiver only wrote transfer_files
    // rows inside complete_history, so a partial receive had files: [] in its
    // history detail ("no files to view" in the GUI). The fileset hook inserts
    // them before data flows, so the cancelled receive still shows its file.
    let recv_detail = receiver
        .history_detail(&tid)
        .unwrap()
        .expect("receive detail row exists");
    assert_eq!(recv_detail.files.len(), 1, "partial receive lists its file");
    assert_eq!(recv_detail.files[0].relative_path, "big.bin");
    assert_eq!(recv_detail.files[0].source_path, None);

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
