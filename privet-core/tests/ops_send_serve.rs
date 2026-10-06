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

/// Issue regression: the receiver unilaterally drops (forgets) the sender, then
/// the sender — which still trusts the receiver — tries to send. The receiver
/// no longer trusts the sender, so it must decline the offer with a reason and
/// the sender must fail fast (no reconnect storm) with a clear rejection, and
/// its history row must be marked 'failed' so the send is visible and resendable.
#[tokio::test]
async fn send_to_peer_that_forgot_us_is_rejected_fast_with_failed_history() {
    init_tracing();
    let dir = TempDir::new().unwrap();
    let sender = engine(&dir, "send");

    let mut receiver = engine(&dir, "recv");
    let s_spki = sender.identity().spki_der().to_vec();
    let s_fp = sender.identity().fingerprint();
    let r_fp = receiver.identity().fingerprint();
    let r_spki = receiver.identity().spki_der().to_vec();
    // Pre-insert mutual trust, as if the pair had completed pairing earlier.
    {
        let conn = privet_storage::migration::open_and_migrate(dir.path().join("recv.db")).unwrap();
        privet_storage::trust::insert_paired(
            &conn,
            &privet_storage::trust::PeerTrust {
                device_fingerprint: &s_fp,
                peer_spki: &s_spki,
                peer_device_name: "sender",
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
    {
        let conn = privet_storage::migration::open_and_migrate(dir.path().join("send.db")).unwrap();
        privet_storage::trust::insert_paired(
            &conn,
            &privet_storage::trust::PeerTrust {
                device_fingerprint: &r_fp,
                peer_spki: &r_spki,
                peer_device_name: "receiver",
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

    // The receiver unilaterally drops the sender: forget removes the row, so
    // the sender is Unknown to the receiver while still Trusted to the sender.
    receiver.forget_peer(&s_fp).unwrap();

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
    .expect("send timeout");

    match outcome {
        Err(privet_core::CoreError::Transfer(
            privet_transfer::TransferError::Rejected(reason),
        )) => {
            assert_eq!(reason, "peer_not_trusted");
        }
        Ok(_) => panic!("expected a rejection, got a success"),
        Err(other) => panic!("expected a rejection, got {other}"),
    }

    // The failed send leaves a terminal 'failed' history row (not a forever
    // 'partial') so it is visible in History and resendable.
    let rows = sender.history(None, 10).unwrap();
    let row = rows
        .iter()
        .find(|r| r.status == "failed")
        .expect("failed send has a failed history row");
    assert_eq!(row.direction, "send");

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

/// Ground truth for the receiver-side display bug: during a normal auto-accept
/// send, the receiver must emit TransferOffered, then TransferProgress (once
/// verified bytes are known), then TransferCompleted — so the GUI tile can
/// advance past 0% and terminate. If any of these are missing, the tile would
/// stick at 0% forever.
#[tokio::test]
async fn receiver_emits_offered_progress_completed() {
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
                subnet_cidr: "127.0.0.1/32",
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

    // Subscribe to the RECEIVER's events before the transfer starts.
    let mut recv_events = receiver.subscribe();

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

    // Big enough to guarantee the receiver is mid-flight when progress ticks.
    let src = dir.path().join("big.bin");
    std::fs::write(&src, vec![7u8; 8 * 1024 * 1024]).unwrap();

    let mut target_addr = serve.quic_addr;
    target_addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
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

    // Drain the receiver events until we see Offered, Progress and Completed
    // (in any order, but all three must appear).
    let mut saw_offered = false;
    let mut saw_progress = false;
    let mut saw_completed = false;
    let mut progress_bytes = 0u64;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(
            Duration::from_secs(2),
            recv_events.recv(),
        )
        .await
        {
            Ok(Ok(privet_core::EngineEvent::TransferOffered { .. })) => saw_offered = true,
            Ok(Ok(privet_core::EngineEvent::TransferProgress {
                verified_bytes, ..
            })) => {
                saw_progress = true;
                progress_bytes = progress_bytes.max(verified_bytes);
            }
            Ok(Ok(privet_core::EngineEvent::TransferCompleted { .. })) => {
                saw_completed = true;
                break;
            }
            Ok(Ok(_)) => {}
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_)))
            | Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {}
            Err(_) => break,
        }
    }

    assert!(saw_offered, "receiver must emit TransferOffered");
    assert!(
        saw_progress && progress_bytes > 0,
        "receiver must emit TransferProgress with verified_bytes > 0 (got {progress_bytes})"
    );
    assert!(
        saw_completed,
        "receiver must emit TransferCompleted (otherwise the GUI tile freezes)"
    );

    // The completed receive must leave the daemon's active-transfer registry
    // empty — if the transfer stayed registered, the GUI's reconcile would keep
    // its tile forever ("can't cancel, doesn't disappear").
    assert!(
        receiver.active_transfer_ids().is_empty(),
        "completed receive must unregister from the active-transfer registry"
    );

    serve.shutdown().await;
    let _ = receiver.shutdown().await;
}

/// Regression pin for WP-R9 (progress stuck at 0% on fast receives).
///
/// Unlike `receiver_emits_offered_progress_completed`, this test does not just
/// require *a* progress event: it requires the event to be ordered **before**
/// the terminal `TransferCompleted`, which is what actually lets a GUI tile
/// advance and then terminate. A 4 MiB receive over loopback finishes far
/// inside the receiver's 1s progress throttle, so this is the fast path.
///
/// How this assertion can fail (i.e. what it is protecting):
///  * if the first progress report is gated behind the 1s throttle, a fast
///    receive reaches `Completed` with no progress at all -> `progress_idx`
///    stays `None`;
///  * if progress is only emitted from the data-frame path, the chunks that
///    arrive before their `SegmentManifest` are verified inside `on_manifest`
///    (the control path), which never reports -> same failure;
///  * if a report is emitted only *after* `Completed`, `progress_idx >=
///    completed_idx` and the tile still never advances.
#[tokio::test]
async fn fast_receive_reports_verified_bytes_before_completed() {
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
                subnet_cidr: "127.0.0.1/32",
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

    let mut recv_events = receiver.subscribe();
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

    // 4 MiB: well above the 64 KiB inline threshold (so the chunked/manifest
    // path runs) but small enough to complete well inside the 1s throttle.
    const SIZE: usize = 4 * 1024 * 1024;
    let src = dir.path().join("fast.bin");
    std::fs::write(&src, vec![9u8; SIZE]).unwrap();

    let mut target_addr = serve.quic_addr;
    target_addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
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

    // Record the ordered event sequence until Completed.
    let mut seq: Vec<(&'static str, u64, u64)> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), recv_events.recv()).await {
            Ok(Ok(privet_core::EngineEvent::TransferProgress {
                verified_bytes,
                total_bytes,
                ..
            })) => seq.push(("progress", verified_bytes, total_bytes)),
            Ok(Ok(privet_core::EngineEvent::TransferCompleted { .. })) => {
                seq.push(("completed", 0, 0));
                break;
            }
            Ok(Ok(_)) => {}
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_)))
            | Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {}
            Err(_) => break,
        }
    }

    let completed_idx = seq.iter().position(|(k, _, _)| *k == "completed");
    assert!(
        completed_idx.is_some(),
        "receiver must emit TransferCompleted; saw sequence {seq:?}"
    );
    let completed_idx = completed_idx.unwrap();

    let progress_idx = seq
        .iter()
        .position(|(k, v, _)| *k == "progress" && *v > 0);
    assert!(
        progress_idx.is_some(),
        "receiver must report TransferProgress with verified_bytes > 0 before Completed; saw {seq:?}"
    );
    let progress_idx = progress_idx.unwrap();

    assert!(
        progress_idx < completed_idx,
        "progress with verified_bytes > 0 must precede TransferCompleted so the GUI tile advances \
         then terminates; progress at {progress_idx}, completed at {completed_idx}; saw {seq:?}"
    );

    // The reported totals must stay truthful: the byte count is clamped to the
    // advertised total, and the total itself is the offer's size.
    let (_, verified, total) = seq[progress_idx];
    assert!(
        verified <= total,
        "verified_bytes must be clamped to total_bytes (got {verified} > {total})"
    );
    assert_eq!(
        total, SIZE as u64,
        "progress must advertise the offer's total_bytes"
    );

    serve.shutdown().await;
    let _ = receiver.shutdown().await;
}
