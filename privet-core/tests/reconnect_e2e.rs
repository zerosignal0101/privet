//! 重连 e2e ——传输断开 -> 退避 -> 重连 -> resume。
//!
//! `backoff_exhausted_pauses` 验证退避耗尽时返回 TransportLost。
//! `drop_mid_transfer_then_resume` 验证跨连接 resume 位图传递（双阶段 receiver：bad→drop→good→续传）。
//! `crash_recovery_scans_part` 验证孤儿对账清理。
use std::sync::Arc;
use std::time::Duration;

use privet_core::connection::{
    acquire_control, acquire_data, hello_exchange_responder, ControlRole, DataRole,
};
use privet_core::identity_tls::build_tls_material;
use privet_core::reconnect::Backoff;
use privet_core::transfer::receive_over_connection;
use privet_core::transfer::send_with_reconnect;
use privet_core::EngineEvent;
use privet_crypto::identity::Identity;
use privet_transfer::control::AcceptPolicy;
use privet_transfer::prepare::prepare_dir;
use privet_transfer::CollisionPolicy;
use privet_transfer::FsPartStore;
use privet_transfer::TransferEngineConfig;
use privet_transport::{QuicTransport, Transport, TransportMode};
use tempfile::TempDir;

/// 退避耗尽：receiver accept 后建立流再立即 drop（模拟崩溃后对端不归），
/// sender 的 send_with_reconnect 在退避耗尽后返回 TransportLost。
#[tokio::test]
async fn backoff_exhausted_pauses_reconnect_exhausted() {
    let srv_id = Identity::generate().unwrap();
    let cli_id = Identity::generate().unwrap();

    let cfg = privet_transport::config::TransportConfigPrivet::default();
    let srv_quic = Arc::new(QuicTransport::new(
        build_tls_material(&srv_id).unwrap(),
        cfg.clone(),
    ));
    let cli_quic = Arc::new(QuicTransport::new(
        build_tls_material(&cli_id).unwrap(),
        cfg,
    ));

    let listener = srv_quic.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().await.unwrap();

    let src = TempDir::new().unwrap();
    let payload = b"reconnect test content";
    std::fs::write(src.path().join("rc.txt"), payload).unwrap();
    let save_dir = TempDir::new().unwrap();
    let transfer_cfg = TransferEngineConfig {
        save_dir: save_dir.path().to_path_buf(),
        ..Default::default()
    };
    let (etx, _erx) = tokio::sync::broadcast::channel::<privet_core::EngineEvent>(64);
    let prepared = prepare_dir(src.path(), None, 0, 1024 * 1024, 1024).unwrap();

    // receiver：循环 accept -> 建流 -> 丢（模拟崩溃）。
    // sender 的 acquire_control/acquire_data 可成功（流已建），
    // 但 run_sender 时连接断开 -> TransportLost -> 退避循环。
    // 无限循环：select! 会在 sender 耗尽时取消此 future。
    let accept = async {
        loop {
            let bad_conn = listener.accept().await.unwrap();
            // 须先建流让 sender 的 acquire_control/acquire_data 通过。
            let mut bad_ctrl = acquire_control(bad_conn.as_ref(), ControlRole::Responder)
                .await
                .unwrap();
            // send_with_reconnect 现在内含 hello_exchange，应答方须回应。
            let _ = privet_core::connection::hello_exchange_responder(
                bad_ctrl.as_mut(),
                &srv_id,
                1,
                "srv",
                "windows"
            )
            .await;
            let bad_data = acquire_data(bad_conn.as_ref(), DataRole::Responder)
                .await
                .unwrap();
            drop(bad_data);
            drop(bad_ctrl);
            drop(bad_conn);
        }
    };

    // sender：3 次退避（1ms each），耗尽后返回 TransportLost。
    let send = async {
        let mut backoff = Backoff::with_schedule(vec![
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
        ]);
        send_with_reconnect(
            cli_quic.as_ref() as &dyn Transport,
            None,
            addr,
            TransportMode::Quic,
            &cli_id,
            "cli",
            prepared,
            transfer_cfg,
            etx,
            "tx_rc".into(),
            &mut backoff,
            None,
        )
        .await
    };

    let result = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::select! {
            r = send => r,
            _ = accept => unreachable!("accept must not complete before send exhausts backoff"),
        }
    })
    .await
    .expect("send_with_reconnect timed out - should have exhausted in <30s");
    assert!(
        matches!(
            result,
            Err(privet_core::CoreError::Transfer(
                privet_transfer::TransferError::TransportLost
            ))
        ),
        "expected TransportLost after backoff exhaustion, got {:?}",
        result
    );
}

/// 崩溃恢复：staging 目录有遗留 .part（无对应 DB partial）-> 孤儿对账清理。
#[tokio::test]
async fn crash_recovery_scans_part_and_reconciles() {
    use privet_core::transfer::recover_partial_transfers;
    use privet_storage::migration::open_and_migrate;
    let save_dir = TempDir::new().unwrap();
    // 造 staging 目录结构: save_dir/.privet/tx_id/orphan.part（无对应 .part.meta = 孤儿）
    let staging = save_dir.path().join(".privet").join("orphan_tx");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(staging.join("orphan.part"), b"x").unwrap();
    let conn = open_and_migrate(":memory:").unwrap();
    recover_partial_transfers(save_dir.path(), &conn).unwrap();
    // 孤儿被清理。
    assert!(
        !staging.join("orphan.part").exists(),
        "orphan .part must be removed"
    );
}

/// 断连中段 -> 重连 -> resume 位图跨连接传递
/// 双阶段 receiver：round1 收 ≥1 块后 drop；sender send_with_reconnect 退避后重连；
/// round2 完成剩余。事件流验证 TransferReconnecting + 续传基线 Progress。
#[tokio::test]
async fn drop_mid_transfer_then_resume() {
    let srv_id = Identity::generate().unwrap();
    let cli_id = Identity::generate().unwrap();

    let tr_cfg = privet_transport::config::TransportConfigPrivet::default();
    let srv_quic = Arc::new(QuicTransport::new(
        build_tls_material(&srv_id).unwrap(),
        tr_cfg.clone(),
    ));
    let cli_quic = Arc::new(QuicTransport::new(
        build_tls_material(&cli_id).unwrap(),
        tr_cfg,
    ));

    let listener = srv_quic.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().await.unwrap();

    let src = TempDir::new().unwrap();
    let save = TempDir::new().unwrap();
    let save_path = save.path().to_path_buf();
    // 10 MiB / 1 MiB chunk = 10 块（确保 round1 drop 前传输未完成）。
    let data: Vec<u8> = (0..10_000_000u64).map(|i| (i % 251) as u8).collect();
    std::fs::write(src.path().join("resume.bin"), &data).unwrap();

    let transfer_cfg = TransferEngineConfig {
        save_dir: save.path().to_path_buf(),
        on_collision: CollisionPolicy::Overwrite,
        ..Default::default()
    };
    let prepared = prepare_dir(src.path(), None, 0, 1024 * 1024, 1024).unwrap();

    let (etx, _erx) = tokio::sync::broadcast::channel::<EngineEvent>(256);
    let etx_clone = etx.clone();

    // 事件收集器（容错 Lagged，持续运行）。
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let ev_captured = events.clone();
    let mut erx_sub = etx.subscribe();
    let collector = tokio::spawn(async move {
        loop {
            match erx_sub.recv().await {
                Ok(e) => ev_captured.lock().unwrap().push(e),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let recv_cfg = transfer_cfg.clone();
    let recv_save = save_path.clone();
    let recv_task = tokio::spawn(async move {
        let local_id = Identity::generate().unwrap();

        // === Round 1：收到 ≥1 个块后 drop 连接 ===
        let conn1 = listener.accept().await.unwrap();
        let mut ctrl1 = acquire_control(conn1.as_ref(), ControlRole::Responder)
            .await
            .unwrap();
        hello_exchange_responder(ctrl1.as_mut(), &local_id, 1, "srv", "windows")
            .await
            .unwrap();
        let data1 = acquire_data(conn1.as_ref(), DataRole::Responder)
            .await
            .unwrap();

        let mut r1 = tokio::spawn(receive_over_connection(
            ctrl1,
            data1,
            FsPartStore::new(recv_save.clone()),
            recv_cfg.clone(),
            etx.clone(),
            None,
            AcceptPolicy::AutoAccept,
        ));

        // 等 staging 目录出现（数据到达），再等 100ms 让 ≥1 块落盘，然后 abort round 1。
        let stage_dir = recv_save.join(".privet").join("t_resume");
        let wait_for_data = async {
            loop {
                if stage_dir.exists() {
                    if let Ok(rd) = std::fs::read_dir(&stage_dir) {
                        for e in rd.flatten() {
                            if e.path().extension().and_then(|s| s.to_str()) == Some("part")
                                && e.metadata().map(|m| m.len()).unwrap_or(0) >= 1_048_576
                            {
                                return;
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::select! {
            _ = &mut r1 => { return; } // 传输快完成，走正常路径
            _ = wait_for_data => {}
        }
        // 断开连接 + abort receiver
        drop(conn1);
        r1.abort();
        tokio::time::sleep(Duration::from_millis(500)).await; // 给 sender 退避 + 重连窗口

        // === Round 2：续传完成剩余块 ===
        let conn2 = listener.accept().await.unwrap();
        let mut ctrl2 = acquire_control(conn2.as_ref(), ControlRole::Responder)
            .await
            .unwrap();
        hello_exchange_responder(ctrl2.as_mut(), &local_id, 1, "srv", "windows")
            .await
            .unwrap();
        let data2 = acquire_data(conn2.as_ref(), DataRole::Responder)
            .await
            .unwrap();
        receive_over_connection(
            ctrl2,
            data2,
            FsPartStore::new(recv_save),
            recv_cfg,
            etx,
            None,
            AcceptPolicy::AutoAccept,
        )
        .await
        .unwrap();
        // 200ms drain 延迟：让 sender 在 stream 关闭前收完 TransferVerified ack
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    // === 发送方：短退避表（100ms × 6）→ 自动重连续传 ===
    let send_result = {
        let mut backoff = Backoff::with_schedule(vec![
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
        ]);
        send_with_reconnect(
            cli_quic.as_ref() as &dyn Transport,
            None,
            addr,
            TransportMode::Quic,
            &cli_id,
            "cli",
            prepared,
            transfer_cfg,
            etx_clone,
            "t_resume".into(),
            &mut backoff,
            None,
        )
        .await
    };

    // 停收集器
    tokio::time::sleep(Duration::from_millis(50)).await;
    collector.abort();
    let _ = collector.await;
    drop(recv_task);

    // === 断言 ===
    send_result.expect("send_with_reconnect must succeed after reconnect");

    // 文件内容正确（最终断言）。
    assert_eq!(
        std::fs::read(save_path.join("resume.bin")).unwrap(),
        data,
        "final file content must match"
    );

    // 事件流验证。
    let captured = events.lock().unwrap();

    // 必须含 TransferCompleted。
    let has_completed = captured
        .iter()
        .any(|e| matches!(e, EngineEvent::TransferCompleted { .. }));
    assert!(has_completed, "must emit TransferCompleted at end");

    // 含 TransferReconnecting（证明重连发生）。
    let has_reconnect = captured
        .iter()
        .any(|e| matches!(e, EngineEvent::TransferReconnecting { .. }));
    assert!(
        has_reconnect,
        "must emit TransferReconnecting after dropped connection"
    );

    // 含 TransferProgress 续传基线（证明 resume 位图跨连接传递、sender 跳过了已验块）。
    let has_resume_baseline = captured.iter().any(|e| {
        matches!(
            e,
            EngineEvent::TransferProgress {
                verified_bytes,
                ..
            } if *verified_bytes >= 1_048_576
        )
    });
    assert!(
        has_resume_baseline,
        "must emit TransferProgress with resume baseline >= 1 MiB after reconnect"
    );
}
