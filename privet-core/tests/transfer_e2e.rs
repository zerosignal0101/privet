//! Task C13/C15：真实 QUIC/TCP 上的传送 e2e（分块路径 / 内联快路径 / TCP 降级）。
//!
//! 关键点：
//! - QUIC 单向数据流（open_uni）仅本地分配，**不发送 STREAM frame**；
//!   sender 须写至少 1 字节数据后方发 STREAM frame，receiver 的 accept_uni 才能解析。
//!   → sender 在 run_sender 之前写一空 DataFrame（payload=None），receiver 的
//!   handle_data 遇到 None payload 为 no-op 跳过。
//! - TCP 单连接多路（stream_id 1 共享），无此问题，open_data_stream 即可。
use std::sync::Arc;
use std::time::Duration;

use privet_core::adapters::transfer_sink::CoreTransferEventSink;
use privet_core::connection::{acquire_control, acquire_data, ControlRole, DataRole};
use privet_core::identity_tls::build_tls_material;
use privet_crypto::identity::Identity;
use privet_protocol::DataFrame;
use privet_transfer::prepare::prepare_dir;
use privet_transfer::receiver::run_receiver;
use privet_transfer::sender::{run_sender, MappedChunkReader, SenderInputs};
use privet_transfer::{
    FsPartStore, ReceiverInputs, StreamControlChannel, StreamDataChannel, TransferEngineConfig,
};
use privet_transport::{send_data, QuicTransport, TcpTransport, Transport, TransportMode};
use tempfile::TempDir;

/// 分块文件（>64KiB，单段单块）经 QUIC 单向数据流传送 e2e。
#[tokio::test]
async fn send_chunked_file_over_quic() {
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

    // 源文件：>64KiB -> 走分块路径（非内联）。
    let src = TempDir::new().unwrap();
    let payload: Vec<u8> = (0..70_000).map(|i| (i % 251) as u8).collect();
    std::fs::write(src.path().join("big.bin"), &payload).unwrap();

    let save_dir = TempDir::new().unwrap();
    let store = FsPartStore::new(save_dir.path().to_path_buf());
    let transfer_cfg = TransferEngineConfig {
        save_dir: save_dir.path().to_path_buf(),
        ..Default::default()
    };
    let (etx, _erx) = tokio::sync::broadcast::channel::<privet_core::EngineEvent>(64);
    let etx_send = etx.clone();

    let prepared = prepare_dir(src.path(), None, 0, 1024 * 1024, 1024).unwrap();

    let accept = async {
        let conn = listener.accept().await.unwrap();
        let ctrl = acquire_control(conn.as_ref(), ControlRole::Responder)
            .await
            .unwrap();
        let data = acquire_data(conn.as_ref(), DataRole::Responder)
            .await
            .unwrap();
        let inputs = ReceiverInputs {
            control: Box::new(StreamControlChannel::new(ctrl)),
            data: vec![Box::new(StreamDataChannel::new(data))],
            store: Box::new(store),
            events: Box::new(CoreTransferEventSink::new(etx)),
            config: transfer_cfg.clone(),
            accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
            registry: None,
        };
        let result = run_receiver(inputs).await;
        // 保持 conn 不 drop（配对 e2e 同模式）：防止 premature close 破坏 sender 侧操作。
        (result, conn)
    };

    let send = async {
        let conn = cli_quic
            .connect(addr, TransportMode::Quic, None)
            .await
            .unwrap();
        let ctrl = acquire_control(conn.as_ref(), ControlRole::Initiator)
            .await
            .unwrap();
        let mut data = acquire_data(conn.as_ref(), DataRole::Initiator)
            .await
            .unwrap();
        // QUIC 单向流：open_uni 仅本地分配，不发送 STREAM frame。
        // 须写数据后方发 STREAM frame，receiver 的 accept_uni 才能解析。
        send_data(data.as_mut(), &DataFrame { payload: None }, None)
            .await
            .unwrap();
        let reader = Box::new(MappedChunkReader::from_prepared(&prepared));
        let inputs = SenderInputs {
            control: Box::new(StreamControlChannel::new(ctrl)),
            data: vec![Box::new(StreamDataChannel::new(data))],
            events: Box::new(CoreTransferEventSink::new(etx_send)),
            config: transfer_cfg.clone(),
            prepared,
            reader,
            transfer_id: "tx1".into(),
            cmd_rx: None,
        };
        let result = run_sender(inputs).await;
        // 保持 conn 不 drop，与 accept 对称。
        (result, conn)
    };

    let ((s_result, _s_conn), (r_result, _r_conn)) =
        tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(send, accept)
        })
        .await
        .expect("QUIC transfer timed out");
    s_result.expect("sender failed");
    r_result.expect("receiver failed");

    let landed = std::fs::read(save_dir.path().join("big.bin")).unwrap();
    assert_eq!(
        landed, payload,
        "landed file must match source byte-for-byte"
    );
}

/// 内联文件（≤64KiB 快路径）经 TCP 单连接多路传送 e2e（TCP 降级路径）。
#[tokio::test]
async fn send_inline_file_over_tcp() {
    let srv_id = Identity::generate().unwrap();
    let cli_id = Identity::generate().unwrap();

    let cfg = privet_transport::config::TransportConfigPrivet::default();
    let srv_tcp = Arc::new(TcpTransport::new(
        build_tls_material(&srv_id).unwrap(),
        cfg.clone(),
    ));
    let cli_tcp = Arc::new(TcpTransport::new(build_tls_material(&cli_id).unwrap(), cfg));

    let listener = srv_tcp.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().await.unwrap();

    // 源文件：≤64KiB -> 走内联快路径（单数据帧，不分块）。
    let src = TempDir::new().unwrap();
    let payload = b"hello privet core over tcp";
    std::fs::write(src.path().join("hi.txt"), payload).unwrap();

    let save_dir = TempDir::new().unwrap();
    let store = FsPartStore::new(save_dir.path().to_path_buf());
    let transfer_cfg = TransferEngineConfig {
        save_dir: save_dir.path().to_path_buf(),
        ..Default::default()
    };
    let (etx, _erx) = tokio::sync::broadcast::channel::<privet_core::EngineEvent>(64);
    let etx_send = etx.clone();

    let prepared = prepare_dir(src.path(), None, 0, 1024 * 1024, 1024).unwrap();

    let accept = async {
        let conn = listener.accept().await.unwrap();
        let ctrl = acquire_control(conn.as_ref(), ControlRole::Responder)
            .await
            .unwrap();
        let data = acquire_data(conn.as_ref(), DataRole::Responder)
            .await
            .unwrap();
        let inputs = ReceiverInputs {
            control: Box::new(StreamControlChannel::new(ctrl)),
            data: vec![Box::new(StreamDataChannel::new(data))],
            store: Box::new(store),
            events: Box::new(CoreTransferEventSink::new(etx)),
            config: transfer_cfg.clone(),
            accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
            registry: None,
        };
        run_receiver(inputs).await
    };

    let send = async {
        let conn = cli_tcp
            .connect(addr, TransportMode::Tcp, None)
            .await
            .unwrap();
        let ctrl = acquire_control(conn.as_ref(), ControlRole::Initiator)
            .await
            .unwrap();
        let data = acquire_data(conn.as_ref(), DataRole::Initiator)
            .await
            .unwrap();
        let reader = Box::new(MappedChunkReader::from_prepared(&prepared));
        let inputs = SenderInputs {
            control: Box::new(StreamControlChannel::new(ctrl)),
            data: vec![Box::new(StreamDataChannel::new(data))],
            events: Box::new(CoreTransferEventSink::new(etx_send)),
            config: transfer_cfg.clone(),
            prepared,
            reader,
            transfer_id: "tx2".into(),
            cmd_rx: None,
        };
        run_sender(inputs).await
    };

    let (s, r) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(send, accept)
    })
    .await
    .expect("TCP transfer timed out");
    s.expect("sender failed");
    r.expect("receiver failed");

    let landed = std::fs::read(save_dir.path().join("hi.txt")).unwrap();
    assert_eq!(landed, payload, "landed file must match source");
}

/// 目录结构（含嵌套子目录）经 QUIC 单向数据流传送 e2e。
#[tokio::test]
async fn send_directory_over_quic() {
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

    // 源目录：根文件 + 子目录文件。
    let src = TempDir::new().unwrap();
    let payload_a = b"file a content";
    let payload_b = b"file b content in subdir";
    std::fs::write(src.path().join("a.txt"), payload_a).unwrap();
    let sub = src.path().join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("b.txt"), payload_b).unwrap();

    let save_dir = TempDir::new().unwrap();
    let store = FsPartStore::new(save_dir.path().to_path_buf());
    let transfer_cfg = TransferEngineConfig {
        save_dir: save_dir.path().to_path_buf(),
        ..Default::default()
    };
    let (etx, _erx) = tokio::sync::broadcast::channel::<privet_core::EngineEvent>(64);
    let etx_send = etx.clone();

    let prepared = prepare_dir(src.path(), Some("root"), 0, 1024 * 1024, 1024).unwrap();

    let accept = async {
        let conn = listener.accept().await.unwrap();
        let ctrl = acquire_control(conn.as_ref(), ControlRole::Responder)
            .await
            .unwrap();
        let data = acquire_data(conn.as_ref(), DataRole::Responder)
            .await
            .unwrap();
        let inputs = ReceiverInputs {
            control: Box::new(StreamControlChannel::new(ctrl)),
            data: vec![Box::new(StreamDataChannel::new(data))],
            store: Box::new(store),
            events: Box::new(CoreTransferEventSink::new(etx)),
            config: transfer_cfg.clone(),
            accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
            registry: None,
        };
        let result = run_receiver(inputs).await;
        (result, conn)
    };

    let send = async {
        let conn = cli_quic
            .connect(addr, TransportMode::Quic, None)
            .await
            .unwrap();
        let ctrl = acquire_control(conn.as_ref(), ControlRole::Initiator)
            .await
            .unwrap();
        let mut data = acquire_data(conn.as_ref(), DataRole::Initiator)
            .await
            .unwrap();
        send_data(data.as_mut(), &DataFrame { payload: None }, None)
            .await
            .unwrap();
        let reader = Box::new(MappedChunkReader::from_prepared(&prepared));
        let inputs = SenderInputs {
            control: Box::new(StreamControlChannel::new(ctrl)),
            data: vec![Box::new(StreamDataChannel::new(data))],
            events: Box::new(CoreTransferEventSink::new(etx_send)),
            config: transfer_cfg.clone(),
            prepared,
            reader,
            transfer_id: "tx_dir".into(),
            cmd_rx: None,
        };
        let result = run_sender(inputs).await;
        (result, conn)
    };

    let ((s_result, _s_conn), (r_result, _r_conn)) =
        tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(send, accept)
        })
        .await
        .expect("dir QUIC transfer timed out");
    s_result.expect("sender failed");
    r_result.expect("receiver failed");

    let landed_a = std::fs::read(save_dir.path().join("root").join("a.txt")).unwrap();
    assert_eq!(landed_a, payload_a, "root file mismatch");
    let landed_b = std::fs::read(save_dir.path().join("root").join("sub").join("b.txt")).unwrap();
    assert_eq!(landed_b, payload_b, "nested file mismatch");
}

/// 64KiB 边界：内联（≤65536 字节，快路径单帧）与分块（≥65537 字节，首块）经 QUIC 传送 e2e。
#[tokio::test]
async fn inline_boundary_64kib_and_plus1() {
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

    // 两个文件：65536 字节（内联）和 65537 字节（1 块）。
    let src = TempDir::new().unwrap();
    let inline_payload: Vec<u8> = (0..65536).map(|i| i as u8).collect();
    let chunked_payload: Vec<u8> = (0..65537).map(|i| (i ^ 0xaa) as u8).collect();
    std::fs::write(src.path().join("inline.bin"), &inline_payload).unwrap();
    std::fs::write(src.path().join("chunked.bin"), &chunked_payload).unwrap();

    let save_dir = TempDir::new().unwrap();
    let store = FsPartStore::new(save_dir.path().to_path_buf());
    let transfer_cfg = TransferEngineConfig {
        save_dir: save_dir.path().to_path_buf(),
        ..Default::default()
    };
    let (etx, _erx) = tokio::sync::broadcast::channel::<privet_core::EngineEvent>(64);
    let etx_send = etx.clone();

    let prepared = prepare_dir(src.path(), None, 0, 1024 * 1024, 1024).unwrap();

    let accept = async {
        let conn = listener.accept().await.unwrap();
        let ctrl = acquire_control(conn.as_ref(), ControlRole::Responder)
            .await
            .unwrap();
        let data = acquire_data(conn.as_ref(), DataRole::Responder)
            .await
            .unwrap();
        let inputs = ReceiverInputs {
            control: Box::new(StreamControlChannel::new(ctrl)),
            data: vec![Box::new(StreamDataChannel::new(data))],
            store: Box::new(store),
            events: Box::new(CoreTransferEventSink::new(etx)),
            config: transfer_cfg.clone(),
            accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
            registry: None,
        };
        let result = run_receiver(inputs).await;
        (result, conn)
    };

    let send = async {
        let conn = cli_quic
            .connect(addr, TransportMode::Quic, None)
            .await
            .unwrap();
        let ctrl = acquire_control(conn.as_ref(), ControlRole::Initiator)
            .await
            .unwrap();
        let mut data = acquire_data(conn.as_ref(), DataRole::Initiator)
            .await
            .unwrap();
        send_data(data.as_mut(), &DataFrame { payload: None }, None)
            .await
            .unwrap();
        let reader = Box::new(MappedChunkReader::from_prepared(&prepared));
        let inputs = SenderInputs {
            control: Box::new(StreamControlChannel::new(ctrl)),
            data: vec![Box::new(StreamDataChannel::new(data))],
            events: Box::new(CoreTransferEventSink::new(etx_send)),
            config: transfer_cfg.clone(),
            prepared,
            reader,
            transfer_id: "tx_boundary".into(),
            cmd_rx: None,
        };
        let result = run_sender(inputs).await;
        (result, conn)
    };

    let ((s_result, _s_conn), (r_result, _r_conn)) =
        tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(send, accept)
        })
        .await
        .expect("boundary QUIC transfer timed out");
    s_result.expect("sender failed");
    r_result.expect("receiver failed");

    let landed_inline = std::fs::read(save_dir.path().join("inline.bin")).unwrap();
    assert_eq!(landed_inline, inline_payload, "65536B inline file mismatch");
    let landed_chunked = std::fs::read(save_dir.path().join("chunked.bin")).unwrap();
    assert_eq!(
        landed_chunked, chunked_payload,
        "65537B chunked file mismatch"
    );
}

/// 分块文件经 TCP 单连接多路传送 e2e（TCP 降级路径 + 大分块）。
#[tokio::test]
async fn send_chunked_file_over_tcp() {
    let srv_id = Identity::generate().unwrap();
    let cli_id = Identity::generate().unwrap();

    let cfg = privet_transport::config::TransportConfigPrivet::default();
    let srv_tcp = Arc::new(TcpTransport::new(
        build_tls_material(&srv_id).unwrap(),
        cfg.clone(),
    ));
    let cli_tcp = Arc::new(TcpTransport::new(build_tls_material(&cli_id).unwrap(), cfg));

    let listener = srv_tcp.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().await.unwrap();

    // 源文件：>64KiB -> 走分块路径。
    let src = TempDir::new().unwrap();
    let payload: Vec<u8> = (0..70_000).map(|i| (i % 251) as u8).collect();
    std::fs::write(src.path().join("tcp_big.bin"), &payload).unwrap();

    let save_dir = TempDir::new().unwrap();
    let store = FsPartStore::new(save_dir.path().to_path_buf());
    let transfer_cfg = TransferEngineConfig {
        save_dir: save_dir.path().to_path_buf(),
        ..Default::default()
    };
    let (etx, _erx) = tokio::sync::broadcast::channel::<privet_core::EngineEvent>(64);
    let etx_send = etx.clone();

    let prepared = prepare_dir(src.path(), None, 0, 1024 * 1024, 1024).unwrap();

    let accept = async {
        let conn = listener.accept().await.unwrap();
        let ctrl = acquire_control(conn.as_ref(), ControlRole::Responder)
            .await
            .unwrap();
        let data = acquire_data(conn.as_ref(), DataRole::Responder)
            .await
            .unwrap();
        let inputs = ReceiverInputs {
            control: Box::new(StreamControlChannel::new(ctrl)),
            data: vec![Box::new(StreamDataChannel::new(data))],
            store: Box::new(store),
            events: Box::new(CoreTransferEventSink::new(etx)),
            config: transfer_cfg.clone(),
            accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
            registry: None,
        };
        run_receiver(inputs).await
    };

    let send = async {
        let conn = cli_tcp
            .connect(addr, TransportMode::Tcp, None)
            .await
            .unwrap();
        let ctrl = acquire_control(conn.as_ref(), ControlRole::Initiator)
            .await
            .unwrap();
        let data = acquire_data(conn.as_ref(), DataRole::Initiator)
            .await
            .unwrap();
        let reader = Box::new(MappedChunkReader::from_prepared(&prepared));
        let inputs = SenderInputs {
            control: Box::new(StreamControlChannel::new(ctrl)),
            data: vec![Box::new(StreamDataChannel::new(data))],
            events: Box::new(CoreTransferEventSink::new(etx_send)),
            config: transfer_cfg.clone(),
            prepared,
            reader,
            transfer_id: "tx_tcp".into(),
            cmd_rx: None,
        };
        run_sender(inputs).await
    };

    let (s, r) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(send, accept)
    })
    .await
    .expect("TCP chunked transfer timed out");
    s.expect("sender failed");
    r.expect("receiver failed");

    let landed = std::fs::read(save_dir.path().join("tcp_big.bin")).unwrap();
    assert_eq!(
        landed, payload,
        "landed file must match source byte-for-byte"
    );
}

/// 大文件（64MiB = 2 发送窗口）经真实 QUIC 传送 e2e。
/// 验证选择性重传修复在真实 QUIC 链路上不退化：多段多窗口下无洪泛、无 ChunkCorrupt、
/// 无停滞。loopback 虽然快（RTO 不触发），但完整的协议路径（流打开/控制通道/数据通道/
/// 选段布局/位图）均被覆盖。
#[tokio::test]
async fn large_file_over_quic() {
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

    // 64 MiB = 2 个发送窗口（64 chunks × 1 MiB），跨 window boundary。
    let src = TempDir::new().unwrap();
    let payload: Vec<u8> = (0..64u64 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    std::fs::write(src.path().join("qlarge.bin"), &payload).unwrap();

    let save_dir = TempDir::new().unwrap();
    let store = FsPartStore::new(save_dir.path().to_path_buf());
    let transfer_cfg = TransferEngineConfig {
        save_dir: save_dir.path().to_path_buf(),
        ..Default::default()
    };
    let (etx, _erx) = tokio::sync::broadcast::channel::<privet_core::EngineEvent>(64);
    let etx_send = etx.clone();

    let prepared = prepare_dir(src.path(), None, 0, 1024 * 1024, 1024).unwrap();

    let accept = async {
        let conn = listener.accept().await.unwrap();
        let ctrl = acquire_control(conn.as_ref(), ControlRole::Responder)
            .await
            .unwrap();
        let data = acquire_data(conn.as_ref(), DataRole::Responder)
            .await
            .unwrap();
        // QUIC 单向流：须先发一空帧触发 receiver accept_uni 响应
        let inputs = ReceiverInputs {
            control: Box::new(StreamControlChannel::new(ctrl)),
            data: vec![Box::new(StreamDataChannel::new(data))],
            store: Box::new(store),
            events: Box::new(CoreTransferEventSink::new(etx)),
            config: transfer_cfg.clone(),
            accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
            registry: None,
        };
        let result = run_receiver(inputs).await;
        (result, conn)
    };

    let send = async {
        let conn = cli_quic
            .connect(addr, TransportMode::Quic, None)
            .await
            .unwrap();
        let ctrl = acquire_control(conn.as_ref(), ControlRole::Initiator)
            .await
            .unwrap();
        let mut data = acquire_data(conn.as_ref(), DataRole::Initiator)
            .await
            .unwrap();
        send_data(data.as_mut(), &DataFrame { payload: None }, None)
            .await
            .unwrap();
        let reader = Box::new(MappedChunkReader::from_prepared(&prepared));
        let inputs = SenderInputs {
            control: Box::new(StreamControlChannel::new(ctrl)),
            data: vec![Box::new(StreamDataChannel::new(data))],
            events: Box::new(CoreTransferEventSink::new(etx_send)),
            config: transfer_cfg.clone(),
            prepared,
            reader,
            transfer_id: "tx_qlarge".into(),
            cmd_rx: None,
        };
        let result = run_sender(inputs).await;
        (result, conn)
    };

    let ((s_result, _s_conn), (r_result, _r_conn)) =
        tokio::time::timeout(Duration::from_secs(60), async {
            tokio::join!(send, accept)
        })
        .await
        .expect("QUIC large-file transfer timed out");
    s_result.expect("sender failed");
    r_result.expect("receiver failed");

    let landed = std::fs::read(save_dir.path().join("qlarge.bin")).unwrap();
    assert_eq!(landed, payload, "QUIC large file must match source");
}

/// 大文件（64MiB = 2 发送窗口）经真实 TCP 传送 e2e。
/// TCP 使用单连接双通道多路（stream_id 0 控制 / stream_id 1 数据），大文件下验证：
/// - 帧编解码无 desync（原为 33 块时 protobuf decode error / invalid key value）
/// - 控制/数据通道无互相阻塞
/// - 选择性重传在 TCP 路径上不引入退化
#[tokio::test]
async fn large_file_over_tcp() {
    let srv_id = Identity::generate().unwrap();
    let cli_id = Identity::generate().unwrap();

    let cfg = privet_transport::config::TransportConfigPrivet::default();
    let srv_tcp = Arc::new(TcpTransport::new(
        build_tls_material(&srv_id).unwrap(),
        cfg.clone(),
    ));
    let cli_tcp = Arc::new(TcpTransport::new(build_tls_material(&cli_id).unwrap(), cfg));

    let listener = srv_tcp.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().await.unwrap();

    let src = TempDir::new().unwrap();
    let payload: Vec<u8> = (0..64u64 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    std::fs::write(src.path().join("tcp_large.bin"), &payload).unwrap();

    let save_dir = TempDir::new().unwrap();
    let store = FsPartStore::new(save_dir.path().to_path_buf());
    let transfer_cfg = TransferEngineConfig {
        save_dir: save_dir.path().to_path_buf(),
        ..Default::default()
    };
    let (etx, _erx) = tokio::sync::broadcast::channel::<privet_core::EngineEvent>(64);
    let etx_send = etx.clone();

    let prepared = prepare_dir(src.path(), None, 0, 1024 * 1024, 1024).unwrap();

    let accept = async {
        let conn = listener.accept().await.unwrap();
        let ctrl = acquire_control(conn.as_ref(), ControlRole::Responder)
            .await
            .unwrap();
        let data = acquire_data(conn.as_ref(), DataRole::Responder)
            .await
            .unwrap();
        let inputs = ReceiverInputs {
            control: Box::new(StreamControlChannel::new(ctrl)),
            data: vec![Box::new(StreamDataChannel::new(data))],
            store: Box::new(store),
            events: Box::new(CoreTransferEventSink::new(etx)),
            config: transfer_cfg.clone(),
            accept_policy: privet_transfer::control::AcceptPolicy::AutoAccept,
            registry: None,
        };
        run_receiver(inputs).await
    };

    let send = async {
        let conn = cli_tcp
            .connect(addr, TransportMode::Tcp, None)
            .await
            .unwrap();
        let ctrl = acquire_control(conn.as_ref(), ControlRole::Initiator)
            .await
            .unwrap();
        let data = acquire_data(conn.as_ref(), DataRole::Initiator)
            .await
            .unwrap();
        let reader = Box::new(MappedChunkReader::from_prepared(&prepared));
        let inputs = SenderInputs {
            control: Box::new(StreamControlChannel::new(ctrl)),
            data: vec![Box::new(StreamDataChannel::new(data))],
            events: Box::new(CoreTransferEventSink::new(etx_send)),
            config: transfer_cfg.clone(),
            prepared,
            reader,
            transfer_id: "tx_tcp_large".into(),
            cmd_rx: None,
        };
        run_sender(inputs).await
    };

    let (s, r) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(send, accept)
    })
    .await
    .expect("TCP large-file transfer timed out");
    s.expect("sender failed");
    r.expect("receiver failed");

    let landed = std::fs::read(save_dir.path().join("tcp_large.bin")).unwrap();
    assert_eq!(landed, payload, "TCP large file must match source");
}
