//! End-to-end transfer orchestration tests.
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
            transfer_id: "tx1".into(),
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
        .expect("QUIC transfer timed out");
    s_result.expect("sender failed");
    r_result.expect("receiver failed");

    let landed = std::fs::read(save_dir.path().join("big.bin")).unwrap();
    assert_eq!(
        landed, payload,
        "landed file must match source byte-for-byte"
    );
}

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
