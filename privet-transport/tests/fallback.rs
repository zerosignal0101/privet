//! PreferQuic 降级测试。

mod common;

use privet_transport::{QuicTransport, TcpTransport, Transport, TransportMode};

#[tokio::test(flavor = "multi_thread")]
async fn prefer_quic_falls_back_to_tcp_on_quic_failure() {
    let mat = common::test_tls_material();
    let tcp = TcpTransport::new(mat.clone(), Default::default());
    let tcp_listener = tcp.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let tcp_addr = tcp_listener.local_addr().await.unwrap();
    let _srv = tokio::spawn(async move {
        let _conn = tcp_listener.accept().await;
    });

    let quic = QuicTransport::new(mat, Default::default());
    let dead_quic_addr: std::net::SocketAddr = "127.0.0.1:55999".parse().unwrap();
    let conn = privet_transport::connect_with_fallback(
        &quic,
        Some(&tcp),
        dead_quic_addr,
        tcp_addr,
        TransportMode::PreferQuic,
        None,
    )
    .await
    .unwrap();
    assert_eq!(conn.kind(), privet_transport::TransportKind::Tcp);
}

#[tokio::test(flavor = "multi_thread")]
async fn quic_only_does_not_fallback() {
    let mat = common::test_tls_material();
    let quic = QuicTransport::new(mat, Default::default());
    let dead: std::net::SocketAddr = "127.0.0.1:55998".parse().unwrap();
    let res =
        privet_transport::connect_with_fallback(&quic, None, dead, dead, TransportMode::Quic, None)
            .await;
    assert!(res.is_err());
}
