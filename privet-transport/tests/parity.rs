
mod common;

use privet_transport::{QuicTransport, TcpTransport, Transport, TransportKind, TransportMode};

async fn connect_kind(t: &dyn Transport, addr: std::net::SocketAddr, mode: TransportMode) {
    let listener = t.bind(addr).await.unwrap();
    let bound = listener.local_addr().await.unwrap();
    let _srv = tokio::spawn(async move {
        let _conn = listener.accept().await;
    });
    let client = t.connect(bound, mode, None).await.unwrap();
    let kind = client.kind();
    match mode {
        TransportMode::Quic => assert_eq!(kind, TransportKind::Quic),
        TransportMode::Tcp => assert_eq!(kind, TransportKind::Tcp),
        _ => {}
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn quic_and_tcp_both_connect_and_report_kind() {
    let mat = common::test_tls_material();
    let quic = QuicTransport::new(mat.clone(), Default::default());
    let tcp = TcpTransport::new(mat, Default::default());
    connect_kind(&quic, "127.0.0.1:0".parse().unwrap(), TransportMode::Quic).await;
    connect_kind(&tcp, "127.0.0.1:0".parse().unwrap(), TransportMode::Tcp).await;
}
