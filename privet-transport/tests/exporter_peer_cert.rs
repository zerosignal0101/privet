//! TCP exporter keying material agreement + peer_cert_der on both transports.
//! TCP 两侧导出密钥一致；QUIC 两侧均可持对端证书。

mod common;

use privet_transport::config::TransportConfigPrivet;
use privet_transport::transport::Transport;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn tcp_exporter_matches_both_sides() {
    let mat = common::test_tls_material();
    let tcp = privet_transport::TcpTransport::new(mat.clone(), TransportConfigPrivet::default());
    let listener = tcp.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().await.unwrap();

    let srv = async {
        let conn = listener.accept().await.unwrap();
        let e = conn
            .export_keying_material(b"privet-pairing-binding", Some(&[]))
            .expect("tcp server exporter");
        (e, conn.peer_cert_der())
    };
    let cli = async {
        let conn = tcp
            .connect(addr, privet_transport::TransportMode::Tcp, None)
            .await
            .unwrap();
        let e = conn
            .export_keying_material(b"privet-pairing-binding", Some(&[]))
            .expect("tcp client exporter");
        (e, conn.peer_cert_der())
    };

    let ((srv_exporter, srv_cert), (cli_exporter, cli_cert)) =
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(srv, cli) })
            .await
            .unwrap();

    assert_eq!(srv_exporter.len(), 32);
    assert_eq!(cli_exporter.len(), 32);
    assert_eq!(
        srv_exporter, cli_exporter,
        "TCP both sides agree on exporter (binding)"
    );
    assert!(cli_cert.is_some(), "TCP client must see server certificate");
    // 服务端 offer_client_auth=true, 客户端 with_client_auth_cert → 服务端可见客户端证书
    assert!(srv_cert.is_some(), "TCP server must see client certificate");
}

#[tokio::test(flavor = "multi_thread")]
async fn quic_both_sides_peer_cert_some() {
    use privet_transport::QuicTransport;

    let mat = common::test_tls_material();
    let mat2 = common::test_tls_material();
    let srv = QuicTransport::new(mat.clone(), TransportConfigPrivet::default());
    let listener = srv.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().await.unwrap();

    let srv = async {
        let conn = listener.accept().await.unwrap();
        conn.peer_cert_der()
    };
    let cli = async {
        let conn = QuicTransport::new(mat2, TransportConfigPrivet::default())
            .connect(addr, privet_transport::TransportMode::Quic, None)
            .await
            .unwrap();
        conn.peer_cert_der()
    };

    let (srv_cert, cli_cert) =
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(srv, cli) })
            .await
            .unwrap();

    assert!(
        cli_cert.is_some(),
        "QUIC client must see server certificate"
    );
    assert!(
        srv_cert.is_some(),
        "QUIC server must see client certificate"
    );
}
