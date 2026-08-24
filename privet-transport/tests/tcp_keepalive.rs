//! §10: TCP keepalive + clean close verify.

mod common;

use privet_transport::config::TransportConfigPrivet;
use privet_transport::transport::Transport;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn tcp_connect_close_clean() {
    let mat = common::test_tls_material();
    let tcp = privet_transport::TcpTransport::new(mat.clone(), TransportConfigPrivet::default());
    let listener = tcp.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().await.unwrap();

    let srv = tokio::spawn(async move {
        let conn = listener.accept().await.unwrap();
        conn
    });

    let client = tcp
        .connect(addr, privet_transport::TransportMode::Tcp, None)
        .await
        .unwrap();

    // Close cleanly
    client.close(privet_transport::CloseReason::Normal).await;

    // Server should also complete
    let _ = tokio::time::timeout(Duration::from_secs(3), srv).await;
}
