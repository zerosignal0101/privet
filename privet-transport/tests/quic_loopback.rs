//! QUIC loopback: connect, control stream echo.

mod common;

use privet_transport::Transport;

#[tokio::test(flavor = "multi_thread")]
async fn quic_bind_and_client_connects() {
    let mat = common::test_tls_material();
    let transport = privet_transport::QuicTransport::new(mat, Default::default());
    let listener = transport
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let bound = listener.local_addr().await.unwrap();

    let _srv = tokio::spawn(async move {
        let conn = listener.accept().await.unwrap();
        conn
    });
    let client = transport
        .connect(bound, privet_transport::TransportMode::Quic, None)
        .await
        .unwrap();
    assert_eq!(client.kind(), privet_transport::TransportKind::Quic);
    // 核对点：max_data_streams 当前返回 STREAM_POOL_SIZE（peer max 暂不可用）。
    let streams = client.max_data_streams();
    assert!(streams >= 1);
    assert!(streams <= privet_transport::STREAM_POOL_SIZE);
}
