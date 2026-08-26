//! QUIC client applies TransportConfigPrivet (idle timeout, BBR, stream pool).

mod common;

use privet_transport::config::{Congestion, TransportConfigPrivet};
use privet_transport::Transport;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn quic_client_with_custom_config_connects() {
    let mat = common::test_tls_material();
    let cfg = TransportConfigPrivet {
        idle_timeout: Duration::from_secs(60),
        stream_pool_size: 8,
        congestion: Congestion::Bbr,
        ..Default::default()
    };
    let transport = privet_transport::QuicTransport::new(mat, cfg);
    let listener = transport
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let bound = listener.local_addr().await.unwrap();

    let _srv = tokio::spawn(async move {
        let conn = listener.accept().await.unwrap();
        conn
    });

    // Client with the same custom config should connect
    let client = transport
        .connect(bound, privet_transport::TransportMode::Quic, None)
        .await
        .unwrap();
    assert_eq!(client.kind(), privet_transport::TransportKind::Quic);
    let streams = client.max_data_streams();
    assert!(streams >= 1);
}
