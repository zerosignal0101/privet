//! Exercise frame I/O through the concrete QUIC and TLS-over-TCP implementations.

mod common;

use privet_protocol::control_frame::Payload as ControlPayload;
use privet_protocol::data_frame::Payload as DataPayload;
use privet_protocol::{Cancel, ChunkHeader, ControlFrame, ControlMessage, DataFrame};
use privet_transport::{Connection, Transport, TransportMode};

fn control_frame() -> ControlFrame {
    ControlFrame {
        payload: Some(ControlPayload::Control(ControlMessage {
            msg: Some(privet_protocol::control_message::Msg::Cancel(Cancel {
                transfer_id: "frame-io-test".into(),
                reason: "test".into(),
            })),
        })),
    }
}

fn data_frame(length: usize) -> DataFrame {
    DataFrame {
        payload: Some(DataPayload::ChunkHeader(ChunkHeader {
            file_id: "file-1".into(),
            segment_id: 2,
            chunk_index: 3,
            offset: 4,
            length: length as u64,
        })),
    }
}

async fn assert_frame_roundtrip(client: Box<dyn Connection>, server: Box<dyn Connection>) {
    let expected_control = control_frame();
    let mut client_control = client.open_control().await.unwrap();
    privet_transport::send_control(client_control.as_mut(), &expected_control)
        .await
        .unwrap();
    let mut server_control = server.accept_control().await.unwrap();
    let received_control = privet_transport::recv_control(server_control.as_mut())
        .await
        .unwrap();
    assert_eq!(received_control.payload, expected_control.payload);

    let raw = b"frame io over concrete transport";
    let expected_data = data_frame(raw.len());
    let mut client_data = client.open_data_stream().await.unwrap();
    privet_transport::send_data(client_data.as_mut(), &expected_data, Some(raw))
        .await
        .unwrap();
    let mut server_data = server.accept_data_stream().await.unwrap();
    let (received_data, received_raw) = privet_transport::recv_data(server_data.as_mut())
        .await
        .unwrap();
    assert_eq!(received_data.payload, expected_data.payload);
    assert_eq!(received_raw.unwrap().as_ref(), raw);
}

#[tokio::test(flavor = "multi_thread")]
async fn frame_io_over_quic() {
    let server_transport = privet_transport::QuicTransport::new(
        common::test_tls_material(),
        Default::default(),
    );
    let listener = server_transport
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = listener.local_addr().await.unwrap();
    let client_transport = privet_transport::QuicTransport::new(
        common::test_tls_material(),
        Default::default(),
    );
    let (server, client) = tokio::join!(
        listener.accept(),
        client_transport.connect(address, TransportMode::Quic, None),
    );
    assert_frame_roundtrip(client.unwrap(), server.unwrap()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn frame_io_over_tcp_tls() {
    let server_transport = privet_transport::TcpTransport::new(
        common::test_tls_material(),
        Default::default(),
    );
    let listener = server_transport
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = listener.local_addr().await.unwrap();
    let client_transport = privet_transport::TcpTransport::new(
        common::test_tls_material(),
        Default::default(),
    );
    let (server, client) = tokio::join!(
        listener.accept(),
        client_transport.connect(address, TransportMode::Tcp, None),
    );
    assert_frame_roundtrip(client.unwrap(), server.unwrap()).await;
}

#[tokio::test]
async fn send_data_rejects_raw_length_mismatch() {
    use async_trait::async_trait;
    use bytes::BytesMut;
    use privet_transport::{Stream, TransportError};

    struct Sink;
    #[async_trait]
    impl Stream for Sink {
        async fn send_all(&mut self, _: &[u8]) -> Result<(), TransportError> { Ok(()) }
        async fn recv_exact(&mut self, _: usize) -> Result<BytesMut, TransportError> {
            unreachable!()
        }
        async fn reset(self: Box<Self>, _: u32) {}
    }

    let error = privet_transport::send_data(&mut Sink, &data_frame(4), Some(b"abc"))
        .await
        .unwrap_err();
    assert!(matches!(error, TransportError::Frame(_)));
}
