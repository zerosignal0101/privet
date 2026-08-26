//! TCP loopback: connect, control stream round-trip, max_data_streams=1.

mod common;

use privet_transport::Transport;

#[tokio::test(flavor = "multi_thread")]
async fn tcp_connect_control_roundtrip() {
    let mat = common::test_tls_material();
    let transport = privet_transport::TcpTransport::new(mat, Default::default());
    let listener = transport
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let bound = listener.local_addr().await.unwrap();

    let srv = tokio::spawn(async move {
        let conn = listener.accept().await.unwrap();
        conn
    });
    let client = transport
        .connect(bound, privet_transport::TransportMode::Tcp, None)
        .await
        .unwrap();
    assert_eq!(client.kind(), privet_transport::TransportKind::Tcp);
    assert_eq!(client.max_data_streams(), 1);

    let mut c = client.control_stream().unwrap();
    let msg = privet_protocol::ControlFrame {
        payload: Some(privet_protocol::control_frame::Payload::Control(
            privet_protocol::ControlMessage {
                msg: Some(privet_protocol::control_message::Msg::Cancel(
                    privet_protocol::Cancel {
                        transfer_id: "t1".into(),
                        reason: "user".into(),
                    },
                )),
            },
        )),
    };
    privet_transport::send_control(c.as_mut(), &msg)
        .await
        .unwrap();

    let server = srv.await.unwrap();
    let mut s = server.control_stream().unwrap();
    let got = privet_transport::recv_control(s.as_mut()).await.unwrap();
    assert!(matches!(
        got.payload,
        Some(privet_protocol::control_frame::Payload::Control(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_control_interleaves_data() {
    let mat = common::test_tls_material();
    let transport = privet_transport::TcpTransport::new(mat, Default::default());
    let listener = transport
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let bound = listener.local_addr().await.unwrap();
    let srv = tokio::spawn(async move {
        let conn = listener.accept().await.unwrap();
        conn
    });
    let client = transport
        .connect(bound, privet_transport::TransportMode::Tcp, None)
        .await
        .unwrap();
    let server = srv.await.unwrap();

    let mut data = client.open_data_stream().await.unwrap();
    let dh = privet_protocol::DataFrame {
        payload: Some(privet_protocol::data_frame::Payload::ChunkHeader(
            privet_protocol::ChunkHeader {
                file_id: "f".into(),
                segment_id: 0,
                chunk_index: 0,
                offset: 0,
                length: 4,
            },
        )),
    };
    privet_transport::send_data(data.as_mut(), &dh, Some(b"abcd"))
        .await
        .unwrap();
    let mut ctrl = client.control_stream().unwrap();
    privet_transport::send_control(
        ctrl.as_mut(),
        &privet_protocol::ControlFrame {
            payload: Some(privet_protocol::control_frame::Payload::Control(
                privet_protocol::ControlMessage {
                    msg: Some(privet_protocol::control_message::Msg::Cancel(
                        privet_protocol::Cancel {
                            transfer_id: "t1".into(),
                            reason: "interleave".into(),
                        },
                    )),
                },
            )),
        },
    )
    .await
    .unwrap();

    let mut sctrl = server.control_stream().unwrap();
    let got = privet_transport::recv_control(sctrl.as_mut())
        .await
        .unwrap();
    assert!(matches!(
        got.payload,
        Some(privet_protocol::control_frame::Payload::Control(_))
    ));
}
