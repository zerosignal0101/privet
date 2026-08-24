//! Control-stream priority + TCP cancel-responsiveness under backpressure.
//! TCP 数据通道满时，Cancel 控制帧必须在前 200ms 内送达。

mod common;

use privet_transport::config::TransportConfigPrivet;
use privet_transport::transport::Transport;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn cancel_arrives_while_data_backpressure() {
    let mat = common::test_tls_material();
    let tcp = privet_transport::TcpTransport::new(mat.clone(), TransportConfigPrivet::default());
    let listener = tcp.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().await.unwrap();

    // 服务端：accept 后得到控制流+数据流，但不 drain 数据通道
    let accept = async {
        let conn = listener.accept().await.unwrap();
        let ctrl = conn.control_stream().unwrap();
        let data = conn.open_data_stream().await.unwrap();
        (ctrl, data)
    };
    // 客户端：connect 后得到控制流+数据流
    let connect = async {
        let conn = tcp
            .connect(addr, privet_transport::TransportMode::Tcp, None)
            .await
            .unwrap();
        let ctrl = conn.control_stream().unwrap();
        let data = conn.open_data_stream().await.unwrap();
        (ctrl, data)
    };

    let ((mut srv_ctrl, _srv_data), (mut cli_ctrl, mut cli_data)) =
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(accept, connect)
        })
        .await
        .unwrap();

    // Flood: 100 个数据帧填满 data_tx（cap=64），不 drain 服务端数据通道
    for _ in 0..100 {
        let df = privet_protocol::DataFrame {
            payload: Some(privet_protocol::data_frame::Payload::ChunkHeader(
                privet_protocol::ChunkHeader {
                    file_id: "f".into(),
                    segment_id: 0,
                    chunk_index: 0,
                    offset: 0,
                    length: 1,
                },
            )),
        };
        privet_transport::send_data(cli_data.as_mut(), &df, Some(b"x"))
            .await
            .unwrap();
    }

    // 数据通道已满 — 发送 Cancel 控制帧
    let cancel = privet_protocol::ControlFrame {
        payload: Some(privet_protocol::control_frame::Payload::Control(
            privet_protocol::ControlMessage {
                msg: Some(privet_protocol::control_message::Msg::Cancel(
                    privet_protocol::Cancel {
                        transfer_id: "t1".into(),
                        reason: "test".into(),
                    },
                )),
            },
        )),
    };
    privet_transport::send_control(cli_ctrl.as_mut(), &cancel)
        .await
        .unwrap();

    // 服务端 drain 控制通道（数据通道满的情况下，控制帧应在 200ms 内到达）
    let start = std::time::Instant::now();
    let got = tokio::time::timeout(
        Duration::from_millis(500),
        privet_transport::recv_control(srv_ctrl.as_mut()),
    )
    .await;
    assert!(
        got.is_ok(),
        "control frame blocked by data backpressure, timed out"
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(200),
        "control arrived too late: {:?}",
        elapsed
    );

    // 验证是 Control 帧（Cancel 确认）
    let cf = got.unwrap().expect("recv_control error");
    assert!(
        matches!(
            cf.payload,
            Some(privet_protocol::control_frame::Payload::Control(_))
        ),
        "expected Control frame, got {:?}",
        cf
    );
}
