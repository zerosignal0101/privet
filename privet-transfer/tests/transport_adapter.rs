//! Stream 适配器（包 privet_transport::Stream + frame_io）。
use async_trait::async_trait;
use bytes::BytesMut;
use privet_protocol::{
    control_frame::Payload as CP, data_frame::Payload as DP, ChunkHeader, ControlFrame,
    ControlMessage, DataFrame,
};
use privet_transfer::transport_adapter::{StreamControlChannel, StreamDataChannel};
use privet_transfer::{ControlChannel, DataChannel};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

/// 双向内存流：两条 VecDeque 队列（每个方向一条）+ 通知。
struct LoopbackStream {
    to_peer: Arc<ChannelPair>,   // 写入此端 -> 对端读出
    from_peer: Arc<ChannelPair>, // 对端写入 -> 从此端读出
}
struct ChannelPair {
    buf: Mutex<VecDeque<u8>>,
    notify: Notify,
}

impl LoopbackStream {
    fn pair() -> (Self, Self) {
        let a_to_b = Arc::new(ChannelPair {
            buf: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
        });
        let b_to_a = Arc::new(ChannelPair {
            buf: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
        });
        (
            Self {
                to_peer: a_to_b.clone(),
                from_peer: b_to_a.clone(),
            },
            Self {
                to_peer: b_to_a.clone(),
                from_peer: a_to_b.clone(),
            },
        )
    }
}

#[async_trait]
impl privet_transport::Stream for LoopbackStream {
    async fn send_all(&mut self, buf: &[u8]) -> Result<(), privet_transport::TransportError> {
        let mut b = self.to_peer.buf.lock().unwrap();
        b.extend(buf.iter().copied());
        self.to_peer.notify.notify_one();
        Ok(())
    }
    async fn recv_exact(&mut self, n: usize) -> Result<BytesMut, privet_transport::TransportError> {
        loop {
            let should_wait = {
                let mut b = self.from_peer.buf.lock().unwrap();
                if b.len() >= n {
                    let mut out = BytesMut::with_capacity(n);
                    for _ in 0..n {
                        out.extend_from_slice(&[b.pop_front().unwrap()]);
                    }
                    return Ok(out);
                }
                true
            };
            if should_wait {
                self.from_peer.notify.notified().await;
            }
        }
    }
    async fn reset(self: Box<Self>, _code: u32) {}
}

fn ctl(id: &str) -> ControlFrame {
    ControlFrame {
        payload: Some(CP::Control(ControlMessage {
            msg: Some(privet_protocol::control_message::Msg::Cancel(
                privet_protocol::Cancel {
                    transfer_id: id.into(),
                    reason: "u".into(),
                },
            )),
        })),
    }
}

#[tokio::test]
async fn stream_control_roundtrip() {
    let (a, b) = LoopbackStream::pair();
    let mut sa = StreamControlChannel::new(Box::new(a));
    let mut sb = StreamControlChannel::new(Box::new(b));
    sa.send(ctl("t1")).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), sb.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(got.payload, Some(CP::Control(_))));
}

#[tokio::test]
async fn stream_data_roundtrip_with_raw() {
    let (a, b) = LoopbackStream::pair();
    let mut sa = StreamDataChannel::new(Box::new(a));
    let mut sb = StreamDataChannel::new(Box::new(b));
    let df = DataFrame {
        payload: Some(DP::ChunkHeader(ChunkHeader {
            file_id: "f".into(),
            segment_id: 0,
            chunk_index: 0,
            offset: 0,
            length: 4,
        })),
    };
    sa.send(df, Some(b"abcd")).await.unwrap();
    let (f, raw) = tokio::time::timeout(Duration::from_secs(2), sb.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(f.payload, Some(DP::ChunkHeader(_))));
    assert_eq!(raw.unwrap().as_ref(), b"abcd");
}
