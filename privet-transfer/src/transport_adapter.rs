//! Stream 适配器：把 privet_transport::Stream（字节流）包成 ControlChannel/DataChannel（帧级）。
//! 真实 QUIC/TCP e2e（QuicTransport/TcpTransport）推迟到 privet-core。

use async_trait::async_trait;
use bytes::BytesMut;
use privet_protocol::{ControlFrame, DataFrame};
use privet_transport::frame_io::{recv_control, recv_data, send_control, send_data};
use privet_transport::Stream;

use crate::error::{Result, TransferError};

pub struct StreamControlChannel {
    inner: Box<dyn Stream>,
}
impl StreamControlChannel {
    pub fn new(inner: Box<dyn Stream>) -> Self {
        Self { inner }
    }
}
#[async_trait]
impl crate::ControlChannel for StreamControlChannel {
    async fn send(&mut self, frame: ControlFrame) -> Result<()> {
        send_control(self.inner.as_mut(), &frame)
            .await
            .map_err(map_te)
    }
    async fn recv(&mut self) -> Result<ControlFrame> {
        recv_control(self.inner.as_mut()).await.map_err(map_te)
    }
}

pub struct StreamDataChannel {
    inner: Box<dyn Stream>,
}
impl StreamDataChannel {
    pub fn new(inner: Box<dyn Stream>) -> Self {
        Self { inner }
    }
}
#[async_trait]
impl crate::DataChannel for StreamDataChannel {
    async fn send(&mut self, frame: DataFrame, raw: Option<&[u8]>) -> Result<()> {
        send_data(self.inner.as_mut(), &frame, raw)
            .await
            .map_err(map_te)
    }
    async fn recv(&mut self) -> Result<(DataFrame, Option<BytesMut>)> {
        recv_data(self.inner.as_mut()).await.map_err(map_te)
    }
}

fn map_te(e: privet_transport::TransportError) -> TransferError {
    use privet_transport::TransportError as TE;
    // 用 ?e（Debug）记录完整错误链，暴露 quinn 内层 ConnectionError
    // （TimedOut / ApplicationClosed / Reset / LocallyClosed 等），诊断连接为何死亡。
    // 可重试（连接/流死亡）-> TransportLost；不可重试（帧解析错等）-> Transport。
    let resumable = matches!(
        &e,
        TE::Closed(_) | TE::Quic(_) | TE::QuicRead(_) | TE::QuicReadExact(_) | TE::QuicWrite(_)
    );
    if resumable {
        tracing::warn!(error = ?e, "transport stream error -> TransportLost (resumable)");
    } else {
        tracing::debug!(error = ?e, "transport stream error (non-resumable)");
    }
    match e {
        TE::Closed(_) | TE::Quic(_) | TE::QuicRead(_) | TE::QuicReadExact(_) | TE::QuicWrite(_) => {
            TransferError::TransportLost
        }
        other => TransferError::Transport(other.to_string()),
    }
}
