//! Transport 抽象。

use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::BytesMut;

pub use crate::config::TransportMode;
use crate::error::TransportError;

/// 传输种类（连接已建立后报告）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Quic,
    Tcp,
}

/// 连接关闭原因。
#[derive(Debug, Clone)]
pub enum CloseReason {
    Normal,
    Error(String),
    /// 应用层错误码（映射 QUIC reset / TCP close）。
    Application(u32),
}

/// 统一传输：connect / bind。
#[async_trait]
pub trait Transport: Send + Sync {
    /// `bind_source`：多宿主时绑本机接口源地址；None=内核按路由表选。
    async fn connect(
        &self,
        addr: SocketAddr,
        mode: TransportMode,
        bind_source: Option<SocketAddr>,
    ) -> Result<Box<dyn Connection>, TransportError>;

    async fn bind(&self, addr: SocketAddr) -> Result<Box<dyn Listener>, TransportError>;
}

/// 逻辑流：send/recv/reset。
/// 双向流（控制）两半均可用；单向数据流（sender 侧仅 send_all，receiver 侧仅 recv_exact）。
#[async_trait]
pub trait Stream: Send + Sync {
    async fn send_all(&mut self, buf: &[u8]) -> Result<(), TransportError>;
    async fn recv_exact(&mut self, n: usize) -> Result<BytesMut, TransportError>;
    async fn reset(self: Box<Self>, code: u32);
}

/// 连接：控制流 + 数据流。
#[async_trait]
pub trait Connection: Send + Sync {
    /// 逻辑流 0（控制）。返回的 Stream 双向可用。
    /// TCP 返回 Ok；QUIC 返回 Err(TransportError::Unavailable)（QUIC 用异步 open_control/accept_control）。
    fn control_stream(&self) -> Result<Box<dyn Stream>, TransportError>;

    /// 发起方开控制流（QUIC: open_bi 双向流；TCP: 返回共享控制流 stream_id 0）。
    async fn open_control(&self) -> Result<Box<dyn Stream>, TransportError> {
        Err(TransportError::Unavailable(
            "open_control not supported".into(),
        ))
    }

    /// 应答方收控制流（QUIC: accept_bi；TCP: 返回共享控制流 stream_id 0）。
    async fn accept_control(&self) -> Result<Box<dyn Stream>, TransportError> {
        Err(TransportError::Unavailable(
            "accept_control not supported".into(),
        ))
    }

    /// 开新数据流。QUIC=新单向流；TCP=唯一数据流（stream_id 1）。
    async fn open_data_stream(&self) -> Result<Box<dyn Stream>, TransportError>;

    /// 应答方收数据流（QUIC: accept_uni；TCP: 返回共享数据流 stream_id 1）。
    async fn accept_data_stream(&self) -> Result<Box<dyn Stream>, TransportError> {
        Err(TransportError::Unavailable(
            "accept_data_stream not supported".into(),
        ))
    }

    /// QUIC=min(8, peer max)；TCP=1。
    fn max_data_streams(&self) -> usize;

    fn kind(&self) -> TransportKind;

    /// 对端证书 DER（供 P3 钉扎；传输层不校验）。
    fn peer_cert_der(&self) -> Option<Vec<u8>>;

    /// TLS exporter（RFC 5705 转录绑定用）。默认不支持；QUIC 真实现。
    fn export_keying_material(
        &self,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> std::result::Result<Vec<u8>, TransportError> {
        Err(TransportError::Unavailable("exporter not supported".into()))
    }

    async fn close(self: Box<Self>, reason: CloseReason);
}

/// 监听器：accept 入站连接。
#[async_trait]
pub trait Listener: Send {
    async fn accept(&self) -> Result<Box<dyn Connection>, TransportError>;
    async fn local_addr(&self) -> Result<SocketAddr, TransportError>;
}
