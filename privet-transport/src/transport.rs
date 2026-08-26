
use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::BytesMut;

pub use crate::config::TransportMode;
use crate::error::TransportError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Quic,
    Tcp,
}

#[derive(Debug, Clone)]
pub enum CloseReason {
    Normal,
    Error(String),
    Application(u32),
}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn connect(
        &self,
        addr: SocketAddr,
        mode: TransportMode,
        bind_source: Option<SocketAddr>,
    ) -> Result<Box<dyn Connection>, TransportError>;

    async fn bind(&self, addr: SocketAddr) -> Result<Box<dyn Listener>, TransportError>;
}

#[async_trait]
pub trait Stream: Send + Sync {
    async fn send_all(&mut self, buf: &[u8]) -> Result<(), TransportError>;
    async fn recv_exact(&mut self, n: usize) -> Result<BytesMut, TransportError>;
    async fn reset(self: Box<Self>, code: u32);
}

#[async_trait]
pub trait Connection: Send + Sync {
    fn control_stream(&self) -> Result<Box<dyn Stream>, TransportError>;

    async fn open_control(&self) -> Result<Box<dyn Stream>, TransportError> {
        Err(TransportError::Unavailable(
            "open_control not supported".into(),
        ))
    }

    async fn accept_control(&self) -> Result<Box<dyn Stream>, TransportError> {
        Err(TransportError::Unavailable(
            "accept_control not supported".into(),
        ))
    }

    async fn open_data_stream(&self) -> Result<Box<dyn Stream>, TransportError>;

    async fn accept_data_stream(&self) -> Result<Box<dyn Stream>, TransportError> {
        Err(TransportError::Unavailable(
            "accept_data_stream not supported".into(),
        ))
    }

    fn max_data_streams(&self) -> usize;

    fn kind(&self) -> TransportKind;

    fn peer_cert_der(&self) -> Option<Vec<u8>>;

    fn export_keying_material(
        &self,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> std::result::Result<Vec<u8>, TransportError> {
        Err(TransportError::Unavailable("exporter not supported".into()))
    }

    async fn close(self: Box<Self>, reason: CloseReason);
}

#[async_trait]
pub trait Listener: Send {
    async fn accept(&self) -> Result<Box<dyn Connection>, TransportError>;
    async fn local_addr(&self) -> Result<SocketAddr, TransportError>;
}
