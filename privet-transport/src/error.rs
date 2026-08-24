//! 传输层错误。

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("quic connection: {0}")]
    Quic(#[from] quinn::ConnectionError),
    #[error("quic connect: {0}")]
    QuicConnect(#[from] quinn::ConnectError),
    #[error("quic write: {0}")]
    QuicWrite(#[from] quinn::WriteError),
    #[error("quic read: {0}")]
    QuicRead(#[from] quinn::ReadError),
    #[error("quic read exact: {0}")]
    QuicReadExact(#[from] quinn::ReadExactError),
    #[error("rustls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("frame: {0}")]
    Frame(#[from] privet_protocol::error::FrameError),
    #[error("connection closed: {0}")]
    Closed(String),
    #[error("connect timeout after {0:?}")]
    ConnectTimeout(std::time::Duration),
    #[error("transport unavailable: {0}")]
    Unavailable(String),
    #[error("tls material invalid: {0}")]
    TlsMaterial(String),
    #[error("invalid config: {0}")]
    Config(String),
    #[error("frame too large (DoS)")]
    TooLarge,
}

pub type Result<T> = std::result::Result<T, TransportError>;
