use thiserror::Error;

#[derive(Error, Debug)]
pub enum PrivetError {
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("security error: {0}")]
    Security(#[from] SecurityError),

    #[error("discovery error: {0}")]
    Discovery(#[from] DiscoveryError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("peer not found: {0}")]
    PeerNotFound(String),

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("transfer rejected: {0}")]
    TransferRejected(String),

    #[error("disk full: need {needed} bytes, have {available} available")]
    DiskFull { needed: u64, available: u64 },

    #[error("connection timeout")]
    ConnectionTimeout,

    #[error("UDP blocked, TCP fallback required")]
    UdpBlocked,
}

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("QUIC connection error: {0}")]
    Quic(String),

    #[error("QUIC connection lost: {0}")]
    ConnectionLost(String),

    #[error("TCP fallback error: {0}")]
    TcpFallback(String),

    #[error("handshake timeout")]
    HandshakeTimeout,
}

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("unexpected message type: expected {expected}, got {got}")]
    UnexpectedMessage { expected: String, got: String },

    #[error("version mismatch: local {local}, remote {remote}")]
    VersionMismatch { local: u8, remote: u8 },
}

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("fingerprint mismatch: expected {expected}, got {got}")]
    FingerprintMismatch { expected: String, got: String },

    #[error("peer not trusted: {0}")]
    NotTrusted(String),

    #[error("pairing required")]
    PairingRequired,
}

#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("mDNS error: {0}")]
    Mdns(String),

    #[error("beacon error: {0}")]
    Beacon(String),

    #[error("scan error: {0}")]
    Scan(String),
}

pub type Result<T> = std::result::Result<T, PrivetError>;
