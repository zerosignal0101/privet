//! 发现层错误。

#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("decode: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("beacon invalid: {0}")]
    BeaconInvalid(String),
    #[error("beacon expired")]
    BeaconExpired,
    #[error("beacon replay (nonce seen)")]
    BeaconReplay,
    #[error("mdns: {0}")]
    Mdns(String),
    #[error("invalid config: {0}")]
    Config(String),
    #[error("not running")]
    NotRunning,
}

pub type Result<T> = std::result::Result<T, DiscoveryError>;
