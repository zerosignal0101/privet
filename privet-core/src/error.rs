//! CoreError：融合 leaf crate 错误。
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("pairing: {0}")]
    Pairing(#[from] privet_security::PairingError),
    #[error("transfer: {0}")]
    Transfer(#[from] privet_transfer::TransferError),
    #[error("transport: {0}")]
    Transport(#[from] privet_transport::TransportError),
    #[error("storage: {0}")]
    Storage(#[from] privet_storage::StorageError),
    #[error("crypto: {0}")]
    Crypto(#[from] privet_crypto::CryptoError),
    #[error("discovery: {0}")]
    Discovery(#[from] privet_discovery::DiscoveryError),
    #[error("not paired: {0}")]
    NotPaired(String),
    #[error("needs daemon: {0}")]
    NeedsDaemon(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("internal: {0}")]
    Internal(String),
}

impl CoreError {
    /// 稳定错误码（事件/退出码用；不含敏感材料）。
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::Pairing(_) => "pairing",
            Self::Transfer(_) => "transfer",
            Self::Transport(_) => "transport",
            Self::Storage(_) => "storage",
            Self::Crypto(_) => "crypto",
            Self::Discovery(_) => "discovery",
            Self::NotPaired(_) => "not_paired",
            Self::NeedsDaemon(_) => "needs_daemon",
            Self::Io(_) => "io",
            Self::Internal(_) => "internal",
        }
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;
