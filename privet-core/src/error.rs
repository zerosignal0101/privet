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
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::Pairing(_) => "pairing",
            // Surface the specific failure (rejected / transport_lost / ...)
            // so the GUI can show a readable message instead of a generic
            // "transfer" for every failure.
            Self::Transfer(t) => t.error_code(),
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
