use thiserror::Error;

#[derive(Debug, Error)]
pub enum PairingError {
    #[error("pairing code mismatch")]
    CodeMismatch,
    #[error("pairing code expired")]
    CodeExpired,
    #[error("pairing code attempts exhausted")]
    AttemptsExhausted,
    #[error("transcript invalid: {0}")]
    TranscriptInvalid(String),
    #[error("peer key mismatch (fail-closed)")]
    KeyMismatch,
    #[error("already paired")]
    AlreadyPaired,
    #[error("peer revoked")]
    Revoked,
    #[error("transport failed: {0}")]
    TransportFailed(String),
    #[error("ack timeout")]
    AckTimeout,
    #[error("crypto: {0}")]
    Crypto(#[from] privet_crypto::CryptoError),
    #[error("protocol frame: {0}")]
    Protocol(String),
}

impl PairingError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::CodeMismatch => "code_mismatch",
            Self::CodeExpired => "code_expired",
            Self::AttemptsExhausted => "attempts_exhausted",
            Self::TranscriptInvalid(_) => "transcript_invalid",
            Self::KeyMismatch => "key_mismatch",
            Self::AlreadyPaired => "already_paired",
            Self::Revoked => "revoked",
            Self::TransportFailed(_) => "transport_failed",
            Self::AckTimeout => "ack_timeout",
            Self::Crypto(_) => "crypto",
            Self::Protocol(_) => "protocol",
        }
    }
}

pub type Result<T> = std::result::Result<T, PairingError>;
