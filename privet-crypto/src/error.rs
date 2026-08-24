//! crypto 错误类型。

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("keystore error: {0}")]
    KeyStore(String),
    #[error("rng failure: {0}")]
    Rng(String),
    #[error("pake error: {0}")]
    Pake(String),
    #[error("pake already finished (single-use)")]
    PakeAlreadyFinished,
    #[error("certificate error: {0}")]
    Certificate(String),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
