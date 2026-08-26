
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("migration failed at version {version}: {reason}")]
    Migration { version: u32, reason: String },
    #[error("path unsafe: {0}")]
    Path(String),
    #[error("decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("encode error: {0}")]
    Encode(#[from] prost::EncodeError),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid state: {0}")]
    InvalidState(String),
    #[error("corrupt sidecar data: {0}")]
    Corrupt(String),
}
