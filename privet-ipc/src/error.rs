#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("IPC message exceeds the configured limit")]
    MessageTooLarge,
    #[error("IPC connection closed")]
    Closed,
    #[error("request timed out")]
    Timeout,
    #[error("daemon rejected request [{code}]: {message}")]
    Remote { code: String, message: String },
    #[error("protocol error: {0}")]
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, IpcError>;
