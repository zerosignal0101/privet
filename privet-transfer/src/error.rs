//! TransferError + 错误码映射。

use privet_protocol::error::PathError;

/// 传送错误分类。-> 映射 ControlMessage.cancel{reason} / TransferVerified{ok=false,error}。
#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("declined: {0}")]
    Declined(String),
    #[error("cancelled: {0}")]
    Cancelled(String),
    #[error("verify failed: {0}")]
    VerifyFailed(String),
    #[error("chunk corrupt (retransmit exhausted)")]
    ChunkCorrupt,
    #[error("disk full")]
    DiskFull,
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("path unsafe: {0}")]
    PathUnsafe(String),
    #[error("aborted: {0}")]
    Aborted(String),
    #[error("transport lost (resumable)")]
    TransportLost,
    #[error("too many files: {0} > {1}")]
    TooManyFiles(u64, u64),
    #[error("manifest mismatch: {0}")]
    ManifestMismatch(String),
    #[error("frame/protocol: {0}")]
    Protocol(String),
    #[error("storage: {0}")]
    Storage(#[from] privet_storage::StorageError),
    #[error("transport: {0}")]
    Transport(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("internal: {0}")]
    Internal(String),
}

impl From<PathError> for TransferError {
    fn from(e: PathError) -> Self {
        TransferError::PathUnsafe(format!("{e:?}"))
    }
}

/// -> ControlMessage.cancel.reason / TransferVerified.error 用的短码串。
impl TransferError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::Declined(_) => "declined",
            Self::Cancelled(_) => "cancelled",
            Self::VerifyFailed(_) => "verify_failed",
            Self::ChunkCorrupt => "chunk_corrupt",
            Self::DiskFull => "disk_full",
            Self::PermissionDenied(_) => "permission_denied",
            Self::PathUnsafe(_) => "path_unsafe",
            Self::Aborted(_) => "aborted",
            Self::TransportLost => "transport_lost",
            Self::TooManyFiles(_, _) => "too_many_files",
            Self::ManifestMismatch(_) => "manifest_mismatch",
            Self::Protocol(_)
            | Self::Storage(_)
            | Self::Transport(_)
            | Self::Io(_)
            | Self::Internal(_) => "internal",
        }
    }

    /// 是否可重试（对齐 TransferFailed{retryable}）。
    pub fn retryable(&self) -> bool {
        matches!(
            self,
            Self::TransportLost | Self::ChunkCorrupt | Self::VerifyFailed(_)
        )
    }
}

pub type Result<T> = std::result::Result<T, TransferError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_classification() {
        assert!(TransferError::TransportLost.retryable());
        assert!(TransferError::ChunkCorrupt.retryable());
        assert!(TransferError::VerifyFailed("x".into()).retryable());
        assert!(!TransferError::Declined("x".into()).retryable());
        assert!(!TransferError::PathUnsafe("x".into()).retryable());
    }

    #[test]
    fn path_error_maps_to_path_unsafe() {
        let e: TransferError = PathError::ParentRef.into();
        assert!(matches!(e, TransferError::PathUnsafe(_)));
        assert_eq!(e.error_code(), "path_unsafe");
    }
}
