use std::path::PathBuf;
use std::time::{Instant, SystemTime};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::peer::PeerId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Negotiating,
    WaitingAcceptance,
    Transferring,
    Paused,
    Completing,
    Completed,
    Failed(String),
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferDirection {
    Sending,
    Receiving,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferSession {
    pub id: SessionId,
    pub peer: PeerId,
    pub direction: TransferDirection,
    pub state: SessionState,
    pub files: FileManifest,
    pub progress: TransferProgress,
    #[serde(skip)]
    pub started_at: Option<Instant>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransferProgress {
    pub total_bytes: u64,
    pub bytes_transferred: u64,
    pub current_speed_bps: f64,
    pub per_file: Vec<FileProgress>,
}

impl TransferProgress {
    pub fn percent(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.bytes_transferred as f64 / self.total_bytes as f64) * 100.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileProgress {
    pub path: PathBuf,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
    pub state: FileTransferState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileTransferState {
    Pending,
    Active,
    Completed,
    Skipped,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileManifest {
    pub files: Vec<FileEntry>,
    pub total_size: u64,
}

impl FileManifest {
    pub fn from_paths(paths: &[PathBuf]) -> std::io::Result<Self> {
        let mut files = Vec::new();
        let mut total_size = 0u64;

        for path in paths {
            let metadata = std::fs::metadata(path)?;
            let relative_path = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            let sha256 = if metadata.len() <= 64 * 1024 * 1024 {
                // Compute hash for files <= 64MB
                None // Will be computed during transfer
            } else {
                None // Lazy hash for large files
            };

            let entry = FileEntry {
                relative_path,
                size: metadata.len(),
                modified: metadata.modified().ok(),
                sha256,
                is_dir: metadata.is_dir(),
            };
            total_size += entry.size;
            files.push(entry);
        }

        Ok(Self { files, total_size })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub relative_path: String,
    pub size: u64,
    #[serde(with = "system_time_serde")]
    pub modified: Option<SystemTime>,
    pub sha256: Option<Vec<u8>>,
    pub is_dir: bool,
}

// SystemTime serialization helper
mod system_time_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::{Duration, SystemTime};

    pub fn serialize<S: Serializer>(time: &Option<SystemTime>, s: S) -> Result<S::Ok, S::Error> {
        match time {
            Some(t) => {
                let dur = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
                s.serialize_u64(dur.as_secs())
            }
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SystemTime>, D::Error> {
        let opt: Option<u64> = Option::deserialize(d)?;
        Ok(opt.map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs)))
    }
}
