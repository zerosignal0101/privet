use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::session::{SessionId, TransferDirection};

/// Append-only transfer record log (JSONL format).
#[derive(Clone)]
pub struct TransferLog {
    path: std::path::PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferFileRecord {
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
    /// Relative path from the protocol (for tree display in history).
    /// None for legacy records that predate folder transfer support.
    #[serde(default)]
    pub relative_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferRecordState {
    Completed,
    Failed,
    Cancelled,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRecord {
    pub session_id: SessionId,
    pub direction: TransferDirection,
    pub peer_fingerprint: String,
    pub peer_name: String,
    pub files: Vec<TransferFileRecord>,
    pub total_bytes: u64,
    pub bytes_transferred: u64,
    pub started_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub state: TransferRecordState,
    pub error: Option<String>,
}

impl TransferLog {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Ensure file exists
        if !path.exists() {
            std::fs::File::create(path)?;
        }
        Ok(Self { path: path.to_owned() })
    }

    pub fn append(&self, record: &TransferRecord) -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)?;
        let json = serde_json::to_string(record)?;
        use std::io::Write;
        writeln!(file, "{json}")?;
        Ok(())
    }

    pub fn read_all(&self) -> std::io::Result<Vec<TransferRecord>> {
        let content = std::fs::read_to_string(&self.path)?;
        Ok(content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect())
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Read all records sorted by completed_at descending (most recent first).
    pub fn read_all_sorted(&self) -> std::io::Result<Vec<TransferRecord>> {
        let mut records = self.read_all()?;
        records.sort_by(|a, b| {
            let a_time = a.completed_at.unwrap_or(0);
            let b_time = b.completed_at.unwrap_or(0);
            b_time.cmp(&a_time)
        });
        Ok(records)
    }
}
