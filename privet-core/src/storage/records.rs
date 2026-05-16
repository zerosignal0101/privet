use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::session::{SessionId, TransferDirection};

/// Append-only transfer record log (JSONL format).
pub struct TransferLog {
    path: std::path::PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferRecord {
    pub session_id: SessionId,
    pub direction: TransferDirection,
    pub peer_fingerprint: String,
    pub files: Vec<String>,
    pub total_bytes: u64,
    pub bytes_transferred: u64,
    pub completed: bool,
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
        content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| serde_json::from_str(line).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
            .collect()
    }
}
