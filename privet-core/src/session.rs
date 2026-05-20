use std::path::{Path, PathBuf};
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

impl std::str::FromStr for SessionId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
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

// ---------------------------------------------------------------------------
// Directory expansion types (sender side)
// ---------------------------------------------------------------------------

/// Maximum directory traversal depth to prevent stack overflow.
const MAX_DEPTH: u16 = 256;

/// Maximum number of files in a single expanded list.
const MAX_FILE_COUNT: usize = 100_000;

/// A file to be sent, carrying both the absolute filesystem path (for reading)
/// and the relative path (for the protocol wire format).
#[derive(Clone, Debug)]
pub struct FileToSend {
    pub absolute_path: PathBuf,
    pub relative_path: String,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub sha256: Option<Vec<u8>>,
    pub is_dir: bool,
}

/// Result of expanding a list of paths (which may include directories).
#[derive(Clone, Debug)]
pub struct ExpansionResult {
    pub files: Vec<FileToSend>,
    pub total_size: u64,
    pub skipped: Vec<SkippedPath>,
}

/// A path that was skipped during directory expansion.
#[derive(Clone, Debug)]
pub struct SkippedPath {
    pub path: PathBuf,
    pub reason: String,
}

/// Normalize a relative path to use forward slashes (protocol wire format).
fn normalize_relative_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Expand a list of input paths (files and directories) into a flat list of
/// `FileToSend` entries with relative paths. Directories are walked recursively;
/// empty directories produce `is_dir: true` marker entries.
pub fn expand_paths(paths: &[PathBuf]) -> ExpansionResult {
    let mut files = Vec::new();
    let mut total_size = 0u64;
    let mut skipped = Vec::new();

    for path in paths {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                skipped.push(SkippedPath {
                    path: path.clone(),
                    reason: format!("cannot read metadata: {e}"),
                });
                continue;
            }
        };

        if metadata.is_symlink() {
            skipped.push(SkippedPath {
                path: path.clone(),
                reason: "symlink skipped".into(),
            });
            continue;
        }

        if metadata.is_dir() {
            let parent = path.parent().unwrap_or(Path::new("."));
            let base_name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            let mut dir_has_files = false;
            walk_dir(
                path,
                parent,
                &mut files,
                &mut total_size,
                &mut skipped,
                &mut dir_has_files,
                0,
            );

            if !dir_has_files {
                // Empty directory: add marker entry
                let relative_path = normalize_relative_path(&PathBuf::from(&base_name));
                files.push(FileToSend {
                    absolute_path: path.clone(),
                    relative_path,
                    size: 0,
                    modified: metadata.modified().ok(),
                    sha256: None,
                    is_dir: true,
                });
            }
        } else if metadata.is_file() {
            if files.len() >= MAX_FILE_COUNT {
                skipped.push(SkippedPath {
                    path: path.clone(),
                    reason: "file count limit exceeded".into(),
                });
                continue;
            }
            let relative_path = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            total_size += metadata.len();
            files.push(FileToSend {
                absolute_path: path.clone(),
                relative_path,
                size: metadata.len(),
                modified: metadata.modified().ok(),
                sha256: None,
                is_dir: false,
            });
        } else {
            skipped.push(SkippedPath {
                path: path.clone(),
                reason: "not a regular file or directory".into(),
            });
        }
    }

    ExpansionResult {
        files,
        total_size,
        skipped,
    }
}

/// Recursively walk a directory, adding `FileToSend` entries for each regular
/// file found. Empty subdirectories get `is_dir: true` marker entries.
fn walk_dir(
    dir: &Path,
    root_parent: &Path,
    files: &mut Vec<FileToSend>,
    total_size: &mut u64,
    skipped: &mut Vec<SkippedPath>,
    dir_has_files: &mut bool,
    depth: u16,
) {
    if depth >= MAX_DEPTH {
        skipped.push(SkippedPath {
            path: dir.to_path_buf(),
            reason: "maximum directory depth exceeded".into(),
        });
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            skipped.push(SkippedPath {
                path: dir.to_path_buf(),
                reason: format!("cannot read directory: {e}"),
            });
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                skipped.push(SkippedPath {
                    path: dir.to_path_buf(),
                    reason: format!("cannot read directory entry: {e}"),
                });
                continue;
            }
        };

        let path = entry.path();
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                skipped.push(SkippedPath {
                    path: path.clone(),
                    reason: format!("cannot read metadata: {e}"),
                });
                continue;
            }
        };

        if metadata.is_symlink() {
            skipped.push(SkippedPath {
                path,
                reason: "symlink skipped".into(),
            });
            continue;
        }

        if metadata.is_dir() {
            let mut sub_has_files = false;
            walk_dir(
                &path,
                root_parent,
                files,
                total_size,
                skipped,
                &mut sub_has_files,
                depth + 1,
            );

            if sub_has_files {
                *dir_has_files = true;
            } else {
                // Empty subdirectory: add marker
                let relative = path.strip_prefix(root_parent).unwrap_or(&path);
                let relative_path = normalize_relative_path(relative);
                files.push(FileToSend {
                    absolute_path: path,
                    relative_path,
                    size: 0,
                    modified: metadata.modified().ok(),
                    sha256: None,
                    is_dir: true,
                });
            }
        } else if metadata.is_file() {
            if files.len() >= MAX_FILE_COUNT {
                skipped.push(SkippedPath {
                    path: path.clone(),
                    reason: "file count limit exceeded".into(),
                });
                continue;
            }
            let relative = path.strip_prefix(root_parent).unwrap_or(&path);
            let relative_path = normalize_relative_path(relative);
            *total_size += metadata.len();
            files.push(FileToSend {
                absolute_path: path,
                relative_path,
                size: metadata.len(),
                modified: metadata.modified().ok(),
                sha256: None,
                is_dir: false,
            });
            *dir_has_files = true;
        }
        // Skip special files (FIFO, socket, device, etc.)
    }
}

impl FileManifest {
    /// Build a `FileManifest` from an already-expanded list of `FileToSend`.
    /// Drops `absolute_path` — only the protocol-level `relative_path` is kept.
    pub fn from_expanded(files: &[FileToSend]) -> Self {
        let entries: Vec<FileEntry> = files
            .iter()
            .map(|f| FileEntry {
                relative_path: f.relative_path.clone(),
                size: f.size,
                modified: f.modified,
                sha256: f.sha256.clone(),
                is_dir: f.is_dir,
            })
            .collect();
        let total_size = entries.iter().map(|e| e.size).sum();
        Self {
            files: entries,
            total_size,
        }
    }
}
