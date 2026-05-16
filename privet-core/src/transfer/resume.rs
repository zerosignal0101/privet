use std::collections::HashMap;
use std::path::PathBuf;

use crate::session::FileEntry;

/// Check which files in a manifest can be resumed (partially received).
/// Returns a map from relative_path to bytes already received.
pub fn check_resume(
    download_dir: &PathBuf,
    files: &[FileEntry],
) -> HashMap<String, u64> {
    let mut resume_map = HashMap::new();

    for entry in files {
        let dest = download_dir.join(&entry.relative_path);
        if let Ok(meta) = std::fs::metadata(&dest) {
            let existing_size = meta.len();
            if existing_size > 0 && existing_size < entry.size {
                // Partial file exists — can resume
                resume_map.insert(entry.relative_path.clone(), existing_size);
            }
        }
    }

    resume_map
}

/// Check if a file is already fully received by comparing size and optionally hash.
pub fn is_complete(entry: &FileEntry, download_dir: &PathBuf) -> bool {
    let dest = download_dir.join(&entry.relative_path);
    if let Ok(meta) = std::fs::metadata(&dest) {
        if meta.len() == entry.size {
            // Size matches — could verify hash here for certainty
            return true;
        }
    }
    false
}
