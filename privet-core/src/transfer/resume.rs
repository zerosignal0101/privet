use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::session::FileEntry;

/// Returns true if two timestamps are within `tolerance_secs` of each other.
fn mtime_matches(actual: SystemTime, expected: SystemTime, tolerance_secs: u64) -> bool {
    let diff = if actual > expected {
        actual.duration_since(expected).unwrap_or_default().as_secs()
    } else {
        expected.duration_since(actual).unwrap_or_default().as_secs()
    };
    diff <= tolerance_secs
}

/// Check which files in a manifest can be resumed (partially received).
/// Uses name+size+mtime to verify the partial file hasn't been modified.
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

            // Must be a partial file (non-empty but smaller than expected)
            if existing_size == 0 || existing_size >= entry.size {
                continue;
            }

            // Verify mtime hasn't changed (file not modified since original transfer)
            let mt_ok = match entry.modified {
                Some(expected_mtime) => meta
                    .modified()
                    .ok()
                    .map_or(true, |actual| mtime_matches(actual, expected_mtime, 2)),
                None => true, // No mtime info, assume match
            };

            if mt_ok {
                resume_map.insert(entry.relative_path.clone(), existing_size);
            }
        }
    }

    resume_map
}

/// Check if a file is already fully received by name+size+mtime.
pub fn is_complete(entry: &FileEntry, download_dir: &PathBuf) -> bool {
    let dest = download_dir.join(&entry.relative_path);
    if let Ok(meta) = std::fs::metadata(&dest) {
        if meta.len() != entry.size {
            return false;
        }
        // Verify mtime matches if available
        if let Some(expected_mtime) = entry.modified {
            if let Ok(actual_mtime) = meta.modified() {
                return mtime_matches(actual_mtime, expected_mtime, 2);
            }
        }
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn mtime_within_tolerance() {
        let now = SystemTime::now();
        assert!(mtime_matches(now, now, 0));
        assert!(mtime_matches(now - Duration::from_secs(1), now, 2));
        assert!(mtime_matches(now + Duration::from_secs(1), now, 2));
        assert!(!mtime_matches(now - Duration::from_secs(5), now, 2));
    }
}
