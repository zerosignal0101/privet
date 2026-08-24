//! 存储层路径纵深防御：入库前用 protocol 清洗器复验

use crate::error::StorageError;
use privet_protocol::path::{sanitize_relative_path, sanitize_root_name};

/// 复验 relative_path，返回规范化串（`/` 分隔）。拒 -> StorageError::Path。
pub fn guard_relative_path(p: &str) -> Result<String, StorageError> {
    sanitize_relative_path(p)
        .map(|s| s.into_string())
        .map_err(|e| StorageError::Path(format!("relative_path: {e:?}")))
}

/// 复验 root_name：空 -> None；非空 -> Some(规范化)。
pub fn guard_root_name(p: &str) -> Result<Option<String>, StorageError> {
    sanitize_root_name(p)
        .map(|opt| opt.map(|s| s.into_string()))
        .map_err(|e| StorageError::Path(format!("root_name: {e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsafe_relative_paths() {
        for bad in ["../x", "/abs", "C:foo", "a\0b", ""] {
            assert!(guard_relative_path(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn accepts_and_normalizes_safe_relative_paths() {
        assert_eq!(guard_relative_path("a/b.txt").unwrap(), "a/b.txt");
        assert_eq!(guard_relative_path("a\\b\\c").unwrap(), "a/b/c");
        assert_eq!(guard_relative_path("a/./b").unwrap(), "a/b");
    }

    #[test]
    fn guard_root_name_empty_none_nonempty_some_and_rejects_bad() {
        assert_eq!(guard_root_name("").unwrap(), None);
        assert_eq!(guard_root_name("Pics").unwrap().as_deref(), Some("Pics"));
        assert!(guard_root_name("../").is_err());
        assert!(guard_root_name("a/b").is_err());
    }
}
