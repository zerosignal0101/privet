//! 路径清洗器：拒 `..`/绝对/盘符/null；规范分隔符为 `/`；限深度长度。
//! `root_name` 空串允许（= 不加落地夹层）；非空作单段夹层。

use crate::error::PathError;

pub const MAX_PATH_DEPTH: usize = 64;
pub const MAX_PATH_BYTES: usize = 4096;

/// 清洗后的相对路径（`/` 分隔）。newtype 防止误用未清洗串。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SanitizedPath(String);

impl SanitizedPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub fn into_string(self) -> String {
        self.0
    }
}

/// 清洗 `relative_path`（FileEntry/DirEntry）。归一化分隔符，拒越界/绝对/盘符/null。
pub fn sanitize_relative_path(path: &str) -> Result<SanitizedPath, PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    if path.bytes().any(|b| b == 0) {
        return Err(PathError::NullByte);
    }
    let first = path.chars().next().unwrap();
    if matches!(first, '/' | '\\') {
        return Err(PathError::Absolute);
    }
    let mut segments: Vec<&str> = Vec::new();
    for seg in path.split(['/', '\\']) {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(PathError::ParentRef);
        }
        if is_drive_letter(seg) {
            return Err(PathError::DriveLetter);
        }
        segments.push(seg);
    }
    if segments.is_empty() {
        return Err(PathError::Empty);
    }
    if segments.len() > MAX_PATH_DEPTH {
        return Err(PathError::TooDeep(MAX_PATH_DEPTH));
    }
    let joined = segments.join("/");
    if joined.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong(MAX_PATH_BYTES));
    }
    Ok(SanitizedPath(joined))
}

/// 清洗 `root_name`：空 -> `None`（不加夹层）；非空须为单段。
pub fn sanitize_root_name(name: &str) -> Result<Option<SanitizedPath>, PathError> {
    if name.is_empty() {
        return Ok(None);
    }
    if name.bytes().any(|b| b == 0) {
        return Err(PathError::NullByte);
    }
    if name.contains(['/', '\\']) {
        return Err(PathError::NotSingleComponent);
    }
    if name == ".." || name == "." {
        return Err(PathError::ParentRef);
    }
    if is_drive_letter(name) {
        return Err(PathError::DriveLetter);
    }
    if name.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong(MAX_PATH_BYTES));
    }
    Ok(Some(SanitizedPath(name.to_string())))
}

/// 检测形如 `C:` / `C:foo` 的盘符段（跨平台安全：拒绝任何「字母:」前缀段）。
fn is_drive_letter(seg: &str) -> bool {
    let mut chars = seg.chars();
    matches!((chars.next(), chars.next()), (Some(a), Some(':')) if a.is_ascii_alphabetic())
}
