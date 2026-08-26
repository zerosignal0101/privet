//! Preparing（前置态）：遍历发送根 -> FileEntry/DirEntry/FileSetSummary + 流式 BLAKE3。
//! 单次扫描产出整文件 BLAKE3 + 段根 + 逐块哈希（三级；段根随 manifest 流式发出，见 sender.rs）。

use std::path::{Path, PathBuf};

use crate::error::{Result, TransferError};
use crate::events::{TransferEvent, TransferEventSink};
use crate::integrity::{chunk_hash, file_hash_streaming, segment_root, SegmentHashes};
use crate::MAX_FILES_PER_TRANSFER;
use privet_crypto::hash::StreamingHasher;
use privet_protocol::layout::derive_segment_layout;
use privet_protocol::path::{sanitize_relative_path, sanitize_root_name};
use privet_protocol::{DirEntry, FileEntry, FileSetSummary};

/// 单文件准备结果（含 manifest 所需哈希）。
#[derive(Debug, Clone)]
pub struct PreparedFile {
    pub file_id: String,
    pub relative_path: String,
    pub abs_path: PathBuf,
    pub size: u64,
    pub mtime_ms: u64,
    pub inline: bool,
    pub inline_data: Option<Vec<u8>>,
    pub file_hash: String,
    pub segments: Vec<SegmentHashes>,
}

impl PreparedFile {
    pub fn to_entry(&self) -> FileEntry {
        FileEntry {
            file_id: self.file_id.clone(),
            relative_path: self.relative_path.clone(),
            size: self.size,
            mtime_ms: self.mtime_ms,
            hash_type: "blake3".into(),
            hash_value: self.file_hash.clone(),
        }
    }
}

/// 准备好的文件集。
#[derive(Debug, Clone)]
pub struct PreparedSet {
    pub root_name: Option<String>,
    pub files: Vec<PreparedFile>,
    pub dirs: Vec<DirEntry>,
    pub summary: FileSetSummary,
}

/// 判断文件数是否在 DoS 上限内。
pub fn is_within_file_limit(count: u64) -> bool {
    count <= MAX_FILES_PER_TRANSFER
}

/// 准备单文件（offset_id 仅用于生成 file_id）。
pub fn prepare_single_file(
    root: &Path,
    rel: &str,
    offset_id: u64,
    chunk_size: u32,
    seg_max_chunks: u32,
) -> Result<PreparedFile> {
    tracing::debug!(rel = %rel, chunk_size, seg_max_chunks, "prepare_single_file start");
    let sanitized = sanitize_relative_path(rel)?;
    let abs = root.join(rel);
    let meta = std::fs::metadata(&abs)?;
    let size = meta.len();
    let mtime_ms = meta
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let file_id = format!("f{offset_id}");
    let inline = size <= crate::INLINE_FILE_THRESHOLD as u64;

    let mut file_hasher = StreamingHasher::new();
    let mut f = std::fs::File::open(&abs)?;
    use std::io::{Read, Seek, SeekFrom};
    let layout = derive_segment_layout(size, chunk_size, seg_max_chunks);
    let cs = chunk_size as usize;
    let mut segments = Vec::with_capacity(layout.len());
    let mut buf = vec![0u8; cs];
    let mut inline_data: Option<Vec<u8>> = if inline {
        Some(Vec::with_capacity(size as usize))
    } else {
        None
    };

    for seg in &layout {
        let mut chunk_hashes = Vec::with_capacity(seg.chunk_count as usize);
        for ci in 0..seg.chunk_count {
            let start = seg.offset + ci as u64 * cs as u64;
            f.seek(SeekFrom::Start(start))?;
            let mut filled = 0usize;
            let target = cs;
            while filled < target {
                let n = f.read(&mut buf[filled..])?;
                if n == 0 {
                    break;
                }
                file_hasher.update(&buf[filled..filled + n]);
                if let Some(id) = inline_data.as_mut() {
                    id.extend_from_slice(&buf[filled..filled + n]);
                }
                filled += n;
            }
            let chunk_data = &buf[..filled];
            chunk_hashes.push(chunk_hash(chunk_data));
        }
        let root = segment_root(&chunk_hashes);
        tracing::trace!(segment_id = seg.segment_id, chunk_count = seg.chunk_count, segment_root = %root, "prepared segment");
        segments.push(SegmentHashes {
            segment_id: seg.segment_id,
            blake3_root: root,
            chunk_hashes,
        });
    }
    drop(f);
    let file_hash = if inline {
        let data = inline_data.clone().unwrap_or_default();
        file_hash_streaming(&[data.as_slice()])?
    } else {
        hex::encode(file_hasher.finalize())
    };

    tracing::debug!(rel = %rel, file_hash = %file_hash, segments = segments.len(), "prepare_single_file done");
    Ok(PreparedFile {
        file_id,
        relative_path: sanitized.into_string(),
        abs_path: abs,
        size,
        mtime_ms,
        inline,
        inline_data,
        file_hash,
        segments,
    })
}

/// 遍历发送根，准备整个文件集。
pub fn prepare_dir(
    root: &Path,
    root_name: Option<&str>,
    start_offset: u64,
    chunk_size: u32,
    seg_max_chunks: u32,
) -> Result<PreparedSet> {
    let sanitized_root = sanitize_root_name(root_name.unwrap_or(""))?;
    let root_name_clean: Option<String> = sanitized_root.map(|s| s.into_string());

    let mut files = Vec::new();
    let mut dirs_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut total_bytes = 0u64;
    let mut visited = std::collections::HashSet::new();
    walk_for_prepare(
        root,
        root,
        &mut files,
        &mut dirs_set,
        &mut total_bytes,
        &mut visited,
        start_offset,
        chunk_size,
        seg_max_chunks,
    )?;

    if !is_within_file_limit(files.len() as u64) {
        return Err(TransferError::TooManyFiles(
            files.len() as u64,
            MAX_FILES_PER_TRANSFER,
        ));
    }

    let dirs: Vec<DirEntry> = dirs_set
        .into_iter()
        .map(|p| DirEntry { relative_path: p })
        .collect();
    let summary = FileSetSummary {
        root_name: root_name_clean.clone().unwrap_or_default(),
        file_count: files.len() as u64,
        total_bytes,
        dir_count: dirs.len() as u64,
    };
    Ok(PreparedSet {
        root_name: root_name_clean,
        files,
        dirs,
        summary,
    })
}

/// 带进度回调的 async prepare 版本（emit PreparingProgress 给事件收集器）。
pub async fn prepare_dir_streaming(
    root: &Path,
    root_name: Option<&str>,
    start_offset: u64,
    chunk_size: u32,
    seg_max_chunks: u32,
    sink: &dyn TransferEventSink,
    transfer_id: &str,
) -> Result<PreparedSet> {
    // Phase 1: 快速遍历统计 total_bytes 及文件列表（不哈希）
    let sanitized_root = sanitize_root_name(root_name.unwrap_or(""))?;
    let root_name_clean: Option<String> = sanitized_root.map(|s| s.into_string());

    let mut file_infos: Vec<(String, PathBuf, u64)> = Vec::new();
    let mut dirs_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut total_bytes = 0u64;
    let mut visited = std::collections::HashSet::new();
    walk_for_count(
        root,
        root,
        &mut file_infos,
        &mut dirs_set,
        &mut total_bytes,
        &mut visited,
    )?;

    if !is_within_file_limit(file_infos.len() as u64) {
        return Err(crate::TransferError::TooManyFiles(
            file_infos.len() as u64,
            MAX_FILES_PER_TRANSFER,
        ));
    }

    // Phase 2: 逐文件哈希 + 进度回调
    let mut files = Vec::with_capacity(file_infos.len());
    let mut scanned_bytes = 0u64;
    for (i, (rel_str, _abs_path, _size)) in file_infos.iter().enumerate() {
        let pf = prepare_single_file(
            root,
            rel_str,
            start_offset + i as u64,
            chunk_size,
            seg_max_chunks,
        )?;
        scanned_bytes += pf.size;
        files.push(pf);
        sink.emit(TransferEvent::PreparingProgress {
            transfer_id: transfer_id.into(),
            scanned_bytes,
            total_bytes,
        })
        .await;
    }

    let dirs: Vec<DirEntry> = dirs_set
        .into_iter()
        .map(|p| DirEntry { relative_path: p })
        .collect();
    let summary = FileSetSummary {
        root_name: root_name_clean.clone().unwrap_or_default(),
        file_count: files.len() as u64,
        total_bytes,
        dir_count: dirs.len() as u64,
    };
    Ok(PreparedSet {
        root_name: root_name_clean,
        files,
        dirs,
        summary,
    })
}

/// 轻量遍历：只统计文件路径和大小，不哈希。
fn walk_for_count(
    root: &Path,
    cur: &Path,
    infos: &mut Vec<(String, PathBuf, u64)>,
    dirs: &mut std::collections::BTreeSet<String>,
    total_bytes: &mut u64,
    visited: &mut std::collections::HashSet<PathBuf>,
) -> Result<()> {
    for entry in std::fs::read_dir(cur)? {
        let entry = entry?;
        let path = entry.path();
        if !visited.insert(path.clone()) {
            continue;
        }
        let rel = path.strip_prefix(root).unwrap();
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if entry.file_type()?.is_dir() {
            if let Ok(s) = sanitize_relative_path(&rel_str) {
                dirs.insert(s.into_string());
            }
            walk_for_count(root, &path, infos, dirs, total_bytes, visited)?;
        } else if entry.file_type()?.is_file() {
            let meta = entry.metadata()?;
            let size = meta.len();
            *total_bytes += size;
            if let Some(parent) = rel.parent() {
                let parent_str = parent.to_string_lossy().replace('\\', "/");
                if !parent_str.is_empty() {
                    if let Ok(s) = sanitize_relative_path(&parent_str) {
                        dirs.insert(s.into_string());
                    }
                }
            }
            infos.push((rel_str, path, size));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_for_prepare(
    root: &Path,
    cur: &Path,
    files: &mut Vec<PreparedFile>,
    dirs: &mut std::collections::BTreeSet<String>,
    total_bytes: &mut u64,
    visited: &mut std::collections::HashSet<PathBuf>,
    next_offset: u64,
    chunk_size: u32,
    seg_max_chunks: u32,
) -> Result<()> {
    for entry in std::fs::read_dir(cur)? {
        let entry = entry?;
        let path = entry.path();
        if !visited.insert(path.clone()) {
            continue;
        }
        let rel = path.strip_prefix(root).unwrap();
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if entry.file_type()?.is_dir() {
            if let Ok(s) = sanitize_relative_path(&rel_str) {
                dirs.insert(s.into_string());
            }
            walk_for_prepare(
                root,
                &path,
                files,
                dirs,
                total_bytes,
                visited,
                next_offset + files.len() as u64,
                chunk_size,
                seg_max_chunks,
            )?;
        } else if entry.file_type()?.is_file() {
            let pf = prepare_single_file(
                root,
                &rel_str,
                next_offset + files.len() as u64,
                chunk_size,
                seg_max_chunks,
            )?;
            *total_bytes += pf.size;
            if let Some(parent) = rel.parent() {
                let parent_str = parent.to_string_lossy().replace('\\', "/");
                if !parent_str.is_empty() {
                    if let Ok(s) = sanitize_relative_path(&parent_str) {
                        dirs.insert(s.into_string());
                    }
                }
            }
            files.push(pf);
        }
    }
    Ok(())
}
