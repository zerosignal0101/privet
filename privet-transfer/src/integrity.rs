//! BLAKE3 三级完整性：逐块 / 段根 / 整文件。
//! 段根定义：BLAKE3( 各块哈希 hex 串按序串接 )（sender/receiver 同法；根随 manifest 流式）。

use crate::error::Result;
use privet_crypto::hash::{blake3, StreamingHasher};
use privet_protocol::layout::derive_segment_layout;

/// 逐块 BLAKE3 hex。
pub fn chunk_hash(data: &[u8]) -> String {
    hex::encode(blake3(data))
}

/// 校验单块。
pub fn verify_chunk(data: &[u8], expected_hex: &str) -> bool {
    let actual = chunk_hash(data);
    let ok = actual == expected_hex;
    if !ok {
        tracing::debug!(expected = %expected_hex, actual = %actual, "verify_chunk failed");
    }
    ok
}

/// 段根：BLAKE3( 串接各块哈希 hex 串 ) hex。
pub fn segment_root(chunk_hashes: &[String]) -> String {
    let mut concat = String::with_capacity(chunk_hashes.len() * 64);
    for h in chunk_hashes {
        concat.push_str(h);
    }
    hex::encode(blake3(concat.as_bytes()))
}

/// 校验段根。
pub fn verify_segment_root(chunk_hashes: &[String], expected_root_hex: &str) -> bool {
    segment_root(chunk_hashes) == expected_root_hex
}

/// 流式整文件 BLAKE3 hex（接受多段切片，便于大文件分块喂入）。
pub fn file_hash_streaming(parts: &[&[u8]]) -> Result<String> {
    let mut h = StreamingHasher::new();
    for p in parts {
        h.update(p);
    }
    Ok(hex::encode(h.finalize()))
}

/// 单段哈希结果（manifest 用）。
#[derive(Debug, Clone)]
pub struct SegmentHashes {
    pub segment_id: u32,
    pub blake3_root: String,
    pub chunk_hashes: Vec<String>,
}

/// 文件三级哈希结果。
#[derive(Debug, Clone)]
pub struct FileHashes {
    pub file_hash: String,
    pub segments: Vec<SegmentHashes>,
}

/// 一次性计算文件三级哈希（整文件已在内存；大文件用 Preparing 流式版本，见 prepare.rs）。
pub fn compute_file_hashes(
    data: &[u8],
    chunk_size: u32,
    seg_max_chunks: u32,
) -> Result<FileHashes> {
    let size = data.len() as u64;
    let layout = derive_segment_layout(size, chunk_size, seg_max_chunks);
    let cs = chunk_size as usize;
    let mut segments = Vec::with_capacity(layout.len());
    for seg in &layout {
        let mut chunk_hashes = Vec::with_capacity(seg.chunk_count as usize);
        for ci in 0..seg.chunk_count as usize {
            let start = seg.offset as usize + ci * cs;
            let end = (start + cs).min(data.len());
            chunk_hashes.push(chunk_hash(&data[start..end]));
        }
        let root = segment_root(&chunk_hashes);
        segments.push(SegmentHashes {
            segment_id: seg.segment_id,
            blake3_root: root,
            chunk_hashes,
        });
    }
    let file_hash = file_hash_streaming(&[data])?;
    Ok(FileHashes {
        file_hash,
        segments,
    })
}
