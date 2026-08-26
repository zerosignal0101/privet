
use crate::error::Result;
use privet_crypto::hash::{blake3, StreamingHasher};
use privet_protocol::layout::derive_segment_layout;

pub fn chunk_hash(data: &[u8]) -> String {
    hex::encode(blake3(data))
}

pub fn verify_chunk(data: &[u8], expected_hex: &str) -> bool {
    let actual = chunk_hash(data);
    let ok = actual == expected_hex;
    if !ok {
        tracing::debug!(expected = %expected_hex, actual = %actual, "verify_chunk failed");
    }
    ok
}

pub fn segment_root(chunk_hashes: &[String]) -> String {
    let mut concat = String::with_capacity(chunk_hashes.len() * 64);
    for h in chunk_hashes {
        concat.push_str(h);
    }
    hex::encode(blake3(concat.as_bytes()))
}

pub fn verify_segment_root(chunk_hashes: &[String], expected_root_hex: &str) -> bool {
    segment_root(chunk_hashes) == expected_root_hex
}

pub fn file_hash_streaming(parts: &[&[u8]]) -> Result<String> {
    let mut h = StreamingHasher::new();
    for p in parts {
        h.update(p);
    }
    Ok(hex::encode(h.finalize()))
}

#[derive(Debug, Clone)]
pub struct SegmentHashes {
    pub segment_id: u32,
    pub blake3_root: String,
    pub chunk_hashes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FileHashes {
    pub file_hash: String,
    pub segments: Vec<SegmentHashes>,
}

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
