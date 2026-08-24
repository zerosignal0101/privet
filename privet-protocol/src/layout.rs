//! 段布局 derived：由 `size`+`chunk_size`+`seg_max_chunks` 计算。
//! sender/receiver/storage(sidecar 骨架) 同法，不入 offer。

use crate::constants::{DEFAULT_CHUNK_SIZE, SEGMENT_MAX_CHUNKS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentLayout {
    pub segment_id: u32,
    pub offset: u64,
    pub length: u64,
    pub chunk_count: u32,
    pub chunk_size: u32,
}

/// 派生段布局。`size==0` -> 空。每段至多 `seg_max_chunks` 块；末块可小于 `chunk_size`。
pub fn derive_segment_layout(
    size: u64,
    chunk_size: u32,
    seg_max_chunks: u32,
) -> Vec<SegmentLayout> {
    if size == 0 || chunk_size == 0 || seg_max_chunks == 0 {
        return Vec::new();
    }
    let cs = chunk_size as u64;
    let total_chunks = size.div_ceil(cs);
    let num_segments = total_chunks.div_ceil(seg_max_chunks as u64);
    let mut out = Vec::with_capacity(num_segments as usize);
    let seg_max = seg_max_chunks as u64;
    for seg in 0..num_segments {
        let start_chunk = seg * seg_max;
        let end_chunk = (start_chunk + seg_max).min(total_chunks);
        let seg_chunk_count = end_chunk - start_chunk;
        let offset = start_chunk * cs;
        let last_in_seg_idx = end_chunk - 1;
        let is_file_last = last_in_seg_idx == total_chunks - 1;
        let last_chunk_size = if is_file_last {
            size - last_in_seg_idx * cs
        } else {
            cs
        };
        let length = (seg_chunk_count - 1) * cs + last_chunk_size;
        out.push(SegmentLayout {
            segment_id: seg as u32,
            offset,
            length,
            chunk_count: seg_chunk_count as u32,
            chunk_size,
        });
    }
    out
}

/// 用默认常量（DEFAULT_CHUNK_SIZE=1MiB、SEGMENT_MAX_CHUNKS=1024）派生。
pub fn derive_segment_layout_default(size: u64) -> Vec<SegmentLayout> {
    derive_segment_layout(size, DEFAULT_CHUNK_SIZE as u32, SEGMENT_MAX_CHUNKS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_no_segments() {
        assert!(derive_segment_layout(0, 1024, 8).is_empty());
    }

    #[test]
    fn single_partial_chunk() {
        let s = derive_segment_layout(500, 1024, 8);
        assert_eq!(s.len(), 1);
        assert_eq!(
            s[0],
            SegmentLayout {
                segment_id: 0,
                offset: 0,
                length: 500,
                chunk_count: 1,
                chunk_size: 1024
            }
        );
    }

    #[test]
    fn multiple_chunks_one_segment() {
        let s = derive_segment_layout(3000, 1024, 8);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].chunk_count, 3);
        assert_eq!(s[0].length, 3000);
        assert_eq!(s[0].offset, 0);
    }

    #[test]
    fn spans_two_segments_at_boundary() {
        // seg_max=8 -> 8 块满段 + 余 1 块 = 2 段；size = 8*100 + 30 = 830
        let s = derive_segment_layout(830, 100, 8);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].segment_id, 0);
        assert_eq!(s[0].chunk_count, 8);
        assert_eq!(s[0].length, 800);
        assert_eq!(s[0].offset, 0);
        assert_eq!(s[1].segment_id, 1);
        assert_eq!(s[1].chunk_count, 1);
        assert_eq!(s[1].length, 30);
        assert_eq!(s[1].offset, 800);
    }

    #[test]
    fn total_length_equals_size() {
        for &size in &[1u64, 100, 1023, 1024, 1025, 8192, 1_000_000] {
            let s = derive_segment_layout(size, 1024, 4);
            let total: u64 = s.iter().map(|x| x.length).sum();
            assert_eq!(total, size, "size={size}");
            assert!(s.iter().all(|x| x.chunk_count <= 4));
        }
    }
}
