//! 续传已验证位图重建
//! 读 `.part` + `.part.meta` -> 重哈希各块比对 `chunk_hash_values` -> 重建位图。
//! 流式 seek+read 每块，内存有界（单块缓冲），不整体加载 .part。

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::StorageError;
use crate::sidecar::{part_meta_path, part_path, read_part_meta};

#[derive(Debug)]
pub struct SegmentBitmask {
    pub segment_id: u32,
    pub bitmask: Vec<u8>,
}

/// 最大合理 chunk 大小（4 MiB；防 OOM）。
const MAX_REASONABLE_CHUNK_SIZE: u64 = 4 * 1024 * 1024;

/// 最大合理 chunk 数量（防 bitmask 爆内存）。
const MAX_REASONABLE_CHUNK_COUNT: usize = 1 << 20;

/// 重建已验证位图（§9：抗畸形 sidecar：bound loop + cap alloc）。
pub fn rebuild_verified_bitmap(
    save_dir: &Path,
    transfer_id: &str,
    relative_path: &str,
) -> Result<Vec<SegmentBitmask>, StorageError> {
    let meta_path = part_meta_path(save_dir, transfer_id, relative_path)?;
    let part_path = part_path(save_dir, transfer_id, relative_path)?;
    let meta = read_part_meta(&meta_path)?;

    let mut file = match std::fs::File::open(&part_path) {
        Ok(f) => Some(f),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };

    let mut out = Vec::with_capacity(meta.segments.len());
    for seg in &meta.segments {
        // §9 sanity caps before allocation
        let chunk_size = seg.chunk_size as u64;
        if chunk_size > MAX_REASONABLE_CHUNK_SIZE {
            return Err(StorageError::Corrupt(format!(
                "chunk_size {} exceeds max {MAX_REASONABLE_CHUNK_SIZE}",
                seg.chunk_size
            )));
        }
        let chunk_count = seg.chunk_count as usize;
        if chunk_count > MAX_REASONABLE_CHUNK_COUNT {
            return Err(StorageError::Corrupt(format!(
                "chunk_count {} exceeds max {MAX_REASONABLE_CHUNK_COUNT}",
                seg.chunk_count
            )));
        }
        // §9 bound loop by available hashes (防 OOB)
        if !seg.chunk_hash_values.is_empty() && seg.chunk_hash_values.len() != chunk_count {
            return Err(StorageError::Corrupt(format!(
                "chunk_count {} != chunk_hash_values.len {}",
                seg.chunk_count,
                seg.chunk_hash_values.len()
            )));
        }
        let n = chunk_count.min(seg.chunk_hash_values.len());
        let mut bitmask = vec![0u8; chunk_count.div_ceil(8)];
        if !seg.chunk_hash_values.is_empty() && chunk_count > 0 {
            let cs = chunk_size;
            let mut buf = vec![0u8; cs as usize];
            for i in 0..n as u64 {
                let start = seg.offset + i * cs;
                let chunk_end = (start + cs).min(seg.offset + seg.length);
                let len = (chunk_end - start) as usize;
                if len == 0 {
                    continue;
                }
                let verified = match file.as_mut() {
                    Some(f) => {
                        if f.seek(SeekFrom::Start(start)).is_err() {
                            continue;
                        }
                        let mut filled = 0;
                        while filled < len {
                            match f.read(&mut buf[filled..len]) {
                                Ok(0) => break,
                                Ok(n) => filled += n,
                                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                                    continue;
                                }
                                Err(_) => break,
                            }
                        }
                        if filled < len {
                            continue;
                        }
                        let actual = privet_crypto::hash::blake3(&buf[..len]);
                        hex::encode(actual) == seg.chunk_hash_values[i as usize]
                    }
                    None => false,
                };
                if verified {
                    bitmask[(i / 8) as usize] |= 1 << (i % 8);
                }
            }
        }
        out.push(SegmentBitmask {
            segment_id: seg.segment_id,
            bitmask,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidecar::{build_initial_meta, write_part_meta_initial};
    use crate::{PartMeta, PartSegment};

    fn write_part(save_dir: &std::path::Path, transfer_id: &str, rel: &str, data: &[u8]) {
        let p = crate::sidecar::part_path(save_dir, transfer_id, rel).unwrap();
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    #[test]
    fn bitmap_matches_intact_part_corrupted_chunk_clears() {
        let dir = tempfile::tempdir().unwrap();
        let save = dir.path();
        let rel = "a.bin";
        let chunk0: &[u8] = b"AAAA";
        let chunk1: &[u8] = b"BBBB";
        let data = [chunk0, chunk1].concat();
        write_part(save, "t1", rel, &data);

        let h0 = hex::encode(privet_crypto::hash::blake3(chunk0));
        let h1 = hex::encode(privet_crypto::hash::blake3(chunk1));
        let meta = PartMeta {
            transfer_id: "t1".into(),
            file_id: "f1".into(),
            relative_path: rel.into(),
            size: 8,
            mtime_ms: 0,
            hash_type: "blake3".into(),
            hash_value: "full".into(),
            segments: vec![PartSegment {
                segment_id: 0,
                offset: 0,
                length: 8,
                chunk_count: 2,
                chunk_size: 4,
                hash_type: "blake3".into(),
                segment_hash_value: "root".into(),
                chunk_hash_values: vec![h0, h1],
            }],
        };
        let mp = crate::sidecar::part_meta_path(save, "t1", rel).unwrap();
        write_part_meta_initial(&mp, &meta).unwrap();

        let bm = rebuild_verified_bitmap(save, "t1", rel).unwrap();
        assert_eq!(bm.len(), 1);
        assert_eq!(bm[0].bitmask, vec![0b11]);

        // 篡改第 1 块 -> 其位清 0
        let mut corrupted = data.clone();
        corrupted[4..8].copy_from_slice(b"XXXX");
        write_part(save, "t1", rel, &corrupted);
        let bm = rebuild_verified_bitmap(save, "t1", rel).unwrap();
        assert_eq!(bm[0].bitmask, vec![0b01]);
    }

    #[test]
    fn segment_without_manifest_is_all_zero() {
        let dir = tempfile::tempdir().unwrap();
        let save = dir.path();
        let rel = "a.bin";
        write_part(save, "t1", rel, b"AAAABBBB");
        let mut meta = build_initial_meta("t1", "f1", rel, 8, 0, "full");
        meta.segments = vec![PartSegment {
            segment_id: 0,
            offset: 0,
            length: 8,
            chunk_count: 2,
            chunk_size: 4,
            hash_type: "blake3".into(),
            segment_hash_value: String::new(),
            chunk_hash_values: vec![],
        }];
        let mp = crate::sidecar::part_meta_path(save, "t1", rel).unwrap();
        write_part_meta_initial(&mp, &meta).unwrap();
        let bm = rebuild_verified_bitmap(save, "t1", rel).unwrap();
        assert_eq!(bm[0].bitmask, vec![0b00]);
    }
}
