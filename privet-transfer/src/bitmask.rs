//! 已验证位图：与 ChunkAck 语义对齐，仅置已验证块。

use privet_protocol::ChunkBitmask;

/// 单段已验证位图。
#[derive(Debug, Clone)]
pub struct VerifiedBitmask {
    bits: Vec<u8>,
    n: u32,
}

impl VerifiedBitmask {
    pub fn new(chunk_count: u32) -> Self {
        let bytes = (chunk_count as usize).div_ceil(8);
        Self {
            bits: vec![0u8; bytes],
            n: chunk_count,
        }
    }

    /// 全零空段（chunk_count=0）。
    pub fn empty_segment(_segment_id: u32) -> Self {
        Self::new(0)
    }

    pub fn set(&mut self, idx: u32) {
        if idx < self.n {
            self.bits[(idx / 8) as usize] |= 1 << (idx % 8);
        }
    }

    pub fn is_set(&self, idx: u32) -> bool {
        if idx >= self.n {
            return false;
        }
        self.bits[(idx / 8) as usize] & (1 << (idx % 8)) != 0
    }

    pub fn count_set(&self) -> u32 {
        (0..self.n).filter(|&i| self.is_set(i)).count() as u32
    }

    pub fn all_set(&self) -> bool {
        self.count_set() == self.n
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    pub fn chunk_count(&self) -> u32 {
        self.n
    }

    /// 从 proto ChunkBitmask 还原（resume 比对用）。
    #[allow(dead_code)]
    pub fn from_bytes(bytes: &[u8], chunk_count: u32) -> Self {
        let mut bm = Self::new(chunk_count);
        let copy = bytes.len().min(bm.bits.len());
        bm.bits[..copy].copy_from_slice(&bytes[..copy]);
        bm
    }

    /// 返回所有已置位的块索引（ChunkAck 用）。
    pub fn set_bits(&self) -> Vec<u64> {
        (0..self.n)
            .filter(|&i| self.is_set(i))
            .map(|i| i as u64)
            .collect()
    }

    /// -> proto ChunkBitmask。
    pub fn to_chunk_bitmask(&self, file_id: &str, segment_id: u32) -> ChunkBitmask {
        ChunkBitmask {
            file_id: file_id.into(),
            segment_id,
            bitmask: self.bits.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_bytes() {
        let mut bm = VerifiedBitmask::new(16);
        bm.set(0);
        bm.set(7);
        bm.set(15);
        let bytes = bm.as_bytes().to_vec();
        let back = VerifiedBitmask::from_bytes(&bytes, 16);
        assert!(back.is_set(0));
        assert!(back.is_set(7));
        assert!(back.is_set(15));
        assert!(!back.is_set(1));
        assert!(!bm.all_set());
        bm.set(1);
        bm.set(2);
        bm.set(3);
        bm.set(4);
        bm.set(5);
        bm.set(6);
        bm.set(8);
        bm.set(9);
        bm.set(10);
        bm.set(11);
        bm.set(12);
        bm.set(13);
        bm.set(14);
        assert!(bm.all_set());
        assert_eq!(bm.count_set(), 16);
    }
}
