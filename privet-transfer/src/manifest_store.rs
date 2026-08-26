//! Receiver 端 manifest 存储 + 到货三态裁决。
//! manifest 已到 + 哈希命中 -> Verified；已到 + 不符 -> Mismatch；未到 -> Pending（缓冲，不丢/不写/不 ack）。

use std::collections::HashMap;

use privet_protocol::SegmentManifest;

use crate::integrity::{verify_chunk, verify_segment_root};

/// 到货裁决。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArrivalVerdict {
    Verified,
    Mismatch,
    Pending,
}

/// manifest 未到时缓冲的块（三态之缓冲态）。
#[derive(Debug, Clone)]
pub struct PendingChunk {
    pub file_id: String,
    pub segment_id: u32,
    pub chunk_index: u64,
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Default)]
struct SegmentManifestEntry {
    chunk_hashes: Vec<String>,
    segment_hash_value: String,
}

/// per file_id -> per segment_id -> manifest。
#[derive(Debug, Default)]
pub struct ReceiverManifestStore {
    manifests: HashMap<String, HashMap<u32, SegmentManifestEntry>>,
    pending: HashMap<(String, u32), Vec<PendingChunk>>,
}

impl ReceiverManifestStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 存储到达的 manifest。
    pub fn store_manifest(&mut self, m: &SegmentManifest) {
        let entry = SegmentManifestEntry {
            chunk_hashes: m.chunk_hash_values.clone(),
            segment_hash_value: m.segment_hash_value.clone(),
        };
        self.manifests
            .entry(m.file_id.clone())
            .or_default()
            .insert(m.segment_id, entry);
    }

    pub fn has_manifest(&self, file_id: &str, segment_id: u32) -> bool {
        self.manifests
            .get(file_id)
            .map(|m| m.contains_key(&segment_id))
            .unwrap_or(false)
    }

    /// 某文件某段的块数（chunk_hashes.len()；all_set 对照用）。
    pub fn segment_chunk_count(&self, file_id: &str, segment_id: u32) -> Option<u32> {
        self.manifests
            .get(file_id)
            .and_then(|segments| segments.get(&segment_id))
            .map(|s| s.chunk_hashes.len() as u32)
    }

    /// 某文件的总块数（各段 chunk_hashes.len() 之和；完整性用）。
    pub fn chunk_count_for_file(&self, file_id: &str) -> u32 {
        self.manifests
            .get(file_id)
            .map(|segments| segments.values().map(|s| s.chunk_hashes.len() as u32).sum())
            .unwrap_or(0)
    }

    /// 段根校验（段内块全验证后调用）。
    pub fn verify_segment_root(&self, file_id: &str, segment_id: u32) -> bool {
        let Some(seg) = self.manifests.get(file_id).and_then(|m| m.get(&segment_id)) else {
            return false;
        };
        verify_segment_root(&seg.chunk_hashes, &seg.segment_hash_value)
    }

    /// 到货裁决。
    pub fn classify_arrival(
        &self,
        file_id: &str,
        segment_id: u32,
        chunk_index: u64,
        data: &[u8],
    ) -> ArrivalVerdict {
        let Some(seg) = self.manifests.get(file_id).and_then(|m| m.get(&segment_id)) else {
            return ArrivalVerdict::Pending;
        };
        let idx = chunk_index as usize;
        if idx >= seg.chunk_hashes.len() {
            tracing::warn!(
                file_id = %file_id, segment_id, chunk_index,
                expected = seg.chunk_hashes.len(),
                "chunk arrival mismatch: index out of manifest range"
            );
            return ArrivalVerdict::Mismatch;
        }
        let expected = &seg.chunk_hashes[idx];
        if verify_chunk(data, expected) {
            ArrivalVerdict::Verified
        } else {
            let actual = crate::integrity::chunk_hash(data);
            tracing::warn!(
                file_id = %file_id, segment_id, chunk_index,
                expected_hash = %expected,
                actual_hash = %actual,
                "chunk arrival mismatch: hash mismatch (prepare vs send read inconsistent?)"
            );
            ArrivalVerdict::Mismatch
        }
    }

    /// 缓冲 pending 块。
    pub fn buffer_pending(&mut self, p: PendingChunk) {
        self.pending
            .entry((p.file_id.clone(), p.segment_id))
            .or_default()
            .push(p);
    }

    pub fn pending_count(&self, file_id: &str, segment_id: u32) -> usize {
        self.pending
            .get(&(file_id.to_string(), segment_id))
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// manifest 到达后回灌 pending 块（返回拷贝供 receiver 校验/写盘）。
    pub fn drain_pending(&mut self, file_id: &str, segment_id: u32) -> Vec<PendingChunk> {
        self.pending
            .remove(&(file_id.to_string(), segment_id))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for CaptureWriter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn mismatch_logs_chunk_identity_and_hashes() {
        let cap = CaptureWriter(Arc::new(Mutex::new(Vec::new())));
        let sub = tracing_subscriber::fmt()
            .with_writer(cap.clone())
            .with_max_level(tracing::Level::WARN)
            .with_target(false)
            .finish();
        let mut store = ReceiverManifestStore::new();
        let good = crate::integrity::chunk_hash(b"good");
        store.store_manifest(&SegmentManifest {
            file_id: "f0".into(),
            segment_id: 0,
            hash_type: "blake3".into(),
            chunk_hash_values: vec![good.clone()],
            segment_hash_value: String::new(),
        });
        let bad_data = b"bad";
        tracing::subscriber::with_default(sub, || {
            let _ = store.classify_arrival("f0", 0, 0, bad_data);
        });
        let s = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        assert!(s.contains("mismatch"), "expected mismatch marker: {s}");
        assert!(s.contains("f0"), "expected file_id: {s}");
        assert!(
            s.contains("segment_id") || s.contains("segment"),
            "expected segment: {s}"
        );
        assert!(s.contains(&good[..8]), "expected expected-hash prefix: {s}");
    }
}
