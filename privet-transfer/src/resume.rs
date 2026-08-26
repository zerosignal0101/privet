//! 续传决策：receiver 重读 .part 重哈希比对 manifest -> 已验证位图；
//! manifest 变更（size/blake3 不符）-> 丢弃 .part 全量重发。

use std::collections::HashMap;

use privet_protocol::ChunkBitmask;
use privet_storage::resume::SegmentBitmask;
use privet_storage::PartMeta;

use crate::error::Result;
use crate::part_store::PartStore;

/// 为文件集构建 resume 位图（offer 前调用；从 .part+sidecar 重建）。
pub fn build_resume_bitmasks(
    store: &dyn PartStore,
    transfer_id: &str,
    files: &[(String, String)],
) -> Result<HashMap<String, Vec<ChunkBitmask>>> {
    let mut out = HashMap::new();
    for (file_id, rel) in files {
        let segs: Vec<SegmentBitmask> = match store.rebuild_resume_bitmask(transfer_id, rel) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let bitmasks: Vec<ChunkBitmask> = segs
            .into_iter()
            .map(|s| ChunkBitmask {
                file_id: file_id.clone(),
                segment_id: s.segment_id,
                bitmask: s.bitmask,
            })
            .collect();
        out.insert(file_id.clone(), bitmasks);
    }
    Ok(out)
}

/// manifest 是否变更（receiver 比对 sidecar PartMeta vs 新 FileEntry 标识）。
pub fn manifest_changed(meta: &PartMeta, new_size: u64, new_hash_value: &str) -> bool {
    meta.size != new_size || meta.hash_value != new_hash_value
}

/// 丢弃某文件 .part + meta（manifest 变更时）。
pub fn discard_part(store: &dyn PartStore, transfer_id: &str, rel: &str) -> Result<()> {
    store.delete_part(transfer_id, rel)
}
