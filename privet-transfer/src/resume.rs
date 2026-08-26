
use std::collections::HashMap;

use privet_protocol::ChunkBitmask;
use privet_storage::resume::SegmentBitmask;
use privet_storage::PartMeta;

use crate::error::Result;
use crate::part_store::PartStore;

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

pub fn manifest_changed(meta: &PartMeta, new_size: u64, new_hash_value: &str) -> bool {
    meta.size != new_size || meta.hash_value != new_hash_value
}

pub fn discard_part(store: &dyn PartStore, transfer_id: &str, rel: &str) -> Result<()> {
    store.delete_part(transfer_id, rel)
}
