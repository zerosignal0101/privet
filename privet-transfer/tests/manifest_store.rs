use privet_transfer::integrity::{chunk_hash, segment_root};
use privet_transfer::manifest_store::{ArrivalVerdict, PendingChunk, ReceiverManifestStore};

fn manifest(seg: u32, chunks: &[&[u8]]) -> privet_protocol::SegmentManifest {
    let hashes: Vec<String> = chunks.iter().map(|c| chunk_hash(c)).collect();
    let root = segment_root(&hashes);
    privet_protocol::SegmentManifest {
        file_id: "f1".into(),
        segment_id: seg,
        hash_type: "blake3".into(),
        chunk_hash_values: hashes,
        segment_hash_value: root,
    }
}

#[test]
fn manifest_absent_chunk_is_pending_buffered() {
    let mut store = ReceiverManifestStore::new();
    let verdict = store.classify_arrival("f1", 0, 0, b"AAAA");
    assert!(matches!(verdict, ArrivalVerdict::Pending));
    store.buffer_pending(PendingChunk {
        file_id: "f1".into(),
        segment_id: 0,
        chunk_index: 0,
        offset: 0,
        data: b"AAAA".to_vec(),
    });
    assert_eq!(store.pending_count("f1", 0), 1);
}

#[test]
fn manifest_present_match_is_verified() {
    let mut store = ReceiverManifestStore::new();
    store.store_manifest(&manifest(0, &[b"AAAA", b"BBBB"]));
    let v = store.classify_arrival("f1", 0, 0, b"AAAA");
    assert!(matches!(v, ArrivalVerdict::Verified));
    let v2 = store.classify_arrival("f1", 0, 1, b"BBBB");
    assert!(matches!(v2, ArrivalVerdict::Verified));
}

#[test]
fn manifest_present_mismatch_is_mismatch() {
    let mut store = ReceiverManifestStore::new();
    store.store_manifest(&manifest(0, &[b"AAAA"]));
    let v = store.classify_arrival("f1", 0, 0, b"XXXX");
    assert!(matches!(v, ArrivalVerdict::Mismatch));
}

#[test]
fn drain_pending_after_manifest_arrives() {
    let mut store = ReceiverManifestStore::new();
    store.buffer_pending(PendingChunk {
        file_id: "f1".into(),
        segment_id: 0,
        chunk_index: 1,
        offset: 4,
        data: b"BBBB".to_vec(),
    });
    store.buffer_pending(PendingChunk {
        file_id: "f1".into(),
        segment_id: 0,
        chunk_index: 0,
        offset: 0,
        data: b"AAAA".to_vec(),
    });
    store.store_manifest(&manifest(0, &[b"AAAA", b"BBBB"]));
    let drained = store.drain_pending("f1", 0);
    assert_eq!(drained.len(), 2);
    for p in &drained {
        assert!(matches!(
            store.classify_arrival("f1", 0, p.chunk_index, &p.data),
            ArrivalVerdict::Verified
        ));
    }
    assert_eq!(store.pending_count("f1", 0), 0);
}

#[test]
fn pending_mismatch_after_drain_is_mismatch() {
    let mut store = ReceiverManifestStore::new();
    store.buffer_pending(PendingChunk {
        file_id: "f1".into(),
        segment_id: 0,
        chunk_index: 0,
        offset: 0,
        data: b"XXXX".to_vec(),
    });
    store.store_manifest(&manifest(0, &[b"AAAA"]));
    let drained = store.drain_pending("f1", 0);
    assert_eq!(drained.len(), 1);
    assert!(matches!(
        store.classify_arrival("f1", 0, 0, &drained[0].data),
        ArrivalVerdict::Mismatch
    ));
}
