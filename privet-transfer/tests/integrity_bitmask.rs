//! BLAKE3 三级 + 位图。
use privet_crypto::hash::blake3;
use privet_protocol::layout::derive_segment_layout;
use privet_transfer::bitmask::VerifiedBitmask;
use privet_transfer::integrity::{
    chunk_hash, compute_file_hashes, file_hash_streaming, segment_root, verify_chunk,
    verify_segment_root,
};

#[test]
fn chunk_hash_is_blake3_hex() {
    let data = b"hello";
    let h = chunk_hash(data);
    assert_eq!(h.len(), 64); // 32 字节 hex
    assert_eq!(h, hex::encode(blake3(data)));
}

#[test]
fn segment_root_over_chunk_hashes() {
    let chunks = [b"aaaa", b"bbbb", b"cccc"];
    let hashes: Vec<String> = chunks.iter().map(|c| chunk_hash(&c[..])).collect();
    let root = segment_root(&hashes);
    // 等价：BLAKE3(h0||h1||h2 的 hex 串字节)
    let mut concat = String::new();
    for h in &hashes {
        concat.push_str(h);
    }
    assert_eq!(root, hex::encode(blake3(concat.as_bytes())));
}

#[test]
fn verify_chunk_match_and_mismatch() {
    let data = b"payload";
    let h = chunk_hash(data);
    assert!(verify_chunk(data, &h));
    assert!(!verify_chunk(b"tampered", &h));
}

#[test]
fn verify_segment_root_roundtrip() {
    let hashes = vec![chunk_hash(b"a"), chunk_hash(b"b")];
    let root = segment_root(&hashes);
    assert!(verify_segment_root(&hashes, &root));
    let bad = vec![chunk_hash(b"a"), chunk_hash(b"X")];
    assert!(!verify_segment_root(&bad, &root));
}

#[test]
fn file_hash_streaming_matches_oneshot() {
    let data = (0..100_000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let streamed = file_hash_streaming(&[data.as_slice()]).unwrap();
    let oneshot = hex::encode(blake3(&data));
    assert_eq!(streamed, oneshot);
}

#[test]
fn compute_file_hashes_three_levels() {
    // size = 2.5 MiB -> 3 块（1MiB+1MiB+0.5MiB），1 段
    let chunk_size = 1024 * 1024u32;
    let size = (chunk_size as u64) * 2 + 500_000;
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let layout = derive_segment_layout(size, chunk_size, 1024);
    assert_eq!(layout.len(), 1);
    assert_eq!(layout[0].chunk_count, 3);

    let hf = compute_file_hashes(&data, chunk_size, 1024).unwrap();
    // 整文件哈希 == 流式
    assert_eq!(hf.file_hash, hex::encode(blake3(&data)));
    // 段数 = layout 段数
    assert_eq!(hf.segments.len(), 1);
    let seg = &hf.segments[0];
    assert_eq!(seg.chunk_hashes.len(), 3);
    // 段根 == segment_root(chunk_hashes)
    assert_eq!(seg.blake3_root, segment_root(&seg.chunk_hashes));
    // 逐块 == 切片哈希
    let cs = chunk_size as usize;
    assert_eq!(seg.chunk_hashes[0], chunk_hash(&data[0..cs]));
    assert_eq!(seg.chunk_hashes[1], chunk_hash(&data[cs..2 * cs]));
    assert_eq!(seg.chunk_hashes[2], chunk_hash(&data[2 * cs..]));
}

#[test]
fn bitmask_set_test_serialize() {
    let mut bm = VerifiedBitmask::new(10); // 10 块 -> 2 字节
    assert!(!bm.is_set(3));
    bm.set(3);
    bm.set(9);
    assert!(bm.is_set(3));
    assert!(bm.is_set(9));
    assert!(!bm.is_set(4));
    let bytes = bm.as_bytes().to_vec();
    // bit 3 in byte0, bit 9 in byte1
    assert_eq!(bytes, vec![0b0000_1000, 0b0000_0010]);
}

#[test]
fn bitmask_to_chunk_bitmask_proto() {
    let mut bm = VerifiedBitmask::new(20);
    bm.set(0);
    bm.set(19);
    let proto = bm.to_chunk_bitmask("f1", 2);
    assert_eq!(proto.file_id, "f1");
    assert_eq!(proto.segment_id, 2);
    assert_eq!(proto.bitmask, bm.as_bytes().to_vec());
}

#[test]
fn bitmask_empty_all_unset() {
    let bm = VerifiedBitmask::new(0);
    assert!(bm.as_bytes().is_empty());
    let protos = VerifiedBitmask::empty_segment(0).to_chunk_bitmask("f", 0);
    assert!(protos.bitmask.is_empty());
}
