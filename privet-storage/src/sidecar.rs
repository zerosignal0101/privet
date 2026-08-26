
use std::path::{Path, PathBuf};

use crate::constants::{PART_META_SUFFIX, PART_SUFFIX, STAGING_DIR_NAME};
use crate::error::StorageError;
use prost::Message;

pub fn part_meta_path(
    save_dir: &Path,
    transfer_id: &str,
    relative_path: &str,
) -> Result<PathBuf, StorageError> {
    let _ = crate::path_guard::guard_relative_path(relative_path)?;
    let mut s = save_dir
        .join(STAGING_DIR_NAME)
        .join(transfer_id)
        .join(relative_path)
        .into_os_string();
    s.push(PART_META_SUFFIX);
    Ok(PathBuf::from(s))
}

pub fn part_path(
    save_dir: &Path,
    transfer_id: &str,
    relative_path: &str,
) -> Result<PathBuf, StorageError> {
    let _ = crate::path_guard::guard_relative_path(relative_path)?;
    let mut s = save_dir
        .join(STAGING_DIR_NAME)
        .join(transfer_id)
        .join(relative_path)
        .into_os_string();
    s.push(PART_SUFFIX);
    Ok(PathBuf::from(s))
}

pub fn build_initial_meta(
    transfer_id: &str,
    file_id: &str,
    relative_path: &str,
    size: u64,
    mtime_ms: u64,
    blake3: &str,
) -> crate::PartMeta {
    let segments = privet_protocol::layout::derive_segment_layout_default(size)
        .into_iter()
        .map(|s| crate::PartSegment {
            segment_id: s.segment_id,
            offset: s.offset,
            length: s.length,
            chunk_count: s.chunk_count,
            chunk_size: s.chunk_size,
            hash_type: "blake3".into(),
            chunk_hash_values: Vec::new(),
            segment_hash_value: String::new(),
        })
        .collect();
    crate::PartMeta {
        transfer_id: transfer_id.into(),
        file_id: file_id.into(),
        relative_path: relative_path.into(),
        size,
        mtime_ms,
        hash_type: "blake3".into(),
        hash_value: blake3.into(),
        segments,
    }
}


fn atomic_write_fsync(path: &Path, data: &[u8]) -> Result<(), StorageError> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("part.meta.tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    fsync_parent(path)?; // rename durability
    Ok(())
}

pub(crate) fn fsync_parent(path: &Path) -> Result<(), StorageError> {
    let parent = path.parent().ok_or_else(|| {
        StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no parent dir",
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let d = std::fs::File::open(parent)?;
        let _ = unsafe { libc::fsync(d.as_raw_fd()) };
    }
    #[cfg(not(unix))]
    {
        if let Ok(d) = std::fs::File::open(parent) {
            let _ = d.sync_data();
        }
    }
    Ok(())
}

pub fn decode_part_meta(bytes: &[u8]) -> Result<crate::PartMeta, StorageError> {
    let meta = crate::PartMeta::decode(bytes)?;
    Ok(meta)
}

pub fn read_part_meta(path: &Path) -> Result<crate::PartMeta, StorageError> {
    let bytes = std::fs::read(path)?;
    decode_part_meta(&bytes)
}

pub fn encode_part_meta(meta: &crate::PartMeta) -> Result<Vec<u8>, StorageError> {
    let mut buf = Vec::with_capacity(meta.encoded_len());
    meta.encode(&mut buf)?;
    Ok(buf)
}

pub fn write_part_meta_initial(path: &Path, meta: &crate::PartMeta) -> Result<(), StorageError> {
    atomic_write_fsync(path, &encode_part_meta(meta)?)
}

pub fn write_segment(
    path: &Path,
    file_id: &str,
    segment_id: u32,
    segment_hash_value: &str,
    chunk_hash_values: &[String],
) -> Result<(), StorageError> {
    let mut meta = read_part_meta(path)?;
    if meta.file_id != file_id {
        return Err(StorageError::InvalidState("file_id mismatch".into()));
    }
    for seg in meta.segments.iter_mut() {
        if seg.segment_id == segment_id {
            seg.segment_hash_value = segment_hash_value.to_string();
            seg.chunk_hash_values = chunk_hash_values.to_vec();
            return atomic_write_fsync(path, &encode_part_meta(&meta)?);
        }
    }
    Err(StorageError::NotFound(format!("segment {segment_id}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PartMeta, PartSegment};

    fn sample() -> PartMeta {
        PartMeta {
            transfer_id: "t1".into(),
            file_id: "f1".into(),
            relative_path: "dir/a.txt".into(),
            size: 2048,
            mtime_ms: 1_700_000_000_000,
            hash_type: "blake3".into(),
            hash_value: "abcdef".into(),
            segments: vec![
                PartSegment {
                    segment_id: 0,
                    offset: 0,
                    length: 1024,
                    chunk_count: 1,
                    chunk_size: 1024,
                    hash_type: "blake3".into(),
                    segment_hash_value: "r0".into(),
                    chunk_hash_values: vec!["h0".into()],
                },
                PartSegment {
                    segment_id: 1,
                    offset: 1024,
                    length: 1024,
                    chunk_count: 1,
                    chunk_size: 1024,
                    hash_type: "blake3".into(),
                    segment_hash_value: "".into(),
                    chunk_hash_values: vec![],
                },
            ],
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let m = sample();
        let bytes = encode_part_meta(&m).unwrap();
        let back = decode_part_meta(&bytes).unwrap();
        assert_eq!(back.transfer_id, "t1");
        assert_eq!(back.size, 2048);
        assert_eq!(back.segments.len(), 2);
        assert_eq!(back.segments[0].chunk_hash_values, vec!["h0".to_string()]);
        assert!(back.segments[1].chunk_hash_values.is_empty());
        assert_eq!(back.segments[0].segment_hash_value, "r0");
    }

    #[test]
    fn initial_write_then_segment_incremental() {
        let dir = tempfile::tempdir().unwrap();
        let save = dir.path();
        let mp = part_meta_path(save, "t1", "a/b.txt").unwrap();
        let mut meta = build_initial_meta("t1", "f1", "a/b.txt", 100, 1, "fullhash");
        meta.segments = vec![
            PartSegment {
                segment_id: 0,
                offset: 0,
                length: 50,
                chunk_count: 1,
                chunk_size: 100,
                hash_type: "blake3".into(),
                segment_hash_value: String::new(),
                chunk_hash_values: vec![],
            },
            PartSegment {
                segment_id: 1,
                offset: 50,
                length: 50,
                chunk_count: 1,
                chunk_size: 100,
                hash_type: "blake3".into(),
                segment_hash_value: String::new(),
                chunk_hash_values: vec![],
            },
        ];
        write_part_meta_initial(&mp, &meta).unwrap();

        let r = read_part_meta(&mp).unwrap();
        assert!(r.segments[0].chunk_hash_values.is_empty());
        assert!(r.segments[1].chunk_hash_values.is_empty());

        write_segment(&mp, "f1", 0, "root0", &["h0".into(), "h1".into()]).unwrap();
        let r = read_part_meta(&mp).unwrap();
        assert_eq!(r.segments[0].segment_hash_value, "root0");
        assert_eq!(
            r.segments[0].chunk_hash_values,
            vec!["h0".to_string(), "h1".to_string()]
        );
        assert!(r.segments[1].chunk_hash_values.is_empty());

        write_segment(&mp, "f1", 1, "root1", &["h2".into()]).unwrap();
        let r = read_part_meta(&mp).unwrap();
        assert_eq!(r.segments[1].segment_hash_value, "root1");
    }

    #[test]
    fn write_segment_rejects_wrong_file_id() {
        let dir = tempfile::tempdir().unwrap();
        let mp = part_meta_path(dir.path(), "t1", "a.txt").unwrap();
        let meta = build_initial_meta("t1", "f1", "a.txt", 100, 1, "x");
        write_part_meta_initial(&mp, &meta).unwrap();
        let err = write_segment(&mp, "WRONG", 0, "r", &[]).unwrap_err();
        assert!(matches!(err, StorageError::InvalidState(_)));
    }
}
