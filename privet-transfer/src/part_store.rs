
use std::path::{Path, PathBuf};

use crate::config::CollisionPolicy;
use crate::error::{Result, TransferError};
use privet_storage::resume::SegmentBitmask;
use privet_storage::sidecar::{
    build_initial_meta, part_meta_path, part_path, write_part_meta_initial, write_segment,
};
use privet_storage::staging::{cleanup_staging_dir, delete_part_and_meta, finalize_part_file};
use privet_storage::STAGING_DIR_NAME;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizeOutcome {
    Landed,
    Skipped,
}

pub trait PartStore: Send + Sync {
    fn pwrite_part(
        &self,
        transfer_id: &str,
        rel_path: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<()>;
    fn read_part_range(
        &self,
        transfer_id: &str,
        rel_path: &str,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>>;
    fn init_part_meta(
        &self,
        transfer_id: &str,
        rel_path: &str,
        file_id: &str,
        size: u64,
        mtime_ms: u64,
        blake3: &str,
    ) -> Result<()>;
    fn write_segment_meta(
        &self,
        transfer_id: &str,
        rel_path: &str,
        file_id: &str,
        segment_id: u32,
        segment_hash_value: &str,
        chunk_hash_values: &[String],
    ) -> Result<()>;
    fn rebuild_resume_bitmask(
        &self,
        transfer_id: &str,
        rel_path: &str,
    ) -> Result<Vec<SegmentBitmask>>;
    fn finalize_part(
        &self,
        transfer_id: &str,
        rel_path: &str,
        final_path: &Path,
        policy: CollisionPolicy,
    ) -> Result<FinalizeOutcome>;
    fn delete_part(&self, transfer_id: &str, rel_path: &str) -> Result<()>;
    fn cleanup_staging(&self, transfer_id: &str) -> Result<()>;
    fn mkdir_finalize_root(&self, save_dir: &Path, root_name: Option<&str>) -> Result<()>;
    fn save_dir(&self) -> &Path;
}

pub struct FsPartStore {
    save_dir: PathBuf,
}

impl FsPartStore {
    pub fn new(save_dir: PathBuf) -> Self {
        Self { save_dir }
    }
    fn part(&self, transfer_id: &str, rel: &str) -> Result<PathBuf> {
        Ok(part_path(&self.save_dir, transfer_id, rel)?)
    }
    fn meta(&self, transfer_id: &str, rel: &str) -> Result<PathBuf> {
        Ok(part_meta_path(&self.save_dir, transfer_id, rel)?)
    }
}

impl PartStore for FsPartStore {
    fn save_dir(&self) -> &Path {
        &self.save_dir
    }

    fn pwrite_part(&self, transfer_id: &str, rel: &str, offset: u64, data: &[u8]) -> Result<()> {
        let p = self.part(transfer_id, rel)?;
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .open(&p)?;
        f.seek(SeekFrom::Start(offset))?;
        f.write_all(data)?;
        Ok(())
    }

    fn read_part_range(
        &self,
        transfer_id: &str,
        rel: &str,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>> {
        let p = self.part(transfer_id, rel)?;
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(&p)?;
        f.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len];
        let mut filled = 0;
        while filled < len {
            let n = f.read(&mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        buf.truncate(filled);
        Ok(buf)
    }

    fn init_part_meta(
        &self,
        transfer_id: &str,
        rel: &str,
        file_id: &str,
        size: u64,
        mtime_ms: u64,
        blake3: &str,
    ) -> Result<()> {
        let meta = build_initial_meta(transfer_id, file_id, rel, size, mtime_ms, blake3);
        write_part_meta_initial(&self.meta(transfer_id, rel)?, &meta)?;
        Ok(())
    }

    fn write_segment_meta(
        &self,
        transfer_id: &str,
        rel: &str,
        file_id: &str,
        segment_id: u32,
        segment_hash_value: &str,
        chunk_hash_values: &[String],
    ) -> Result<()> {
        write_segment(
            &self.meta(transfer_id, rel)?,
            file_id,
            segment_id,
            segment_hash_value,
            chunk_hash_values,
        )?;
        Ok(())
    }

    fn rebuild_resume_bitmask(&self, transfer_id: &str, rel: &str) -> Result<Vec<SegmentBitmask>> {
        Ok(privet_storage::resume::rebuild_verified_bitmap(
            &self.save_dir,
            transfer_id,
            rel,
        )?)
    }

    fn finalize_part(
        &self,
        transfer_id: &str,
        rel: &str,
        final_path: &Path,
        policy: CollisionPolicy,
    ) -> Result<FinalizeOutcome> {
        let part_p = self.part(transfer_id, rel)?;
        let exists = final_path.exists();
        match policy {
            CollisionPolicy::Skip if exists => {
                delete_part_and_meta(&part_p)?;
                Ok(FinalizeOutcome::Skipped)
            }
            CollisionPolicy::Overwrite if exists => {
                let _ = std::fs::remove_file(final_path);
                finalize_part_file(&part_p, final_path)?;
                Ok(FinalizeOutcome::Landed)
            }
            CollisionPolicy::Rename if exists => {
                let free = resolve_collision_path(final_path)?;
                finalize_part_file(&part_p, &free)?;
                Ok(FinalizeOutcome::Landed)
            }
            _ => {
                finalize_part_file(&part_p, final_path)?;
                Ok(FinalizeOutcome::Landed)
            }
        }
    }

    fn delete_part(&self, transfer_id: &str, rel: &str) -> Result<()> {
        let p = self.part(transfer_id, rel)?;
        delete_part_and_meta(&p)?;
        Ok(())
    }

    fn cleanup_staging(&self, transfer_id: &str) -> Result<()> {
        let tdir = self.save_dir.join(STAGING_DIR_NAME).join(transfer_id);
        if tdir.exists() {
            cleanup_staging_dir(&tdir)?;
            let _ = std::fs::remove_dir(&tdir);
            let privet = self.save_dir.join(STAGING_DIR_NAME);
            if let Ok(mut it) = std::fs::read_dir(&privet) {
                if it.next().is_none() {
                    let _ = std::fs::remove_dir(&privet);
                }
            }
        }
        Ok(())
    }

    fn mkdir_finalize_root(&self, save_dir: &Path, root_name: Option<&str>) -> Result<()> {
        let root = match root_name {
            Some(r) => save_dir.join(r),
            None => save_dir.to_path_buf(),
        };
        std::fs::create_dir_all(&root)?;
        Ok(())
    }
}

pub fn resolve_collision_path(final_path: &Path) -> Result<PathBuf> {
    let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = final_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let (stem, ext) = match file_name.rfind('.') {
        Some(i) if i > 0 => (&file_name[..i], Some(&file_name[i..])),
        _ => (file_name.as_str(), None),
    };
    for n in 1..u32::MAX {
        let candidate_name = match ext {
            Some(e) => format!("{stem}({n}){e}"),
            None => format!("{stem}({n})"),
        };
        let candidate = parent.join(&candidate_name);
        if !candidate.exists() {
            match std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&candidate)
            {
                Ok(_) => {
                    std::fs::remove_file(&candidate)?;
                    return Ok(candidate);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
    Err(TransferError::Internal("no free collision name".into()))
}
