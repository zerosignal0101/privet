//! FileSetBatch 流式分帧+ receiver 累积器 + summary 校验。
//! offer 仅 summary；续以 FileSetBatch 多帧（每帧 < 4MiB，is_last 终结）。

use crate::constants::FILESET_BATCH_TARGET_BYTES;
use crate::error::{Result, TransferError};
use crate::prepare::PreparedFile;
use privet_protocol::{DirEntry, FileEntry, FileSetBatch, FileSetSummary, TransferOffer};
use prost::Message;

/// 构建 offer（仅 summary + 元信息）。
pub fn build_offer(transfer_id: &str, set: &crate::prepare::PreparedSet) -> TransferOffer {
    TransferOffer {
        transfer_id: transfer_id.into(),
        summary: Some(set.summary.clone()),
        resume_supported: true,
        proto_version: crate::PROTO_VERSION,
    }
}

/// FileSetBatch 分帧器：累积 files/dirs 至目标字节量后切帧。
pub struct FileSetBatcher {
    transfer_id: String,
    cur_files: Vec<FileEntry>,
    cur_dirs: Vec<DirEntry>,
    cur_bytes: usize,
    frames: Vec<FileSetBatch>,
}

impl FileSetBatcher {
    pub fn new(transfer_id: String) -> Self {
        Self {
            transfer_id,
            cur_files: Vec::new(),
            cur_dirs: Vec::new(),
            cur_bytes: 0,
            frames: Vec::new(),
        }
    }

    fn flush_if_full(&mut self) {
        if self.cur_bytes >= FILESET_BATCH_TARGET_BYTES && !self.cur_files.is_empty() {
            self.frames.push(FileSetBatch {
                transfer_id: self.transfer_id.clone(),
                files: std::mem::take(&mut self.cur_files),
                dirs: std::mem::take(&mut self.cur_dirs),
                is_last: false,
            });
            self.cur_bytes = 0;
        }
    }

    pub fn push(&mut self, pf: &PreparedFile) {
        let entry = pf.to_entry();
        self.cur_bytes += entry.encoded_len();
        self.cur_files.push(entry);
        self.flush_if_full();
    }

    #[allow(dead_code)]
    pub fn push_dir(&mut self, d: &DirEntry) {
        self.cur_dirs.push(d.clone());
    }

    /// 终结：输出剩余 + 末帧 is_last=true。至少返回 1 帧（即使空）。
    pub fn finish(mut self) -> Vec<FileSetBatch> {
        self.frames.push(FileSetBatch {
            transfer_id: self.transfer_id,
            files: std::mem::take(&mut self.cur_files),
            dirs: std::mem::take(&mut self.cur_dirs),
            is_last: true,
        });
        self.frames
    }
}

/// receiver 累积重建 FileSet，按 summary 校完整性（Q4）。
pub struct FileSetAccumulator {
    summary: FileSetSummary,
    files: Vec<FileEntry>,
    dirs: Vec<DirEntry>,
    complete: bool,
}

impl FileSetAccumulator {
    pub fn new(summary: &FileSetSummary) -> Self {
        Self {
            summary: summary.clone(),
            files: Vec::new(),
            dirs: Vec::new(),
            complete: false,
        }
    }

    pub fn ingest(&mut self, batch: &FileSetBatch) -> Result<()> {
        if self.complete {
            return Err(TransferError::ManifestMismatch(
                "batch after is_last".into(),
            ));
        }
        self.files.extend_from_slice(&batch.files);
        self.dirs.extend_from_slice(&batch.dirs);
        if batch.is_last {
            if self.files.len() as u64 != self.summary.file_count
                || self.dirs.len() as u64 != self.summary.dir_count
            {
                return Err(TransferError::ManifestMismatch(format!(
                    "count mismatch: files {} vs {}, dirs {} vs {}",
                    self.files.len(),
                    self.summary.file_count,
                    self.dirs.len(),
                    self.summary.dir_count
                )));
            }
            self.complete = true;
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn built(&self) -> Result<&[FileEntry]> {
        if !self.complete {
            return Err(TransferError::ManifestMismatch("not complete".into()));
        }
        Ok(&self.files)
    }

    #[allow(dead_code)]
    pub fn dirs(&self) -> &[DirEntry] {
        &self.dirs
    }

    #[allow(dead_code)]
    pub fn summary(&self) -> &FileSetSummary {
        &self.summary
    }
}
