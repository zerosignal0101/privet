//! 传送引擎配置+ 碰撞策略。

use std::path::PathBuf;
use std::time::Duration;

use crate::constants::{
    CHUNK_ACK_INTERVAL, CHUNK_RETRANSMIT_MAX, CHUNK_RETRANSMIT_RTO, INFLIGHT_PER_STREAM,
    STREAM_POOL_SIZE,
};
use privet_protocol::constants::{DEFAULT_CHUNK_SIZE, INLINE_FILE_THRESHOLD, SEGMENT_MAX_CHUNKS};

/// 落地同名碰撞策略（接收方配置；发送方不可指定 overwrite）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CollisionPolicy {
    /// rename（默认）：找空名 name(N).ext，exclusive-create 占位 -> rename。永不丢数据。
    #[default]
    Rename,
    /// skip：unlink .part、不落地，per-file 标 skipped。
    Skip,
    /// overwrite：rename(.part -> 终态) 直接替换（接收方自负）。
    Overwrite,
}

#[derive(Debug, Clone)]
pub struct TransferEngineConfig {
    pub inline_file_threshold: usize,
    pub default_chunk_size: u32,
    pub segment_max_chunks: u32,
    pub stream_pool_size: usize,
    pub inflight_per_stream: usize,
    pub chunk_ack_interval: u64,
    pub chunk_ack_time_base: Duration,
    pub chunk_retransmit_rto: Duration,
    pub chunk_retransmit_max: u32,
    pub fsync_per_segment: bool,
    pub on_collision: CollisionPolicy,
    /// 接收方落地根目录（save_dir）。
    pub save_dir: PathBuf,
}

impl Default for TransferEngineConfig {
    fn default() -> Self {
        Self {
            inline_file_threshold: INLINE_FILE_THRESHOLD,
            default_chunk_size: DEFAULT_CHUNK_SIZE as u32,
            segment_max_chunks: SEGMENT_MAX_CHUNKS,
            stream_pool_size: STREAM_POOL_SIZE,
            inflight_per_stream: INFLIGHT_PER_STREAM,
            chunk_ack_interval: CHUNK_ACK_INTERVAL,
            chunk_ack_time_base: crate::constants::CHUNK_ACK_TIME_BASE,
            chunk_retransmit_rto: CHUNK_RETRANSMIT_RTO,
            chunk_retransmit_max: CHUNK_RETRANSMIT_MAX,
            fsync_per_segment: true,
            on_collision: CollisionPolicy::default(),
            save_dir: PathBuf::from("."),
        }
    }
}
