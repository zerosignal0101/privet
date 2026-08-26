
pub use privet_protocol::constants::{
    DEFAULT_CHUNK_SIZE, INLINE_FILE_THRESHOLD, MAX_CONTROL_FRAME_BYTES, PROTO_VERSION,
    SEGMENT_MAX_CHUNKS,
};

pub const MAX_CONCURRENT_TRANSFERS_PER_PEER: usize = 1;

pub const MAX_FILES_PER_TRANSFER: u64 = 1_048_576;

pub const STREAM_POOL_SIZE: usize = 8;

pub const INFLIGHT_PER_STREAM: usize = 4;

pub const INFLIGHT_TOTAL_CAP: usize = 32;

pub const CHUNK_ACK_INTERVAL: u64 = 16;

pub const CHUNK_RETRANSMIT_RTO: std::time::Duration = std::time::Duration::from_secs(2);

pub const CHUNK_RETRANSMIT_MAX: u32 = 5;

pub const CHUNK_ACK_TIME_BASE: std::time::Duration = std::time::Duration::from_millis(500);

pub const RECONNECT_MAX_ATTEMPTS: u32 = 6;

pub const FILESET_BATCH_TARGET_BYTES: usize = 3 * 1024 * 1024;
