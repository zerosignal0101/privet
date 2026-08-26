//! 常量。protocol/crypto 常量 re-export 不重复定义值。

pub use privet_protocol::constants::{
    DEFAULT_CHUNK_SIZE, INLINE_FILE_THRESHOLD, MAX_CONTROL_FRAME_BYTES, PROTO_VERSION,
    SEGMENT_MAX_CHUNKS,
};

/// 每对端并发传送（v1 固定 1，不保留可配字段）。
pub const MAX_CONCURRENT_TRANSFERS_PER_PEER: usize = 1;

/// 每传送文件数 DoS 硬上限（超限 TooManyFiles，不截断）。
pub const MAX_FILES_PER_TRANSFER: u64 = 1_048_576;

/// QUIC 流池大小。
pub const STREAM_POOL_SIZE: usize = 8;

/// 每流在途块（×8 流 ≈ 32MiB 上限）。
pub const INFLIGHT_PER_STREAM: usize = 4;

/// 总在途块上限（≈32，pending 块 ≤ 此值）。
pub const INFLIGHT_TOTAL_CAP: usize = 32;

/// ChunkAck 间隔（块数，或时间基）。
/// 必须 ≤ INFLIGHT_TOTAL_CAP(32)：否则发送窗口填满（32 inflight）后接收方仍未达 ack 门槛，
/// 慢链路下数据持续到达使 500ms 空闲 flush 永不触发 -> ack 不发 -> 重传爬升 -> ChunkCorrupt 死锁。
/// 取 16 = 窗口的一半，保证每窗口至少 2 次 ack。
pub const CHUNK_ACK_INTERVAL: u64 = 16;

/// 块重传 RTO（自适应默认 2s）。
pub const CHUNK_RETRANSMIT_RTO: std::time::Duration = std::time::Duration::from_secs(2);

/// 块重传上限（超限 ChunkCorrupt）。
pub const CHUNK_RETRANSMIT_MAX: u32 = 5;

/// ChunkAck 时间基（小窗口下避免 sender 空等）。
/// 也作为接收方周期任务（flush ack + 控制轮询）的间隔。
pub const CHUNK_ACK_TIME_BASE: std::time::Duration = std::time::Duration::from_millis(500);

/// 重连退避上限（Reconnecting）。
pub const RECONNECT_MAX_ATTEMPTS: u32 = 6;

/// FileSetBatch 单帧目标上限（<4MiB）。
pub const FILESET_BATCH_TARGET_BYTES: usize = 3 * 1024 * 1024; // 3 MiB（留余 < 4MiB）
