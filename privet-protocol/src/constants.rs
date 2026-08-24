//! 协议级常量

pub const PROTO_VERSION: u32 = 1;

/// 单控制帧最大字节数
pub const MAX_CONTROL_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// 内联快路径阈值，含：≤65536 字节内联
pub const INLINE_FILE_THRESHOLD: usize = 64 * 1024; // 65536

/// 默认块大小
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

/// 每段最大块数
pub const SEGMENT_MAX_CHUNKS: u32 = 1024;

/// 发现/传输端口
pub const PRIVET_DISCOVERY_PORT: u16 = 47809;
pub const QUIC_PORT: u16 = 47808;
pub const TCP_PORT: u16 = 47808;
