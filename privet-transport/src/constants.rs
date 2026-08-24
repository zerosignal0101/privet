//! 传输层常量

pub use privet_protocol::constants::{PROTO_VERSION, QUIC_PORT, TCP_PORT};

/// QUIC 数据流池大小（钳到对端 max_streams）。
pub const STREAM_POOL_SIZE: usize = 8;

/// QUIC 连接超时（PreferQuic 降级触发）。
pub const QUIC_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// 连接空闲超时（映射 quinn max_idle_timeout）。
pub const CONNECTION_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// 心跳周期（策略属 core/transfer，本 crate 仅常量）。
pub const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// 判死缺心跳数。
pub const HEARTBEAT_MISS: u32 = 3;

/// TCP 逻辑流背压 channel 容量。
pub const TCP_STREAM_CHANNEL_CAP: usize = 64;  // 256 KiB
