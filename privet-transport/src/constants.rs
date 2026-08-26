
pub use privet_protocol::constants::{PROTO_VERSION, QUIC_PORT, TCP_PORT};

pub const STREAM_POOL_SIZE: usize = 8;

pub const QUIC_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

pub const CONNECTION_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

pub const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

pub const HEARTBEAT_MISS: u32 = 3;

pub const TCP_STREAM_CHANNEL_CAP: usize = 64;  // 256 KiB
