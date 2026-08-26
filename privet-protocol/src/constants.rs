
pub const PROTO_VERSION: u32 = 1;

pub const MAX_CONTROL_FRAME_BYTES: usize = 4 * 1024 * 1024;

pub const INLINE_FILE_THRESHOLD: usize = 64 * 1024; // 65536

pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

pub const SEGMENT_MAX_CHUNKS: u32 = 1024;

pub const PRIVET_DISCOVERY_PORT: u16 = 47809;
pub const QUIC_PORT: u16 = 47808;
pub const TCP_PORT: u16 = 47808;
