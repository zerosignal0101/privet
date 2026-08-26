
pub use privet_protocol::constants::{PRIVET_DISCOVERY_PORT};

pub const BEACON_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

pub const PEER_STALE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

pub const PEER_LOST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

pub const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

pub const PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

pub const BEACON_TTL: std::time::Duration = std::time::Duration::from_secs(30);

pub const RECENT_N: usize = 5;

pub const PROBE_CONCURRENCY: usize = 8;

pub const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1500);

pub const EVICT_FAILS: u32 = 5;

pub const RATE_LIMIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
pub const RATE_LIMIT_MAX_PER_WINDOW: usize = 10;

pub const NONCE_CACHE_SIZE: usize = 256;
