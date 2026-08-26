//! 发现层常量（与 protocol 重叠的 re-export）。

pub use privet_protocol::constants::{PRIVET_DISCOVERY_PORT};

/// 广播周期
pub const BEACON_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// 失联转 stale
pub const PEER_STALE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// stale 转 lost
pub const PEER_LOST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// 周期扫描间隔（定 stale=180s/lost=300s，扫描周期本计划自选 30s）。
pub const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// 周期主动 Probe 间隔（保证丢包/NAT 环境持续可达）。
pub const PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// beacon 过期阈值（>30s 丢弃）。
pub const BEACON_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// 每 device 保留近邻地址数
pub const RECENT_N: usize = 5;

/// 近邻试探并发上限
pub const PROBE_CONCURRENCY: usize = 8;

/// 单地址试探超时
pub const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1500);

/// 连续失败淘汰阈值
pub const EVICT_FAILS: u32 = 5;

/// 每源 IP beacon 速率限制：窗口内上限（防洪泛，本计划自选默认）。
pub const RATE_LIMIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
pub const RATE_LIMIT_MAX_PER_WINDOW: usize = 10;

/// nonce 去重缓存大小（本计划自选默认）。
pub const NONCE_CACHE_SIZE: usize = 256;
