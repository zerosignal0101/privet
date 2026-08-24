//! storage 常量。

/// 地址淘汰失败计数阈值。
pub const EVICT_FAILS: u32 = 5;

/// recent-N 地址查询数。
pub const RECENT_N: usize = 5;

/// 信任 GC 陈旧天数。
pub const IDENTITY_GC_STALE_DAYS: i64 = 180;

/// busy_timeout 毫秒。
pub const BUSY_TIMEOUT_MS: u32 = 5000;

/// staging 目录名（`<save_dir>/.privet/<transfer_id>/`）。
pub const STAGING_DIR_NAME: &str = ".privet";

/// `.part` 后缀。
pub const PART_SUFFIX: &str = ".part";

/// `.part.meta` 后缀。
pub const PART_META_SUFFIX: &str = ".part.meta";

/// complete 事务批量插 transfer_files 的批大小（自选默认）。
pub const MAX_TRANSFER_FILES_BULK_INSERT: usize = 500;
