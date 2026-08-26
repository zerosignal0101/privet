//! core 层常量：重导出 + 重连退避。
use std::time::Duration;

pub use privet_discovery::constants as discovery_constants;
pub use privet_security::constants as security_constants;
pub use privet_transfer::constants as transfer_constants;
pub use privet_transport::constants as transport_constants;

/// 指数退避表（封顶 30s）。
pub const BACKOFF_SCHEDULE: &[Duration] = &[
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(30),
];
/// 重连上限（约 61s）。
pub const BACKOFF_MAX_ATTEMPTS: u32 = 6;
/// 成功后重置退避。
pub const BACKOFF_RESET_ON_SUCCESS: bool = true;
/// 网络切换立即重试。
pub const NETWORK_SWITCH_IMMEDIATE_RETRY: bool = true;
