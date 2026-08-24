//! 常量：重导出 crypto 的配对常量 + 本层提交时序/速率限制常量
pub use privet_crypto::constants::{
    CODE_VALIDITY_SECS, EXPORTER_LEN, MAX_CODE_ATTEMPTS, NONCE_LEN,
    PAIRING_BINDING_LABEL, PAIRING_CONFIRMATION_LABEL, PAIRING_CONTEXT_STRING,
};

/// I 等 PairingResultAck 超时
pub const PAIRING_ACK_TIMEOUT_SECS: u64 = 30;
/// I 重发 PairingResult 上限
pub const PAIRING_MAX_RETRIES: u32 = 3;
/// 每 IP 在途配对数
pub const PAIRING_CONCURRENCY_PER_IP: u32 = 1;
/// 每分钟配对尝试上限
pub const MAX_PAIRING_ATTEMPTS_PER_MIN: u32 = 5;
/// 信任 GC 陈旧天数
pub const IDENTITY_GC_STALE_DAYS: i64 = 180;
