//! 配对/身份密码学常量

pub const PAIRING_CONTEXT_STRING: &str = "privet-pairing-v1";
pub const PAIRING_BINDING_LABEL: &str = "privet-pairing-binding";

/// PAKE 确认标签派生标签（K_shared 派生，双方须一致；具体 KDF 自选 BLAKE3）。
pub const PAIRING_CONFIRMATION_LABEL: &[u8] = b"privet-pairing-confirmation";

pub const NONCE_LEN: usize = 16;
pub const EXPORTER_LEN: usize = 32;

/// 证书有效期（形式；钉扎不看有效期）。
pub const CERT_VALIDITY_YEARS: i64 = 100;

// 配对码生命周期（后续 pairing 流程层引用，本计划仅定义）
pub const CODE_VALIDITY_SECS: u64 = 600;
pub const MAX_CODE_ATTEMPTS: u32 = 5;
