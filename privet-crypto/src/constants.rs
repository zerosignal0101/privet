
pub const PAIRING_CONTEXT_STRING: &str = "privet-pairing-v1";
pub const PAIRING_BINDING_LABEL: &str = "privet-pairing-binding";

pub const PAIRING_CONFIRMATION_LABEL: &[u8] = b"privet-pairing-confirmation";

pub const NONCE_LEN: usize = 16;
pub const EXPORTER_LEN: usize = 32;

pub const CERT_VALIDITY_YEARS: i64 = 100;

pub const CODE_VALIDITY_SECS: u64 = 600;
pub const MAX_CODE_ATTEMPTS: u32 = 5;
