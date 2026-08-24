//! PairingConfig
use crate::constants::*;

#[derive(Debug, Clone)]
pub struct PairingConfig {
    pub code_validity_secs: u64,
    pub max_code_attempts: u32,
    pub pairing_concurrency_per_ip: u32,
    pub max_pairing_attempts_per_min: u32,
    pub spake2_group: &'static str,
    pub pairing_binding_label: &'static str,
    pub pairing_ack_timeout_secs: u64,
    pub pairing_max_retries: u32,
    pub identity_gc_stale_days: i64,
}

impl Default for PairingConfig {
    fn default() -> Self {
        Self {
            code_validity_secs: CODE_VALIDITY_SECS,
            max_code_attempts: MAX_CODE_ATTEMPTS,
            pairing_concurrency_per_ip: PAIRING_CONCURRENCY_PER_IP,
            max_pairing_attempts_per_min: MAX_PAIRING_ATTEMPTS_PER_MIN,
            spake2_group: "edwards25519",
            pairing_binding_label: PAIRING_BINDING_LABEL,
            pairing_ack_timeout_secs: PAIRING_ACK_TIMEOUT_SECS,
            pairing_max_retries: PAIRING_MAX_RETRIES,
            identity_gc_stale_days: IDENTITY_GC_STALE_DAYS,
        }
    }
}
