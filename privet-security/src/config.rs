//! Runtime-configurable pairing policy.
use crate::constants::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PairingConfig {
    pub code_validity_secs: u64,
    pub max_code_attempts: u32,
    pub pairing_concurrency_per_ip: u32,
    pub max_pairing_attempts_per_min: u32,
    pub spake2_group: String,
    pub pairing_binding_label: String,
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
            spake2_group: "edwards25519".into(),
            pairing_binding_label: PAIRING_BINDING_LABEL.into(),
            pairing_ack_timeout_secs: PAIRING_ACK_TIMEOUT_SECS,
            pairing_max_retries: PAIRING_MAX_RETRIES,
            identity_gc_stale_days: IDENTITY_GC_STALE_DAYS,
        }
    }
}

impl PairingConfig {
    /// Reject values that would disable pairing safeguards or select an unsupported PAKE group.
    pub fn validate(&self) -> Result<(), String> {
        if self.code_validity_secs == 0 {
            return Err("code_validity_secs must be greater than zero".into());
        }
        if self.max_code_attempts == 0 {
            return Err("max_code_attempts must be greater than zero".into());
        }
        if self.pairing_concurrency_per_ip == 0 || self.max_pairing_attempts_per_min == 0 {
            return Err("pairing rate limits must be greater than zero".into());
        }
        if self.spake2_group != "edwards25519" {
            return Err(format!("unsupported SPAKE2 group: {}", self.spake2_group));
        }
        if self.pairing_binding_label.is_empty() {
            return Err("pairing_binding_label must not be empty".into());
        }
        if self.pairing_ack_timeout_secs == 0 {
            return Err("pairing_ack_timeout_secs must be greater than zero".into());
        }
        if self.identity_gc_stale_days <= 0 {
            return Err("identity_gc_stale_days must be greater than zero".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_runtime_pairing_policy() {
        let json = r#"{
            "code_validity_secs": 45,
            "max_code_attempts": 2,
            "pairing_ack_timeout_secs": 4,
            "pairing_max_retries": 1,
            "pairing_binding_label": "privet-test-binding"
        }"#;
        let config: PairingConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.code_validity_secs, 45);
        assert_eq!(config.max_code_attempts, 2);
        assert_eq!(config.pairing_ack_timeout_secs, 4);
        assert_eq!(config.pairing_max_retries, 1);
        assert_eq!(config.pairing_binding_label, "privet-test-binding");
        config.validate().unwrap();
    }

    #[test]
    fn rejects_unsupported_or_unsafe_values() {
        let mut config = PairingConfig::default();
        config.max_code_attempts = 0;
        assert!(config.validate().is_err());

        let mut config = PairingConfig::default();
        config.spake2_group = "unsupported".into();
        assert!(config.validate().is_err());
    }
}
