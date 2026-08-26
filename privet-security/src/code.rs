//! Pairing-code generation and lifetime enforcement.
use crate::constants::{CODE_VALIDITY_SECS, MAX_CODE_ATTEMPTS};
use crate::PairingError;
use privet_crypto::random_bytes;

pub trait Now: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub struct PairingCode {
    code: String,
    generated_at_ms: u64,
    attempts: u32,
    consumed: bool,
    validity_secs: u64,
    max_attempts: u32,
}

impl PairingCode {
    pub fn generate_decimal(clock: &dyn Now) -> Result<Self, PairingError> {
        Self::generate_decimal_with_policy(clock, CODE_VALIDITY_SECS, MAX_CODE_ATTEMPTS)
    }

    pub fn generate_decimal_with_policy(
        clock: &dyn Now,
        validity_secs: u64,
        max_attempts: u32,
    ) -> Result<Self, PairingError> {
        let rb = random_bytes(4)?;
        let n = u32::from_le_bytes([rb[0], rb[1], rb[2], rb[3]]) % 1_000_000;
        Ok(Self {
            code: format!("{n:06}"),
            generated_at_ms: clock.now_ms(),
            attempts: 0,
            consumed: false,
            validity_secs,
            max_attempts,
        })
    }

    pub fn generate_long(clock: &dyn Now, bytes: usize) -> Result<Self, PairingError> {
        Self::generate_long_with_policy(
            clock,
            bytes,
            CODE_VALIDITY_SECS,
            MAX_CODE_ATTEMPTS,
        )
    }

    pub fn generate_long_with_policy(
        clock: &dyn Now,
        bytes: usize,
        validity_secs: u64,
        max_attempts: u32,
    ) -> Result<Self, PairingError> {
        let raw = random_bytes(bytes.max(16))?;
        let code = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &raw);
        Ok(Self {
            code,
            generated_at_ms: clock.now_ms(),
            attempts: 0,
            consumed: false,
            validity_secs,
            max_attempts,
        })
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn as_password(&self) -> &[u8] {
        self.code.as_bytes()
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.generated_at_ms) > self.validity_secs.saturating_mul(1000)
    }

    pub fn record_failure(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }
    pub fn is_consumed(&self) -> bool {
        self.consumed
    }

    pub fn is_exhausted(&self) -> bool {
        self.attempts >= self.max_attempts
    }

    pub fn consume(&mut self) -> bool {
        if self.consumed {
            false
        } else {
            self.consumed = true;
            true
        }
    }

    pub fn check_valid(&self, now_ms: u64) -> Result<(), crate::PairingError> {
        if self.consumed {
            return Err(crate::PairingError::AlreadyPaired);
        }
        if self.is_exhausted() {
            return Err(crate::PairingError::AttemptsExhausted);
        }
        if self.is_expired(now_ms) {
            return Err(crate::PairingError::CodeExpired);
        }
        Ok(())
    }
}
