//! 配对码生命周期：6 位十进制 或 ≥128bit base32 长码；600s/单次/错 5 次作废。
use crate::constants::{CODE_VALIDITY_SECS, MAX_CODE_ATTEMPTS};
use crate::PairingError;
use privet_crypto::random_bytes;

/// 时钟抽象（PairingClock 继承它）。
pub trait Now: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// 单次配对码。
pub struct PairingCode {
    code: String,
    generated_at_ms: u64,
    attempts: u32,
    consumed: bool,
}

impl PairingCode {
    /// 6 位十进制（手输/QR 内嵌）。
    pub fn generate_decimal(clock: &dyn Now) -> Result<Self, PairingError> {
        let rb = random_bytes(4)?;
        let n = u32::from_le_bytes([rb[0], rb[1], rb[2], rb[3]]) % 1_000_000;
        Ok(Self {
            code: format!("{n:06}"),
            generated_at_ms: clock.now_ms(),
            attempts: 0,
            consumed: false,
        })
    }

    /// 长密钥模式（QR 专用，≥128bit base32）。
    pub fn generate_long(clock: &dyn Now, bytes: usize) -> Result<Self, PairingError> {
        let raw = random_bytes(bytes.max(16))?;
        let code = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &raw);
        Ok(Self {
            code,
            generated_at_ms: clock.now_ms(),
            attempts: 0,
            consumed: false,
        })
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    /// SPAKE2 口令字符串（两方喂同一字符串）。
    pub fn as_password(&self) -> &[u8] {
        self.code.as_bytes()
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.generated_at_ms) > CODE_VALIDITY_SECS * 1000
    }

    pub fn record_failure(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }
    pub fn is_consumed(&self) -> bool {
        self.consumed
    }

    pub fn is_exhausted(&self) -> bool {
        self.attempts >= MAX_CODE_ATTEMPTS
    }

    /// 单次消费。成功返回 true，已消费返回 false。
    pub fn consume(&mut self) -> bool {
        if self.consumed {
            false
        } else {
            self.consumed = true;
            true
        }
    }

    /// 码有效性检查：已消费 AlreadyPaired；耗尽 AttemptsExhausted；过期 CodeExpired。
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
