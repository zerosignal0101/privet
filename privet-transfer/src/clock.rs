//! 可注入时钟（与 privet-security::code::Now 同形；不跨 crate 复用以免反向依赖）。

use std::sync::atomic::{AtomicU64, Ordering};

/// 毫秒时钟（now_ms）。
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// 系统时钟。
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;
impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// 可设时钟（测过期/RTO/ack-timeout）。
#[derive(Debug, Default)]
pub struct MutableClock(AtomicU64);
impl MutableClock {
    pub fn new() -> Self {
        Self(0.into())
    }
    pub fn set(&self, ms: u64) {
        self.0.store(ms, Ordering::SeqCst);
    }
    pub fn advance(&self, by_ms: u64) {
        self.0.fetch_add(by_ms, Ordering::SeqCst);
    }
}
impl Clock for MutableClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutable_clock_set_and_advance() {
        let c = MutableClock::new();
        assert_eq!(c.now_ms(), 0);
        c.set(1000);
        assert_eq!(c.now_ms(), 1000);
        c.advance(500);
        assert_eq!(c.now_ms(), 1500);
    }

    #[test]
    fn system_clock_monotonic_nonzero() {
        let c = SystemClock;
        let a = c.now_ms();
        let b = c.now_ms();
        assert!(b >= a);
    }
}
