//! 指数退避 \[1,2,4,8,16,30\]s + 6 次上限 -> Paused{reconnect_exhausted}。
use std::time::Duration;

use crate::constants::BACKOFF_SCHEDULE;
use crate::EngineEvent;

/// 退避迭代器：逐次返回 BACKOFF_SCHEDULE；超过上限返回 None。
/// 默认用全局退避表；测试可注入短 schedule（Vec 而非静态引用）。
#[derive(Debug)]
pub struct Backoff {
    attempt: u32,
    schedule: Vec<Duration>,
}

impl Backoff {
    pub fn new() -> Self {
        Self {
            attempt: 0,
            schedule: BACKOFF_SCHEDULE.to_vec(),
        }
    }
    /// 测试用：自定义退避表（如 vec![1ms, 1ms]）。
    pub fn with_schedule(schedule: Vec<Duration>) -> Self {
        Self {
            attempt: 0,
            schedule,
        }
    }
    pub fn next_backoff(&mut self) -> Option<Duration> {
        if self.attempt as usize >= self.schedule.len() {
            return None;
        }
        let d = self.schedule[self.attempt as usize];
        self.attempt += 1;
        Some(d)
    }
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

pub fn reconnect_event(transfer_id: &str, attempt: u32, backoff: Duration) -> EngineEvent {
    EngineEvent::TransferReconnecting {
        transfer_id: transfer_id.to_string(),
        attempt,
        backoff_ms: backoff.as_millis() as u64,
    }
}

pub fn resumed_event(transfer_id: &str) -> EngineEvent {
    EngineEvent::TransferResumed {
        transfer_id: transfer_id.to_string(),
    }
}

pub fn reset_on_success(b: &mut Backoff) {
    b.reset();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::BACKOFF_MAX_ATTEMPTS;

    #[test]
    fn backoff_schedule_is_spec() {
        assert_eq!(
            BACKOFF_SCHEDULE,
            &[1, 2, 4, 8, 16, 30].map(Duration::from_secs)
        );
        assert_eq!(BACKOFF_MAX_ATTEMPTS, 6);
    }

    #[test]
    fn backoff_iter_yields_then_exhausts() {
        let mut b = Backoff::new();
        assert_eq!(b.next_backoff(), Some(Duration::from_secs(1)));
        assert_eq!(b.next_backoff(), Some(Duration::from_secs(2)));
        for _ in 0..4 {
            let _ = b.next_backoff();
        }
        assert_eq!(b.next_backoff(), None);
    }

    #[test]
    fn reconnect_event_carries_attempt_and_backoff() {
        let e = reconnect_event("t1", 1, Duration::from_millis(1000));
        assert!(matches!(
            e,
            EngineEvent::TransferReconnecting {
                attempt: 1,
                backoff_ms: 1000,
                ..
            }
        ));
    }

    #[test]
    fn backoff_custom_schedule_exhausts_at_custom_len() {
        let short = vec![Duration::from_millis(5), Duration::from_millis(10)];
        let mut b = Backoff::with_schedule(short);
        assert_eq!(b.next_backoff(), Some(Duration::from_millis(5)));
        assert_eq!(b.next_backoff(), Some(Duration::from_millis(10)));
        assert_eq!(b.next_backoff(), None);
    }
}
