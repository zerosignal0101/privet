use privet_security::code::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct FixedClock(AtomicU64);
impl Now for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[test]
fn decimal_code_is_six_digits() {
    let c = PairingCode::generate_decimal(&FixedClock(AtomicU64::new(1000))).unwrap();
    let s = c.code();
    assert_eq!(s.len(), 6);
    assert!(s.chars().all(|ch| ch.is_ascii_digit()));
}

#[test]
fn long_code_is_at_least_128_bits_base32() {
    let c = PairingCode::generate_long(&FixedClock(AtomicU64::new(1000)), 16).unwrap();
    let s = c.code();
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s).unwrap();
    assert!(decoded.len() * 8 >= 128);
}

#[test]
fn not_expired_within_validity() {
    let clk = FixedClock(AtomicU64::new(1000));
    let c = PairingCode::generate_decimal(&clk).unwrap();
    assert!(!c.is_expired(1000 + 599_000));
    assert!(c.is_expired(1000 + 600_000 + 1));
}

#[test]
fn record_failure_then_exhausted_at_five() {
    let clk = FixedClock(AtomicU64::new(1000));
    let mut c = PairingCode::generate_decimal(&clk).unwrap();
    for _ in 0..4 {
        c.record_failure();
        assert!(!c.is_exhausted());
    }
    c.record_failure();
    assert!(c.is_exhausted());
}

#[test]
fn consume_is_single_use() {
    let clk = FixedClock(AtomicU64::new(1000));
    let mut c = PairingCode::generate_decimal(&clk).unwrap();
    assert!(c.consume());
    assert!(!c.consume());
}

#[test]
fn as_password_roundtrips_decimal() {
    let clk = FixedClock(AtomicU64::new(1000));
    let c = PairingCode::generate_decimal(&clk).unwrap();
    assert_eq!(c.as_password(), c.code().as_bytes());
}

#[test]
fn long_code_password_not_short() {
    let clk = FixedClock(AtomicU64::new(1000));
    let c = PairingCode::generate_long(&clk, 16).unwrap();
    assert!(c.as_password().len() >= 26);
}

#[test]
fn custom_policy_controls_expiry_and_attempt_budget() {
    let clk = FixedClock(AtomicU64::new(1_000));
    let mut code = PairingCode::generate_decimal_with_policy(&clk, 2, 2).unwrap();
    assert!(!code.is_expired(3_000));
    assert!(code.is_expired(3_001));
    code.record_failure();
    assert!(!code.is_exhausted());
    code.record_failure();
    assert!(code.is_exhausted());
}
