
use privet_transfer::inflight::{ChunkKey, InFlightTracker};
use std::time::Duration;

fn k(f: &str, s: u32, c: u64) -> ChunkKey {
    ChunkKey {
        file_id: f.into(),
        segment_id: s,
        chunk_index: c,
    }
}

#[tokio::test(start_paused = true)]
async fn track_ack_release() {
    let mut t = InFlightTracker::new();
    t.track(k("f", 0, 0));
    t.track(k("f", 0, 1));
    assert_eq!(t.inflight_count(), 2);
    let removed = t.on_ack("f", 0, &[0]);
    assert_eq!(removed, 1);
    assert_eq!(t.inflight_count(), 1);
}

#[tokio::test(start_paused = true)]
async fn rto_expired_after_window() {
    let mut t = InFlightTracker::new();
    t.track(k("f", 0, 5));
    assert!(t.rto_expired(Duration::from_secs(2)).is_empty());
    tokio::time::advance(Duration::from_secs(3)).await;
    let exp = t.rto_expired(Duration::from_secs(2));
    assert_eq!(exp.len(), 1);
    assert_eq!(exp[0].chunk_index, 5);
}

#[tokio::test(start_paused = true)]
async fn record_retry_recounts_and_restamps() {
    let mut t = InFlightTracker::new();
    let key = k("f", 0, 0);
    t.track(key.clone());
    tokio::time::advance(Duration::from_secs(3)).await;
    let _ = t.rto_expired(Duration::from_secs(2));
    t.record_retry(&key);
    assert_eq!(t.retries(&key), 1);
    // restamped -> not immediately expired again
    assert!(t.rto_expired(Duration::from_secs(2)).is_empty());
}

#[tokio::test(start_paused = true)]
async fn earliest_deadline_is_min_sent_at_plus_rto() {
    let mut t = InFlightTracker::new();
    t.track(k("f", 0, 0));
    tokio::time::advance(Duration::from_secs(1)).await;
    t.track(k("f", 0, 1)); // later sent_at
    let d = t.earliest_deadline(Duration::from_secs(2)).unwrap();
    assert_eq!(
        d,
        tokio::time::Instant::now() - Duration::from_secs(1) + Duration::from_secs(2)
    );
}


#[tokio::test(start_paused = true)]
async fn selective_pre_first_ack_returns_all_expired() {
    let mut t = InFlightTracker::new();
    t.track(k("f", 0, 0));
    t.track(k("f", 0, 1));
    tokio::time::advance(Duration::from_secs(3)).await;
    let exp = t.rto_expired_selective(Duration::from_secs(2));
    assert_eq!(exp.len(), 2, "PreFirstAck: all expired chunks returned");
}

#[tokio::test(start_paused = true)]
async fn selective_armed_behind_frontier_retransmitted() {
    let mut t = InFlightTracker::new();
    t.track(k("f", 0, 5));
    t.track(k("f", 0, 6));
    // chunk 7 acked -> frontier=7; chunk 5,6 still inflight, 5<7 && 6<7 -> behind frontier
    t.on_ack("f", 0, &[7, 8, 9]);
    tokio::time::advance(Duration::from_secs(3)).await;
    let exp = t.rto_expired_selective(Duration::from_secs(2));
    // chunk 5 behind frontier, chunk 6 behind frontier
    assert_eq!(exp.len(), 2, "Armed: both chunks behind frontier");
}

#[tokio::test(start_paused = true)]
async fn selective_armed_ahead_of_frontier_not_retransmitted() {
    let mut t = InFlightTracker::new();
    t.track(k("f", 0, 3));
    t.track(k("f", 0, 4));
    // acked 0..2 only -> frontier=2
    t.on_ack("f", 0, &[0, 1, 2]);
    tokio::time::advance(Duration::from_secs(3)).await;
    let exp = t.rto_expired_selective(Duration::from_secs(2));
    // chunk 3,4 > frontier(2) -> ahead -> NOT retransmitted
    assert!(
        exp.is_empty(),
        "Armed: chunks ahead of frontier not retransmitted"
    );
}

#[tokio::test(start_paused = true)]
async fn selective_empty_ack_does_not_arm() {
    let mut t = InFlightTracker::new();
    t.track(k("f", 0, 0));
    t.on_ack("f", 0, &[]);
    tokio::time::advance(Duration::from_secs(3)).await;
    let exp = t.rto_expired_selective(Duration::from_secs(2));
    assert_eq!(exp.len(), 1, "empty ack: PreFirstAck retains, all expired");
}
