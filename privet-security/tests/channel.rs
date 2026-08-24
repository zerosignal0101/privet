use privet_protocol::control_frame::Payload;
use privet_protocol::{ControlFrame, PairingResultAck};
use privet_security::channel::*;
use privet_security::code::Now;

#[tokio::test]
async fn loopback_pair_roundtrips_frames() {
    let (mut a, mut b) = LoopbackChannel::pair(8);
    let f = ControlFrame {
        payload: Some(Payload::PairingResultAck(PairingResultAck {
            transcript_hash: vec![1, 2, 3],
        })),
    };
    a.send(f.clone()).await.unwrap();
    let got = b.recv().await.unwrap();
    assert_eq!(got.payload, f.payload);
}

#[tokio::test]
async fn lossy_drops_then_delivers_on_resend() {
    let (mut a, b_raw) = LoopbackChannel::pair(8);
    let mut b = LossyChannel::drop_first(Box::new(b_raw), 1);
    let f = ControlFrame {
        payload: Some(Payload::PairingResultAck(PairingResultAck {
            transcript_hash: vec![9],
        })),
    };
    a.send(f.clone()).await.unwrap();
    // first frame dropped -> recv blocks until next frame
    let first = tokio::time::timeout(std::time::Duration::from_millis(50), b.recv()).await;
    assert!(first.is_err());
    a.send(f.clone()).await.unwrap();
    let got = b.recv().await.unwrap();
    assert_eq!(got.payload, f.payload);
}

#[tokio::test]
async fn mutable_clock_advances() {
    let c = MutableClock::new();
    c.set(1000);
    assert_eq!(c.now_ms(), 1000);
    c.set(2000);
    assert_eq!(c.now_ms(), 2000);
}

#[tokio::test]
async fn channel_closed_returns_error() {
    let (mut a, b) = LoopbackChannel::pair(8);
    drop(b);
    let f = ControlFrame { payload: None };
    let r = a.send(f).await;
    assert!(r.is_err());
}
