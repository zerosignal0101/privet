use async_trait::async_trait;
use privet_crypto::identity::Identity;
use privet_protocol::ControlFrame;
use privet_security::channel::{LoopbackChannel, MutableClock, PairingChannel};
use privet_security::commit::*;
use privet_security::session::PairingOutcome;
use privet_security::trust::{InMemoryTrustStore, TrustState, TrustStore};
use privet_security::PairingError;
use std::sync::Arc;

struct HangingChannel;
#[async_trait]
impl PairingChannel for HangingChannel {
    async fn send(&mut self, _frame: ControlFrame) -> Result<(), PairingError> {
        Ok(())
    }
    async fn recv(&mut self) -> Result<ControlFrame, PairingError> {
        std::future::pending().await
    }
}

fn make_proof() -> (PendingProof, Arc<InMemoryTrustStore>, InMemoryProofStore) {
    let id = Identity::generate().unwrap();
    let trust = Arc::new(InMemoryTrustStore::new());
    let proof = PendingProof {
        transcript_hash: [1u8; 32],
        transcript_sig_i: vec![2u8; 64],
        peer_device_fingerprint: "peer-d1".into(),
        peer_device_name: "peer".into(),
        peer_spki: id.spki_der().to_vec(),
        local_spki: vec![3u8; 32],
    };
    (proof, trust, InMemoryProofStore::new())
}

#[tokio::test]
async fn ack_timeout_unreachable_returns_failed_no_commit_and_clears_proof() {
    let (proof, trust, store) = make_proof();
    let (mut ch, _cr) = LoopbackChannel::pair(16);
    drop(_cr);
    let clk = Arc::new(MutableClock::new());
    clk.set(1000);
    assert!(store.load_pending().unwrap().is_none());
    let outcome = wait_for_ack(
        &mut ch,
        &*clk,
        &*trust,
        &proof,
        &store,
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    match outcome {
        PairingOutcome::Failed { reason } => {
            assert!(matches!(
                reason,
                privet_security::PairingError::TransportFailed(_)
            ));
        }
        _ => panic!("expected Failed on unreachable responder"),
    }
    assert!(trust.get("peer-d1").unwrap().is_none());
    assert!(
        store.load_pending().unwrap().is_none(),
        "proof cleared on failed"
    );
}

#[tokio::test]
async fn ack_delivered_commits_and_returns_paired_clears_proof() {
    let (proof, trust, store) = make_proof();
    let (mut ch_i, mut ch_r) = LoopbackChannel::pair(16);
    let clk = Arc::new(MutableClock::new());
    clk.set(1000);

    let ack = privet_protocol::ControlFrame {
        payload: Some(privet_protocol::control_frame::Payload::PairingResultAck(
            privet_protocol::PairingResultAck {
                transcript_hash: proof.transcript_hash.to_vec(),
            },
        )),
    };
    ch_r.send(ack).await.unwrap();
    drop(ch_r);

    let outcome = wait_for_ack(
        &mut ch_i,
        &*clk,
        &*trust,
        &proof,
        &store,
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert!(matches!(outcome, PairingOutcome::Paired { .. }));
    let r = trust.get("peer-d1").unwrap().unwrap();
    assert_eq!(r.trust_state, TrustState::Trusted);
    assert!(
        store.load_pending().unwrap().is_none(),
        "proof cleared after paired"
    );
}

#[tokio::test]
async fn ack_delayed_retry_powers_through() {
    let (proof, trust, store) = make_proof();
    let (mut ch, mut ch_r) = LoopbackChannel::pair(16);
    let clk = Arc::new(MutableClock::new());

    let hash = proof.transcript_hash.to_vec();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _ = ch_r
            .send(privet_protocol::ControlFrame {
                payload: Some(privet_protocol::control_frame::Payload::PairingResultAck(
                    privet_protocol::PairingResultAck {
                        transcript_hash: hash,
                    },
                )),
            })
            .await;
    });

    let outcome = wait_for_ack(
        &mut ch,
        &*clk,
        &*trust,
        &proof,
        &store,
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert!(matches!(outcome, PairingOutcome::Paired { .. }));
    assert_eq!(
        trust.get("peer-d1").unwrap().unwrap().trust_state,
        TrustState::Trusted
    );
}

#[tokio::test]
async fn ack_timeout_retries_exhausted_returns_failed_no_commit() {
    // AckTimeout retries exhausted -> Failed{AckTimeout}, no commit, proof cleared.
    let (proof, trust, store) = make_proof();
    let mut ch = HangingChannel;
    let clk = Arc::new(MutableClock::new());
    let started = std::time::Instant::now();
    let out = wait_for_ack(
        &mut ch,
        &*clk,
        &*trust,
        &proof,
        &store,
        std::time::Duration::from_millis(50),
    )
    .await
    .unwrap();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "must not wait 120s"
    );
    match out {
        PairingOutcome::Failed { reason } => {
            assert!(
                matches!(reason, privet_security::PairingError::AckTimeout),
                "expected AckTimeout, got {reason:?}"
            );
        }
        _ => panic!("expected Failed on AckTimeout"),
    }
    assert!(
        trust.get("peer-d1").unwrap().is_none(),
        "no commit on AckTimeout"
    );
    assert!(
        store.load_pending().unwrap().is_none(),
        "proof cleared after AckTimeout"
    );
}

#[test]
fn should_commit_true_for_unknown() {
    let trust = InMemoryTrustStore::new();
    assert!(should_commit(&trust, "ghost", &[1, 2, 3]).unwrap());
}

#[test]
fn should_commit_false_for_already_trusted_same_spki() {
    let trust = InMemoryTrustStore::new();
    trust
        .commit_peer(privet_security::trust::PeerTrust {
            device_fingerprint: "d1".into(),
            peer_spki: vec![1, 2, 3],
            peer_device_name: "p".into(),
            share_with_peers: false,
            first_paired_ts: 1,
            last_seen_ts: 1,
        })
        .unwrap();
    assert!(!should_commit(&trust, "d1", &[1, 2, 3]).unwrap());
}

#[test]
fn in_memory_proof_store_roundtrip() {
    let store = InMemoryProofStore::new();
    assert!(store.load_pending().unwrap().is_none());
    let proof = make_proof().0;
    store.store_pending(proof.clone()).unwrap();
    let loaded = store.load_pending().unwrap().unwrap();
    assert_eq!(loaded.transcript_hash, [1u8; 32]);
    store.clear_pending().unwrap();
    assert!(store.load_pending().unwrap().is_none());
}
