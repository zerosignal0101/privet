use privet_crypto::identity::Identity;
use privet_crypto::pake::Spake2Backend;
use privet_security::channel::{LoopbackChannel, MutableClock};
use privet_security::code::PairingCode;
use privet_security::session::*;
use privet_security::trust::{InMemoryTrustStore, TrustState, TrustStore};
use std::sync::Arc;
use std::time::Duration;

fn inputs_for(peer: &Identity, code: &str, exporter: [u8; 32]) -> SessionInputs {
    SessionInputs {
        code: code.into(),
        peer_device_fingerprint: peer.fingerprint(),
        peer_device_name: "p".into(),
        peer_spki: peer.spki_der().to_vec(),
        exporter,
    }
}

#[tokio::test]
async fn mitm_different_exporter_at_least_one_fails() {
    let i_id = Arc::new(Identity::generate().unwrap());
    let r_id = Arc::new(Identity::generate().unwrap());
    let i_in = inputs_for(&r_id, "123456", [1u8; 32]);
    let r_in = inputs_for(&i_id, "123456", [2u8; 32]);
    let (mut ci, mut cr) = LoopbackChannel::pair(16);
    let clk = Arc::new(MutableClock::new());
    let ti = Arc::new(InMemoryTrustStore::new());
    let tr = Arc::new(InMemoryTrustStore::new());
    let pake = Arc::new(Spake2Backend);

    let h = {
        let r_id = r_id.clone();
        let tr = tr.clone();
        let clk = clk.clone();
        let pake = pake.clone();
        tokio::spawn(async move { run_responder(&r_id, &r_in, &mut cr, &*clk, &*tr, &*pake).await })
    };
    let oi = run_initiator(
        &i_id,
        &i_in,
        &mut ci,
        &*clk,
        &*ti,
        &*pake,
        &privet_security::commit::InMemoryProofStore::new(),
    )
    .await;
    // Responder may be stuck waiting for PairingResult; timeout to unstick
    let or = tokio::time::timeout(Duration::from_secs(3), h)
        .await
        .ok()
        .and_then(|r| r.ok())
        .and_then(|r| r.ok());
    let i_ok = matches!(&oi, Ok(PairingOutcome::Paired { .. }));
    let r_ok = matches!(&or, Some(PairingOutcome::Paired { .. }));
    // At least one side must NOT be paired
    assert!(
        !i_ok || !r_ok,
        "different exporter must prevent at least one from pairing"
    );
    assert!(ti
        .get(&r_id.fingerprint())
        .unwrap()
        .map_or(true, |r| r.trust_state != TrustState::Trusted));
    assert!(tr
        .get(&i_id.fingerprint())
        .unwrap()
        .map_or(true, |r| r.trust_state != TrustState::Trusted));
}

#[tokio::test]
async fn code_mismatch_fails_no_trust() {
    let i_id = Arc::new(Identity::generate().unwrap());
    let r_id = Arc::new(Identity::generate().unwrap());
    let (mut ci, mut cr) = LoopbackChannel::pair(16);
    let clk = Arc::new(MutableClock::new());
    let ti = Arc::new(InMemoryTrustStore::new());
    let tr = Arc::new(InMemoryTrustStore::new());
    let pake = Arc::new(Spake2Backend);
    let i_in = inputs_for(&r_id, "123456", [9u8; 32]);
    let r_in = inputs_for(&i_id, "000000", [9u8; 32]);

    let h = {
        let r_id = r_id.clone();
        let tr = tr.clone();
        let clk = clk.clone();
        let pake = pake.clone();
        tokio::spawn(async move { run_responder(&r_id, &r_in, &mut cr, &*clk, &*tr, &*pake).await })
    };
    let oi = run_initiator(
        &i_id,
        &i_in,
        &mut ci,
        &*clk,
        &*ti,
        &*pake,
        &privet_security::commit::InMemoryProofStore::new(),
    )
    .await;
    let _or = tokio::time::timeout(Duration::from_secs(3), h).await;
    let i_failed = matches!(&oi, Ok(PairingOutcome::Failed { .. })) || oi.is_err();
    assert!(i_failed, "code mismatch should fail initiator");
    assert!(ti.get(&r_id.fingerprint()).unwrap().is_none());
    assert!(tr.get(&i_id.fingerprint()).unwrap().is_none());
}

#[tokio::test]
async fn code_expiry_checked_fails() {
    let i_id = Arc::new(Identity::generate().unwrap());
    let r_id = Arc::new(Identity::generate().unwrap());
    let (mut ci, mut cr) = LoopbackChannel::pair(16);
    let clk = Arc::new(MutableClock::new());
    clk.set(1000);
    let ti = Arc::new(InMemoryTrustStore::new());
    let tr = Arc::new(InMemoryTrustStore::new());
    let pake = Arc::new(Spake2Backend);
    let i_in = inputs_for(&r_id, "123456", [9u8; 32]);
    let r_in = inputs_for(&i_id, "123456", [9u8; 32]);
    let mut code_i = PairingCode::generate_decimal(&*clk).unwrap();
    let mut code_r = PairingCode::generate_decimal(&*clk).unwrap();
    clk.set(1000 + 600_000 + 1);

    let h = {
        let r_id = r_id.clone();
        let tr = tr.clone();
        let clk = clk.clone();
        let pake = pake.clone();
        tokio::spawn(async move {
            run_responder_checked(&r_id, &r_in, &mut code_r, &mut cr, &*clk, &*tr, &*pake).await
        })
    };
    let oi = run_initiator_checked(
        &i_id,
        &i_in,
        &mut code_i,
        &mut ci,
        &*clk,
        &*ti,
        &*pake,
        &privet_security::commit::InMemoryProofStore::new(),
    )
    .await;
    let or = tokio::time::timeout(Duration::from_secs(3), h).await;
    assert!(matches!(
        &oi,
        Err(privet_security::PairingError::CodeExpired)
    ));
    // Responder checked wrapper detects expiry before any channel interaction
    if let Ok(Ok(r)) = or {
        assert!(r.is_err());
    }
}

#[tokio::test]
async fn attempts_exhausted_after_five_failures() {
    let clk = Arc::new(MutableClock::new());
    clk.set(1000);
    let mut code = PairingCode::generate_decimal(&*clk).unwrap();
    for _ in 0..4 {
        code.record_failure();
        assert!(!code.is_exhausted());
    }
    code.record_failure();
    assert!(code.is_exhausted());
    assert!(matches!(
        code.check_valid(1000),
        Err(privet_security::PairingError::AttemptsExhausted)
    ));
}

#[tokio::test]
async fn long_key_code_128bit_pairs_success() {
    let clk = Arc::new(MutableClock::new());
    clk.set(1000);
    let code_str = {
        let c = PairingCode::generate_long(&*clk, 16).unwrap();
        c.code().to_owned()
    };
    let i_id = Arc::new(Identity::generate().unwrap());
    let r_id = Arc::new(Identity::generate().unwrap());
    let i_in = SessionInputs {
        code: code_str.clone(),
        peer_device_fingerprint: r_id.fingerprint(),
        peer_device_name: "p".into(),
        peer_spki: r_id.spki_der().to_vec(),
        exporter: [5u8; 32],
    };
    let r_in = SessionInputs {
        code: code_str,
        peer_device_fingerprint: i_id.fingerprint(),
        peer_device_name: "p".into(),
        peer_spki: i_id.spki_der().to_vec(),
        exporter: [5u8; 32],
    };
    let (mut ci, mut cr) = LoopbackChannel::pair(16);
    let ti = Arc::new(InMemoryTrustStore::new());
    let tr = Arc::new(InMemoryTrustStore::new());
    let pake = Arc::new(Spake2Backend);
    let h = {
        let r_id = r_id.clone();
        let tr = tr.clone();
        let clk = clk.clone();
        let pake = pake.clone();
        tokio::spawn(async move { run_responder(&r_id, &r_in, &mut cr, &*clk, &*tr, &*pake).await })
    };
    let oi = run_initiator(
        &i_id,
        &i_in,
        &mut ci,
        &*clk,
        &*ti,
        &*pake,
        &privet_security::commit::InMemoryProofStore::new(),
    )
    .await
    .unwrap();
    let or = tokio::time::timeout(Duration::from_secs(3), h).await;
    assert!(matches!(oi, PairingOutcome::Paired { .. }));
    assert!(or
        .ok()
        .and_then(|r| r.ok())
        .is_some_and(|r| matches!(r, Ok(PairingOutcome::Paired { .. }))));
}

#[tokio::test]
async fn consumed_code_rejected_by_check_valid() {
    let clk = Arc::new(MutableClock::new());
    clk.set(1000);
    let mut code = PairingCode::generate_decimal(&*clk).unwrap();
    assert!(!code.is_consumed());
    assert!(code.check_valid(1000).is_ok());
    assert!(code.consume(), "consume returns true first time");
    assert!(code.is_consumed());
    let err = code.check_valid(1000).unwrap_err();
    assert!(
        matches!(err, privet_security::PairingError::AlreadyPaired),
        "got {err:?}"
    );
    assert!(!code.consume(), "second consume returns false");
}

#[tokio::test]
async fn initiator_checked_consumes_code_on_paired() {
    let i_id = Arc::new(Identity::generate().unwrap());
    let r_id = Arc::new(Identity::generate().unwrap());
    let (mut ci, mut cr) = LoopbackChannel::pair(16);
    let clk = Arc::new(MutableClock::new());
    clk.set(1000);
    let ti = Arc::new(InMemoryTrustStore::new());
    let tr = Arc::new(InMemoryTrustStore::new());
    let pake = Arc::new(Spake2Backend);
    let mut code = PairingCode::generate_decimal(&*clk).unwrap();
    let code_str = code.code().to_owned();

    let i_in = SessionInputs {
        code: code_str.clone(),
        peer_device_fingerprint: r_id.fingerprint(),
        peer_device_name: "p".into(),
        peer_spki: r_id.spki_der().to_vec(),
        exporter: [9u8; 32],
    };
    let r_in = SessionInputs {
        code: code_str,
        peer_device_fingerprint: i_id.fingerprint(),
        peer_device_name: "p".into(),
        peer_spki: i_id.spki_der().to_vec(),
        exporter: [9u8; 32],
    };

    let h = {
        let r_id = r_id.clone();
        let tr = tr.clone();
        let clk = clk.clone();
        let pake = pake.clone();
        tokio::spawn(async move { run_responder(&r_id, &r_in, &mut cr, &*clk, &*tr, &*pake).await })
    };
    let store = privet_security::commit::InMemoryProofStore::new();
    let oi = run_initiator_checked(
        &i_id, &i_in, &mut code, &mut ci, &*clk, &*ti, &*pake, &store,
    )
    .await;
    let _or = tokio::time::timeout(Duration::from_secs(3), h).await;
    assert!(
        matches!(oi, Ok(PairingOutcome::Paired { .. })),
        "first pairing ok: {oi:?}"
    );
    assert!(code.is_consumed(), "code consumed after paired");
}
