use privet_crypto::identity::Identity;
use privet_crypto::pake::Spake2Backend;
use privet_security::channel::{LoopbackChannel, MutableClock};
use privet_security::session::*;
use privet_security::trust::{InMemoryTrustStore, TrustState, TrustStore};
use std::sync::Arc;

fn inputs_for(peer: &Identity, exporter: [u8; 32]) -> SessionInputs {
    SessionInputs {
        code: "123456".into(),
        peer_device_fingerprint: peer.fingerprint(),
        peer_device_name: "peer".into(),
        peer_spki: peer.spki_der().to_vec(),
        exporter,
    }
}

#[tokio::test]
async fn happy_path_both_commit_trusted() {
    let i_id = Arc::new(Identity::generate().unwrap());
    let r_id = Arc::new(Identity::generate().unwrap());
    let i_inputs = inputs_for(&r_id, [7u8; 32]);
    let r_inputs = inputs_for(&i_id, [7u8; 32]);
    let (mut ch_i, mut ch_r) = LoopbackChannel::pair(16);
    let clock = Arc::new(MutableClock::new());
    let trust_i = Arc::new(InMemoryTrustStore::new());
    let trust_r = Arc::new(InMemoryTrustStore::new());
    let pake = Arc::new(Spake2Backend);

    let h = {
        let r_id = r_id.clone();
        let clock = clock.clone();
        let trust_r = trust_r.clone();
        let pake = pake.clone();
        tokio::spawn(async move {
            run_responder(&r_id, &r_inputs, &mut ch_r, &*clock, &*trust_r, &*pake).await
        })
    };
    let store = privet_security::commit::InMemoryProofStore::new();
    let oi = run_initiator(
        &i_id, &i_inputs, &mut ch_i, &*clock, &*trust_i, &*pake, &store,
    )
    .await
    .unwrap();
    let or = h.await.unwrap().unwrap();

    assert!(matches!(oi, PairingOutcome::Paired { .. }));
    assert!(matches!(or, PairingOutcome::Paired { .. }));

    // I 写了 trust(R)
    let ri = trust_i.get(&r_id.fingerprint()).unwrap().unwrap();
    assert_eq!(ri.trust_state, TrustState::Trusted);
    assert_eq!(ri.peer_spki, r_id.spki_der());

    // R 写了 trust(I)
    let rr = trust_r.get(&i_id.fingerprint()).unwrap().unwrap();
    assert_eq!(rr.trust_state, TrustState::Trusted);
    assert_eq!(rr.peer_spki, i_id.spki_der());
}
