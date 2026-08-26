//! End-to-end pairing over concrete transports.
use std::time::Duration;

use privet_core::auth::{decide_auth, AuthPlan};
use privet_core::connection::{
    acquire_control, connect_peer, hello_exchange, hello_exchange_responder, ControlRole,
};
use privet_core::identity_tls::{build_tls_material, build_transports};
use privet_core::pairing::{
    run_pairing_initiator, run_pairing_responder, StreamPairingChannel, SystemPairingClock,
};
use privet_crypto::identity::Identity;
use privet_crypto::pake::Spake2Backend;
use privet_security::commit::InMemoryProofStore;
use privet_security::constants::{EXPORTER_LEN, PAIRING_BINDING_LABEL, PAIRING_CONTEXT_STRING};
use privet_security::session::{PairingOutcome, SessionInputs};
use privet_security::trust::{InMemoryTrustStore, PeerTrust, TrustStore};
use privet_transport::{Transport, TransportMode};

#[tokio::test]
async fn pairing_succeeds_over_quic() {
    let cfg = privet_core::EngineConfig::default();

    let srv_id = Identity::generate().unwrap();
    let cli_id = Identity::generate().unwrap();
    let (srv_quic, _) = build_transports(&cfg, build_tls_material(&srv_id).unwrap()).unwrap();
    let (cli_quic, cli_tcp) = build_transports(&cfg, build_tls_material(&cli_id).unwrap()).unwrap();

    let listener = srv_quic.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().await.unwrap();

    let code = "123456".to_string();
    let srv_trust = InMemoryTrustStore::new();
    let cli_trust = InMemoryTrustStore::new();
    let proof = InMemoryProofStore::new();
    let pake = Spake2Backend;
    let clock = SystemPairingClock;

    let accept = async {
        let conn = listener.accept().await.unwrap();
        let exporter_bytes = conn
            .export_keying_material(
                PAIRING_BINDING_LABEL.as_bytes(),
                Some(PAIRING_CONTEXT_STRING.as_bytes()),
            )
            .expect("exporter on server");
        let mut exporter = [0u8; EXPORTER_LEN];
        let n = exporter_bytes.len().min(EXPORTER_LEN);
        exporter[..n].copy_from_slice(&exporter_bytes[..n]);

        let mut ctrl = acquire_control(conn.as_ref(), ControlRole::Responder)
            .await
            .unwrap();
        let hello = hello_exchange_responder(ctrl.as_mut(), &srv_id, 1, "srv", "windows")
            .await
            .unwrap();

        let inputs = SessionInputs {
            code: code.clone(),
            peer_device_fingerprint: hello.device_fingerprint,
            peer_device_name: hello.device_name,
            peer_spki: cli_id.spki_der().to_vec(),
            exporter,
        };
        let mut ch = StreamPairingChannel::new(ctrl);
        let outcome = run_pairing_responder(&srv_id, &inputs, &mut ch, &clock, &srv_trust, &pake)
            .await
            .unwrap();
        (outcome, srv_trust, ch)
    };

    let connect = async {
        let conn = connect_peer(
            cli_quic.as_ref(),
            Some(cli_tcp.as_ref()),
            addr,
            TransportMode::Quic,
            None,
        )
        .await
        .unwrap();
        let mut ctrl = acquire_control(conn.as_ref(), ControlRole::Initiator)
            .await
            .unwrap();
        let ack = hello_exchange(ctrl.as_mut(), &cli_id, 1, "cli")
            .await
            .unwrap();
        let cert_der = conn.peer_cert_der().expect("client sees server cert");
        let peer_spki = privet_security::cert::extract_spki(&cert_der).unwrap();
        let exporter_bytes = conn
            .export_keying_material(
                PAIRING_BINDING_LABEL.as_bytes(),
                Some(PAIRING_CONTEXT_STRING.as_bytes()),
            )
            .unwrap();
        let mut exporter = [0u8; EXPORTER_LEN];
        let n = exporter_bytes.len().min(EXPORTER_LEN);
        exporter[..n].copy_from_slice(&exporter_bytes[..n]);
        let inputs = SessionInputs {
            code: code.clone(),
            peer_device_fingerprint: ack.device_fingerprint,
            peer_device_name: ack.device_name,
            peer_spki,
            exporter,
        };
        let mut ch = StreamPairingChannel::new(ctrl);
        let outcome =
            run_pairing_initiator(&cli_id, &inputs, &mut ch, &clock, &cli_trust, &proof, &pake)
                .await
                .unwrap();
        (outcome, cli_trust, inputs, ch)
    };

    let ((_r_outcome, _r_trust, _r_ch), (i_outcome, i_trust, inputs, _i_ch)) =
        tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(accept, connect)
        })
        .await
        .unwrap();

    assert!(
        matches!(i_outcome, PairingOutcome::Paired { .. }),
        "initiator pairing failed: {:?}",
        i_outcome
    );
    assert!(
        i_trust.get(&srv_id.fingerprint()).unwrap().is_some(),
        "client must trust server"
    );

    let plan = decide_auth(&inputs.peer_spki, &inputs.peer_device_fingerprint, &i_trust).unwrap();
    assert_eq!(plan, AuthPlan::AcceptCodeless);
}

#[tokio::test]
async fn codeless_pinning_for_trusted() {
    let trust = InMemoryTrustStore::new();
    let id = Identity::generate().unwrap();
    let spki = id.spki_der().to_vec();
    trust
        .commit_peer(PeerTrust {
            device_fingerprint: id.fingerprint(),
            peer_spki: spki.clone(),
            peer_device_name: "n".into(),
            share_with_peers: false,
            first_paired_ts: 1,
            last_seen_ts: 1,
        })
        .unwrap();
    let plan = decide_auth(&spki, &id.fingerprint(), &trust).unwrap();
    assert_eq!(plan, AuthPlan::AcceptCodeless);
}
