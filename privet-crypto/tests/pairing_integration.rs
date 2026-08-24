//! 配对密码学层集成：Identity + SPAKE2 + 转录签名。
//! (1) 合法配对：双方派生相同 K/tag，互验签名通过；
//! (2) MITM 双腿 exporter 不同 -> 转录不同 -> 一条腿签名无法在另一条腿验过（P3 §4.4 安全核心）。

use privet_crypto::gen_nonce;
use privet_crypto::identity::Identity;
use privet_crypto::pake::{PakeScheme, Spake2Backend};
use privet_crypto::transcript::{transcript_hash, verify_transcript, TranscriptParts};

#[test]
fn happy_path_pairing() {
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let code = b"123456";
    let scheme = Spake2Backend;

    let (mut st_i, msg_i) = scheme
        .start_initiator(
            code,
            alice.fingerprint().as_bytes(),
            bob.fingerprint().as_bytes(),
        )
        .unwrap();
    let (mut st_r, msg_r) = scheme
        .start_responder(
            code,
            alice.fingerprint().as_bytes(),
            bob.fingerprint().as_bytes(),
        )
        .unwrap();

    let out_i = st_i.finish(&msg_r).unwrap();
    let out_r = st_r.finish(&msg_i).unwrap();
    assert_eq!(out_i.shared_key.as_slice(), out_r.shared_key.as_slice());
    assert_eq!(out_i.confirmation_tag, out_r.confirmation_tag);

    let nonce_i = gen_nonce().unwrap();
    let nonce_r = gen_nonce().unwrap();
    let exporter = [0xAAu8; 32];

    let parts = TranscriptParts {
        proto_version: 1,
        initiator_device_fingerprint: &alice.fingerprint(),
        responder_device_fingerprint: &bob.fingerprint(),
        initiator_spki: alice.spki_der(),
        responder_spki: bob.spki_der(),
        spake2_msg_i: &msg_i,
        spake2_msg_r: &msg_r,
        nonce_i: &nonce_i,
        nonce_r: &nonce_r,
        tls_exporter: &exporter,
        confirmation_tag: &out_i.confirmation_tag,
    };
    let h = transcript_hash(&parts);

    let sig_i = alice.sign(&h);
    let sig_r = bob.sign(&h);
    verify_transcript(bob.spki_der(), &h, &sig_r).unwrap();
    verify_transcript(alice.spki_der(), &h, &sig_i).unwrap();
}

#[test]
fn mitm_two_legs_signatures_do_not_cross_verify() {
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let code = b"654321";
    let scheme = Spake2Backend;

    let (mut st_i, msg_i) = scheme
        .start_initiator(
            code,
            alice.fingerprint().as_bytes(),
            bob.fingerprint().as_bytes(),
        )
        .unwrap();
    let (mut st_r, msg_r) = scheme
        .start_responder(
            code,
            alice.fingerprint().as_bytes(),
            bob.fingerprint().as_bytes(),
        )
        .unwrap();
    let out_i = st_i.finish(&msg_r).unwrap();
    let _out_r = st_r.finish(&msg_i).unwrap();

    let exporter_i_leg = [0xBBu8; 32];
    let exporter_r_leg = [0xCCu8; 32];

    let mut base = TranscriptParts {
        proto_version: 1,
        initiator_device_fingerprint: &alice.fingerprint(),
        responder_device_fingerprint: &bob.fingerprint(),
        initiator_spki: alice.spki_der(),
        responder_spki: bob.spki_der(),
        spake2_msg_i: &msg_i,
        spake2_msg_r: &msg_r,
        nonce_i: &[0u8; 16],
        nonce_r: &[1u8; 16],
        tls_exporter: &exporter_i_leg,
        confirmation_tag: &out_i.confirmation_tag,
    };
    let h_i = transcript_hash(&base);

    let sig_i_on_i_leg = alice.sign(&h_i);

    base.tls_exporter = &exporter_r_leg;
    let h_r = transcript_hash(&base);

    assert!(verify_transcript(alice.spki_der(), &h_r, &sig_i_on_i_leg).is_err());
}
