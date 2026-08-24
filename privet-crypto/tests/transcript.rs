use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::SigningKey;
use privet_crypto::transcript::{
    sign_transcript, transcript_hash, verify_transcript, TranscriptParts,
};

fn sample_parts<'a>(exporter: &'a [u8], fp_i: &'a str, fp_r: &'a str) -> TranscriptParts<'a> {
    TranscriptParts {
        proto_version: 1,
        initiator_device_fingerprint: fp_i,
        responder_device_fingerprint: fp_r,
        initiator_spki: b"spki-i",
        responder_spki: b"spki-r",
        spake2_msg_i: b"msg-i",
        spake2_msg_r: b"msg-r",
        nonce_i: &[0u8; 16],
        nonce_r: &[1u8; 16],
        tls_exporter: exporter,
        confirmation_tag: &[2u8; 32],
    }
}

#[test]
fn both_sides_compute_same_hash_regardless_of_signer() {
    let exporter = [0xAA; 32];
    let h_i = transcript_hash(&sample_parts(&exporter, "alice", "bob"));
    let h_r = transcript_hash(&sample_parts(&exporter, "alice", "bob"));
    assert_eq!(h_i, h_r);
}

#[test]
fn different_exporter_gives_different_hash() {
    let h1 = transcript_hash(&sample_parts(&[1u8; 32], "a", "b"));
    let h2 = transcript_hash(&sample_parts(&[2u8; 32], "a", "b"));
    assert_ne!(h1, h2);
}

#[test]
fn swapping_initiator_responder_changes_hash() {
    let h1 = transcript_hash(&sample_parts(&[9u8; 32], "alice", "bob"));
    let h2 = transcript_hash(&sample_parts(&[9u8; 32], "bob", "alice"));
    assert_ne!(h1, h2);
}

#[test]
fn sign_and_verify_roundtrip() {
    let signing = SigningKey::from_bytes(&[1u8; 32]);
    let verifying = signing.verifying_key();
    let spki = verifying.to_public_key_der().unwrap();
    let h = transcript_hash(&sample_parts(&[3u8; 32], "a", "b"));
    let sig = sign_transcript(&signing, &h);
    verify_transcript(spki.as_ref(), &h, &sig).unwrap();
}

#[test]
fn wrong_key_fails_verification() {
    let signing_a = SigningKey::from_bytes(&[1u8; 32]);
    let verifying_b = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
    let spki_b = verifying_b.to_public_key_der().unwrap();
    let h = transcript_hash(&sample_parts(&[3u8; 32], "a", "b"));
    let sig_a = sign_transcript(&signing_a, &h);
    assert!(verify_transcript(spki_b.as_ref(), &h, &sig_a).is_err());
}

#[test]
fn modified_field_changes_hash() {
    let mut p = sample_parts(&[7u8; 32], "a", "b");
    let h0 = transcript_hash(&p);
    p.proto_version = 2;
    assert_ne!(transcript_hash(&p), h0);
}
