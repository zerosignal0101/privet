use der::{Decode, Encode};
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, VerifyingKey};
use privet_crypto::hash::blake3;
use privet_crypto::identity::Identity;

#[test]
fn generate_sign_verify_roundtrip() {
    let id = Identity::generate().unwrap();
    let msg = b"transcript hash placeholder";
    let sig: Signature = id.sign(msg);
    Identity::verify(id.spki_der(), msg, &sig).unwrap();
}

#[test]
fn wrong_key_fails_verification() {
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    let sig = a.sign(b"x");
    assert!(Identity::verify(b.spki_der(), b"x", &sig).is_err());
}

#[test]
fn fingerprint_matches_blake3_of_spki_prefix() {
    let id = Identity::generate().unwrap();
    let expected = hex::encode(&blake3(id.spki_der()));
    assert_eq!(id.fingerprint(), expected);
}

#[test]
fn two_identities_distinct() {
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    assert_ne!(a.spki_der(), b.spki_der());
}

#[test]
fn cert_carries_identity_spki() {
    let id = Identity::generate().unwrap();
    let parsed = x509_cert::Certificate::from_der(id.cert_der()).expect("cert parses as X.509");
    let cert_spki = &parsed.tbs_certificate.subject_public_key_info;
    let cert_spki_der = cert_spki.to_der().expect("encode cert spki");
    assert_eq!(cert_spki_der.as_slice(), id.spki_der());
    let vk_from_cert = VerifyingKey::from_public_key_der(id.spki_der()).unwrap();
    assert_eq!(vk_from_cert.to_bytes(), id.verifying_key().to_bytes());
}
