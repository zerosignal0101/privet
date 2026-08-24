use privet_crypto::identity::Identity;
use privet_crypto::transcript::transcript_hash;
use privet_security::transcript::*;

#[allow(clippy::too_many_arguments)]
fn hash_for(
    role: Role,
    id1: &Identity,
    id2: &Identity,
    exporter: &[u8; 32],
    tag: &[u8; 32],
    spake_i: &[u8],
    spake_r: &[u8],
    nonce_i: &[u8; 16],
    nonce_r: &[u8; 16],
) -> [u8; 32] {
    let local_id = match role {
        Role::Initiator => id1.fingerprint(),
        _ => id2.fingerprint(),
    };
    let peer_id = match role {
        Role::Initiator => id2.fingerprint(),
        _ => id1.fingerprint(),
    };
    let local_spki = match role {
        Role::Initiator => id1.spki_der(),
        _ => id2.spki_der(),
    };
    let peer_spki = match role {
        Role::Initiator => id2.spki_der(),
        _ => id1.spki_der(),
    };
    let parts = build_transcript_parts(
        role, &local_id, local_spki, &peer_id, peer_spki, spake_i, spake_r, nonce_i, nonce_r,
        exporter, tag,
    );
    transcript_hash(&parts)
}

#[test]
fn both_roles_compute_same_transcript_hash() {
    let id_i = Identity::generate().unwrap();
    let id_r = Identity::generate().unwrap();
    let spake_i = vec![0xaa; 32];
    let spake_r = vec![0xbb; 32];
    let nonce_i = [1u8; 16];
    let nonce_r = [2u8; 16];
    let exporter = [3u8; 32];
    let tag = [4u8; 32];

    let h_i = hash_for(
        Role::Initiator,
        &id_i,
        &id_r,
        &exporter,
        &tag,
        &spake_i,
        &spake_r,
        &nonce_i,
        &nonce_r,
    );
    let h_r = hash_for(
        Role::Responder,
        &id_i,
        &id_r,
        &exporter,
        &tag,
        &spake_i,
        &spake_r,
        &nonce_i,
        &nonce_r,
    );
    assert_eq!(h_i, h_r);
}

#[test]
fn different_exporter_yields_different_hash() {
    let id = Identity::generate().unwrap();
    let tag = [0u8; 32];
    let nonce = [0u8; 16];
    let spake = vec![];
    let h1 = hash_for(
        Role::Initiator,
        &id,
        &id,
        &[1u8; 32],
        &tag,
        &spake,
        &spake,
        &nonce,
        &nonce,
    );
    let h2 = hash_for(
        Role::Initiator,
        &id,
        &id,
        &[2u8; 32],
        &tag,
        &spake,
        &spake,
        &nonce,
        &nonce,
    );
    assert_ne!(h1, h2);
}

#[test]
fn identity_binding_passes_when_match() {
    let id = Identity::generate().unwrap();
    assert!(assert_identity_binding(id.spki_der(), id.spki_der()).is_ok());
}

#[test]
fn identity_binding_fails_when_mismatch() {
    assert!(assert_identity_binding(&[1, 2, 3], &[9, 9, 9]).is_err());
}
