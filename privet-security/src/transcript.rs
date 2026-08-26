use crate::PairingError;
use privet_crypto::transcript::TranscriptParts;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

#[allow(clippy::too_many_arguments)]
pub fn build_transcript_parts<'a>(
    role: Role,
    local_device_fingerprint: &'a str,
    local_spki: &'a [u8],
    peer_device_fingerprint: &'a str,
    peer_spki: &'a [u8],
    spake2_msg_i: &'a [u8],
    spake2_msg_r: &'a [u8],
    nonce_i: &'a [u8],
    nonce_r: &'a [u8],
    exporter: &'a [u8],
    confirmation_tag: &'a [u8; 32],
) -> TranscriptParts<'a> {
    let (id_i, id_r, spki_i, spki_r) = match role {
        Role::Initiator => (local_device_fingerprint, peer_device_fingerprint, local_spki, peer_spki),
        Role::Responder => (peer_device_fingerprint, local_device_fingerprint, peer_spki, local_spki),
    };
    TranscriptParts {
        proto_version: privet_protocol::constants::PROTO_VERSION,
        initiator_device_fingerprint: id_i,
        responder_device_fingerprint: id_r,
        initiator_spki: spki_i,
        responder_spki: spki_r,
        spake2_msg_i,
        spake2_msg_r,
        nonce_i,
        nonce_r,
        tls_exporter: exporter,
        confirmation_tag,
    }
}

pub fn assert_identity_binding(
    declared_pubkey: &[u8],
    tls_spki: &[u8],
) -> Result<(), PairingError> {
    if declared_pubkey == tls_spki {
        Ok(())
    } else {
        Err(PairingError::KeyMismatch)
    }
}
