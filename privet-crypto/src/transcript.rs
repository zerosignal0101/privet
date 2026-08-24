//! 配对转录：规范化拼接 -> BLAKE3 -> Ed25519 签名/验签

use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::constants::PAIRING_CONTEXT_STRING;
use crate::error::CryptoError;

pub struct TranscriptParts<'a> {
    pub proto_version: u32,
    pub initiator_device_fingerprint: &'a str,
    pub responder_device_fingerprint: &'a str,
    pub initiator_spki: &'a [u8],
    pub responder_spki: &'a [u8],
    pub spake2_msg_i: &'a [u8],
    pub spake2_msg_r: &'a [u8],
    pub nonce_i: &'a [u8],
    pub nonce_r: &'a [u8],
    pub tls_exporter: &'a [u8],
    pub confirmation_tag: &'a [u8; 32],
}

/// 转录哈希：BLAKE3(canonical_concat(...))。
/// canonical 编码 = 每字段「tag(ASCII) + 8B LE length + value」，无歧义、域分隔。
/// initiator 字段恒在前（与谁签名无关），双方算同一 hash。
pub fn transcript_hash(parts: &TranscriptParts<'_>) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    field(&mut h, b"proto_version", &parts.proto_version.to_le_bytes());
    field(&mut h, b"context", PAIRING_CONTEXT_STRING.as_bytes());
    field(&mut h, b"fingerprint_i", parts.initiator_device_fingerprint.as_bytes());
    field(&mut h, b"fingerprint_r", parts.responder_device_fingerprint.as_bytes());
    field(&mut h, b"spki_i", parts.initiator_spki);
    field(&mut h, b"spki_r", parts.responder_spki);
    field(&mut h, b"spake_i", parts.spake2_msg_i);
    field(&mut h, b"spake_r", parts.spake2_msg_r);
    field(&mut h, b"nonce_i", parts.nonce_i);
    field(&mut h, b"nonce_r", parts.nonce_r);
    field(&mut h, b"exporter", parts.tls_exporter);
    field(&mut h, b"confirm", parts.confirmation_tag);
    h.finalize().into()
}

fn field(h: &mut blake3::Hasher, tag: &[u8], value: &[u8]) {
    h.update(tag);
    h.update(&(value.len() as u64).to_le_bytes());
    h.update(value);
}

pub fn sign_transcript(signing: &SigningKey, hash: &[u8; 32]) -> Signature {
    signing.sign(hash)
}

pub fn verify_transcript(
    peer_spki: &[u8],
    hash: &[u8; 32],
    sig: &Signature,
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_public_key_der(peer_spki)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    vk.verify(hash, sig)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))
}
