//! SPAKE2 backend and confirmation-key derivation.

use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use crate::constants::PAIRING_CONFIRMATION_LABEL;
use crate::error::CryptoError;

pub struct PakeOutput {
    pub shared_key: Zeroizing<Vec<u8>>,
    pub confirmation_tag: [u8; 32],
}

impl PakeOutput {
    pub fn shared_key(&self) -> &Zeroizing<Vec<u8>> {
        &self.shared_key
    }
    pub fn confirmation_tag(&self) -> &[u8; 32] {
        &self.confirmation_tag
    }
}

pub trait PakeState: Send {
    fn finish(&mut self, peer_msg: &[u8]) -> Result<PakeOutput, CryptoError>;
}

pub trait PakeScheme: Send + Sync {
    fn start_initiator(
        &self,
        password: &[u8],
        id_a: &[u8],
        id_b: &[u8],
    ) -> Result<(Box<dyn PakeState>, Vec<u8>), CryptoError>;
    fn start_responder(
        &self,
        password: &[u8],
        id_a: &[u8],
        id_b: &[u8],
    ) -> Result<(Box<dyn PakeState>, Vec<u8>), CryptoError>;
}

pub struct Spake2Backend;

impl PakeScheme for Spake2Backend {
    fn start_initiator(
        &self,
        password: &[u8],
        fingerprint_a: &[u8],
        fingerprint_b: &[u8],
    ) -> Result<(Box<dyn PakeState>, Vec<u8>), CryptoError> {
        let (state, msg) = Spake2::<Ed25519Group>::start_a(
            &Password::new(password),
            &Identity::new(fingerprint_a),
            &Identity::new(fingerprint_b),
        );
        Ok((Box::new(Spake2State(Some(state))), msg))
    }

    fn start_responder(
        &self,
        password: &[u8],
        fingerprint_a: &[u8],
        fingerprint_b: &[u8],
    ) -> Result<(Box<dyn PakeState>, Vec<u8>), CryptoError> {
        let (state, msg) = Spake2::<Ed25519Group>::start_b(
            &Password::new(password),
            &Identity::new(fingerprint_a),
            &Identity::new(fingerprint_b),
        );
        Ok((Box::new(Spake2State(Some(state))), msg))
    }
}

struct Spake2State(Option<Spake2<Ed25519Group>>);

impl PakeState for Spake2State {
    fn finish(&mut self, peer_msg: &[u8]) -> Result<PakeOutput, CryptoError> {
        let state = self.0.take().ok_or(CryptoError::PakeAlreadyFinished)?;
        let shared = state
            .finish(peer_msg)
            .map_err(|e| CryptoError::Pake(e.to_string()))?;
        let shared_bytes: &[u8] = shared.as_slice();
        let confirmation_tag = derive_confirmation_tag(shared_bytes);
        Ok(PakeOutput {
            shared_key: Zeroizing::new(shared_bytes.to_vec()),
            confirmation_tag,
        })
    }
}


fn derive_confirmation_tag(shared_key: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(PAIRING_CONFIRMATION_LABEL);
    h.update(shared_key);
    h.finalize().into()
}
