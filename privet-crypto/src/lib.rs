//! Device identity, PAKE, hashing, and keystore primitives.

pub mod constants;
pub mod error;
pub mod hash;
pub mod keystore;
pub mod identity;
pub mod pake;
pub mod transcript;

pub use error::CryptoError;

pub fn random_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut out = vec![0u8; len];
    getrandom::getrandom(&mut out).map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(out)
}

pub fn gen_nonce() -> Result<[u8; constants::NONCE_LEN], CryptoError> {
    let mut out = [0u8; constants::NONCE_LEN];
    getrandom::getrandom(&mut out).map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(out)
}
