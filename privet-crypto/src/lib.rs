//! privet-crypto：身份密钥、PAKE、哈希、密钥存储抽象。无网络、无文件 I/O 之外副作用。

pub mod constants;
pub mod error;
pub mod hash;
pub mod keystore;
pub mod identity;
pub mod pake;
pub mod transcript;

pub use error::CryptoError;

/// 用系统 CSPRNG（getrandom）填充 `len` 字节。
pub fn random_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut out = vec![0u8; len];
    getrandom::getrandom(&mut out).map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(out)
}

/// 生成配对 nonce（NONCE_LEN 字节）。
pub fn gen_nonce() -> Result<[u8; constants::NONCE_LEN], CryptoError> {
    let mut out = [0u8; constants::NONCE_LEN];
    getrandom::getrandom(&mut out).map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(out)
}