//! PAKE 包装：可注入 `PakeScheme` trait + SPAKE2(Ed25519Group) 后端（RustCrypto `spake2` crate）。
//!
//! 采用平衡式 SPAKE2（RFC 9383 balanced）
//! 内存清零范围（诚实声明）：
//! - 派生 `shared_key: Zeroizing<Vec<u8>>` 在 drop 时清零（"内存清零" 契约）。
//! - `Spake2State` 内部的 `Spake2<Ed25519Group>` 中间状态**不**被清零：`spake2` 0.4 crate
//!   无 `zeroize` feature，且其内部字段不公开、无法手动清零。该状态短命，`finish()` 后即
//!   drop；依 "端点 OS 未被攻破" 假设，进程内存不被外部读取，此为可接受残余风险。

use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use crate::constants::PAIRING_CONFIRMATION_LABEL;
use crate::error::CryptoError;

/// PAKE 输出：共享密钥 + 确认标签（K_shared 派生，双方须一致）。
/// zeroize: PAKE 状态、派生密钥 drop 时清零。
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

/// 单次 PAKE 状态（finish 消费内部状态，single-use）。
pub trait PakeState: Send {
    fn finish(&mut self, peer_msg: &[u8]) -> Result<PakeOutput, CryptoError>;
}

/// PAKE 方案（可注入替换）。
pub trait PakeScheme: Send + Sync {
    /// 发起方（A 角色）。`id_a`/`id_b` 须双方一致（= 发起方/应答方 device_id）。
    fn start_initiator(
        &self,
        password: &[u8],
        id_a: &[u8],
        id_b: &[u8],
    ) -> Result<(Box<dyn PakeState>, Vec<u8>), CryptoError>;
    /// 应答方（B 角色）。
    fn start_responder(
        &self,
        password: &[u8],
        id_a: &[u8],
        id_b: &[u8],
    ) -> Result<(Box<dyn PakeState>, Vec<u8>), CryptoError>;
}

/// 基于 RustCrypto `spake2` 的 SPAKE2 后端。
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

// 注：不 `impl ZeroizeOnDrop`（spake2 0.4 无 zeroize feature，手动 marker 无 Drop 胶团即谎言）。
// 仅 `shared_key: Zeroizing<Vec<u8>>` 真正清零

/// 确认标签 = BLAKE3(PAIRING_CONFIRMATION_LABEL || K_shared)（K_shared 派生，双方一致）。
fn derive_confirmation_tag(shared_key: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(PAIRING_CONFIRMATION_LABEL);
    h.update(shared_key);
    h.finalize().into()
}
