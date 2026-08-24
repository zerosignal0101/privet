//! 证书 SPKI 提取 + 钉扎决策 + 连接认证策略。
use der::{Decode, Encode};
use x509_cert::Certificate;

use crate::trust::{TrustState, TrustStore};
use crate::PairingError;

/// 从 X.509 叶子证书 DER 提取 SubjectPublicKeyInfo DER（fp = BLAKE3(SPKI)[0..4]）。
pub fn extract_spki(cert_der: &[u8]) -> Result<Vec<u8>, PairingError> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| PairingError::Protocol(format!("cert parse: {e}")))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| PairingError::Protocol(format!("spki encode: {e}")))?;
    Ok(spki_der)
}

/// 钉扎决策。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinDecision {
    /// 未命中信任库 -> 触发配对（非错误）。
    Unknown,
    /// 命中且 SPKI 一致且 Trusted -> 免码直连。
    Trusted,
    /// trust_state=Revoked -> 静默拒绝（不暴露"已被撤销"）。
    Revoked,
    /// SPKI 不符 -> 失败关闭（拒绝 + 状态不动 + 告警）。
    KeyMismatch { stored_spki: Vec<u8> },
}

/// 查信任库做钉扎决策。
pub fn pin(
    peer_spki: &[u8],
    peer_device_id: &str,
    store: &dyn TrustStore,
) -> Result<PinDecision, PairingError> {
    match store.get(peer_device_id)? {
        None => Ok(PinDecision::Unknown),
        Some(r) => match r.trust_state {
            TrustState::Trusted => {
                if r.peer_spki == peer_spki {
                    Ok(PinDecision::Trusted)
                } else {
                    Ok(PinDecision::KeyMismatch {
                        stored_spki: r.peer_spki.clone(),
                    })
                }
            }
            TrustState::Revoked => Ok(PinDecision::Revoked),
            TrustState::Unknown => Ok(PinDecision::Unknown),
        },
    }
}

/// 连接认证动作：钉扎决策映射到核心动作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnAuthAction {
    /// 已配对、SPKI 一致 -> 免码直连。
    AcceptCodeless,
    /// 未知设备 -> 触发配对流程（非错误）。
    TriggerPairing,
    /// Revoked 或 KeyMismatch -> 拒绝（静默 / 失败关闭告警）。
    Reject,
    /// SPKI 不符 -> 失败关闭：拒绝 + 状态不动 + 告警。
    FailClosedAlert,
}

/// 决策映射。
pub fn conn_auth_decision(d: PinDecision) -> ConnAuthAction {
    match d {
        PinDecision::Trusted => ConnAuthAction::AcceptCodeless,
        PinDecision::Unknown => ConnAuthAction::TriggerPairing,
        PinDecision::Revoked => ConnAuthAction::Reject,
        PinDecision::KeyMismatch { .. } => ConnAuthAction::FailClosedAlert,
    }
}
