//! 提交时序：I 侧 Pending proof + 重发 + ack 超时 Failed；R 侧幂等去重。
use std::time::Duration;

use privet_protocol::control_frame::Payload;
use privet_protocol::{ControlFrame, PairingResult, PairingResultAck};

use crate::channel::{PairingChannel, PairingClock};
use crate::constants::PAIRING_MAX_RETRIES;
use crate::session::PairingOutcome;
use crate::trust::{PeerTrust, TrustState, TrustStore};
use crate::PairingError;

/// I 侧 Pending proof（持久化，未提交；崩溃恢复可重发）。
#[derive(Debug, Clone)]
pub struct PendingProof {
    pub transcript_hash: [u8; 32],
    pub transcript_sig_i: Vec<u8>,
    pub peer_device_fingerprint: String,
    pub peer_device_name: String,
    pub peer_spki: Vec<u8>,
    /// I 自己的 SPKI（重发 PairingResult.identity_pubkey 须为 I 的 SPKI）。
    pub local_spki: Vec<u8>,
}

/// 可注入 proof 持久化（core 用 SQLite；测试 InMemory）。
pub trait ProofStore: Send + Sync {
    fn store_pending(&self, proof: PendingProof) -> Result<(), PairingError>;
    fn load_pending(&self) -> Result<Option<PendingProof>, PairingError>;
    fn clear_pending(&self) -> Result<(), PairingError>;
}

pub struct InMemoryProofStore(std::sync::Mutex<Option<PendingProof>>);
impl InMemoryProofStore {
    pub fn new() -> Self {
        Self(std::sync::Mutex::new(None))
    }
}
impl Default for InMemoryProofStore {
    fn default() -> Self {
        Self::new()
    }
}
impl ProofStore for InMemoryProofStore {
    fn store_pending(&self, proof: PendingProof) -> Result<(), PairingError> {
        *self.0.lock().unwrap() = Some(proof);
        Ok(())
    }
    fn load_pending(&self) -> Result<Option<PendingProof>, PairingError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn clear_pending(&self) -> Result<(), PairingError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

/// R 侧幂等判定：已信任同 SPKI 则返回 false（重 ack 不重提交）。
pub fn should_commit(
    trust: &dyn TrustStore,
    peer_device_fingerprint: &str,
    peer_spki: &[u8],
) -> Result<bool, PairingError> {
    match trust.get(peer_device_fingerprint)? {
        Some(r) if r.trust_state == TrustState::Trusted && r.peer_spki == peer_spki => Ok(false),
        _ => Ok(true),
    }
}

/// 构造重发用的 PairingResult ControlFrame。
fn resend_frame(local_spki: &[u8], transcript_sig_i: &[u8]) -> ControlFrame {
    ControlFrame {
        payload: Some(Payload::PairingResult(PairingResult {
            success: true,
            error: String::new(),
            identity_pubkey: local_spki.to_vec(),
            transcript_sig: transcript_sig_i.to_vec(),
        })),
    }
}

/// I 侧等 ack：重发 `resend` 最多 PAIRING_MAX_RETRIES 次，每次 `ack_timeout` 超时；
/// 收到匹配 ack -> 提交 trust(R) + 清 proof -> Paired；耗尽 -> Failed{AckTimeout} + 清 proof（不提交）。
pub async fn wait_for_ack(
    channel: &mut dyn PairingChannel,
    clock: &dyn PairingClock,
    trust: &dyn TrustStore,
    proof: &PendingProof,
    store: &dyn ProofStore,
    ack_timeout: Duration,
) -> Result<PairingOutcome, PairingError> {
    // I 进 Pending: 持久化 proof (转录+双签+R SPKI), 不提交 trust
    let _ = store.store_pending(proof.clone());
    let resend = resend_frame(&proof.local_spki, &proof.transcript_sig_i);
    for attempt in 0..=PAIRING_MAX_RETRIES {
        if attempt > 0 {
            let _ = channel.send(resend.clone()).await;
        }
        match tokio::time::timeout(ack_timeout, channel.recv()).await {
            Ok(Ok(frame)) => match frame.payload {
                Some(Payload::PairingResultAck(PairingResultAck { transcript_hash }))
                    if transcript_hash == proof.transcript_hash.to_vec() =>
                {
                    let now = clock.now_ms();
                    trust.commit_peer(PeerTrust {
                        device_fingerprint: proof.peer_device_fingerprint.clone(),
                        peer_spki: proof.peer_spki.clone(),
                        peer_device_name: proof.peer_device_name.clone(),
                        share_with_peers: false,
                        first_paired_ts: now,
                        last_seen_ts: now,
                    })?;
                    // 提交后清 proof
                    let _ = store.clear_pending();
                    return Ok(PairingOutcome::Paired {
                        peer_device_fingerprint: proof.peer_device_fingerprint.clone(),
                        peer_spki: proof.peer_spki.clone(),
                    });
                }
                _ => continue,
            },
            Ok(Err(_)) => {
                let _ = store.clear_pending();
                return Ok(PairingOutcome::Failed {
                    reason: PairingError::TransportFailed("channel closed".into()),
                });
            }
            Err(_) => continue,
        }
    }
    // retries exhausted: Failed{AckTimeout}, no commit, clear proof
    let _ = store.clear_pending();
    Ok(PairingOutcome::Failed {
        reason: PairingError::AckTimeout,
    })
}

/// 崩溃恢复：从持久化 proof 重发 Result + 等 ack（重连重发）。
pub async fn resume_pending(
    channel: &mut dyn PairingChannel,
    clock: &dyn PairingClock,
    trust: &dyn TrustStore,
    proof: &PendingProof,
    store: &dyn ProofStore,
    ack_timeout: Duration,
) -> Result<PairingOutcome, PairingError> {
    wait_for_ack(channel, clock, trust, proof, store, ack_timeout).await
}
