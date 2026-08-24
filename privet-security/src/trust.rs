//! 信任库状态与可注入 trait。本 crate 不依赖 storage；core 用 storage::trust 实现真实 TrustStore。
use crate::PairingError;

/// 信任状态：Unknown 不在库；Trusted 公钥已钉扎；Revoked 退化为需重新配对。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustState {
    Unknown,
    Trusted,
    Revoked,
}

impl TrustState {
    /// 与 storage 的 String 列互转（storage::trust 用 "Trusted"/"Revoked"）。
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "Trusted" => Self::Trusted,
            "Revoked" => Self::Revoked,
            _ => Self::Unknown,
        }
    }
    pub fn to_db_str(self) -> &'static str {
        match self {
            Self::Trusted => "Trusted",
            Self::Revoked => "Revoked",
            Self::Unknown => "Unknown",
        }
    }
}

/// 待提交的对端信任条目。
#[derive(Debug, Clone)]
pub struct PeerTrust {
    pub device_fingerprint: String,
    pub peer_spki: Vec<u8>,
    pub peer_device_name: String,
    pub share_with_peers: bool,
    pub first_paired_ts: u64,
    pub last_seen_ts: u64,
}

/// 信任库记录（读出形态）。
#[derive(Debug, Clone)]
pub struct TrustRecord {
    pub device_fingerprint: String,
    pub peer_spki: Vec<u8>,
    pub peer_device_name: String,
    pub trust_state: TrustState,
    pub share_with_peers: bool,
    pub first_paired_ts: u64,
    pub last_seen_ts: u64,
    pub revoked_ts: Option<u64>,
    pub revocation_reason: Option<String>,
}

/// 可注入信任库（同步：短促 KV 操作；core 用 spawn_blocking 包 storage）。
pub trait TrustStore: Send + Sync {
    fn get(&self, device_fingerprint: &str) -> Result<Option<TrustRecord>, PairingError>;
    /// 提交/重配对：upsert（存在则覆盖 SPKI 并回到 Trusted）。
    fn commit_peer(&self, peer: PeerTrust) -> Result<(), PairingError>;
    fn revoke(&self, device_fingerprint: &str, reason: &str, now_ms: u64) -> Result<(), PairingError>;
    fn refresh_seen(
        &self,
        device_fingerprint: &str,
        peer_device_name: &str,
        now_ms: u64,
    ) -> Result<(), PairingError>;
    fn forget(&self, device_fingerprint: &str) -> Result<(), PairingError>;
}

/// 进程内信任库（测试/嵌入式）。
pub struct InMemoryTrustStore {
    inner: std::sync::Mutex<std::collections::HashMap<String, TrustRecord>>,
}

impl InMemoryTrustStore {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}
impl Default for InMemoryTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustStore for InMemoryTrustStore {
    fn get(&self, device_fingerprint: &str) -> Result<Option<TrustRecord>, PairingError> {
        Ok(self.inner.lock().unwrap().get(device_fingerprint).cloned())
    }
    fn commit_peer(&self, peer: PeerTrust) -> Result<(), PairingError> {
        let mut m = self.inner.lock().unwrap();
        let existing_first = m.get(&peer.device_fingerprint).and_then(|r| {
            if r.trust_state == TrustState::Trusted {
                Some(r.first_paired_ts)
            } else {
                None
            }
        });
        m.insert(
            peer.device_fingerprint.clone(),
            TrustRecord {
                device_fingerprint: peer.device_fingerprint,
                peer_spki: peer.peer_spki,
                peer_device_name: peer.peer_device_name,
                trust_state: TrustState::Trusted,
                share_with_peers: peer.share_with_peers,
                first_paired_ts: existing_first.unwrap_or(peer.first_paired_ts),
                last_seen_ts: peer.last_seen_ts,
                revoked_ts: None,
                revocation_reason: None,
            },
        );
        Ok(())
    }
    fn revoke(&self, device_fingerprint: &str, reason: &str, now_ms: u64) -> Result<(), PairingError> {
        let mut m = self.inner.lock().unwrap();
        if let Some(r) = m.get_mut(device_fingerprint) {
            r.trust_state = TrustState::Revoked;
            r.revoked_ts = Some(now_ms);
            r.revocation_reason = Some(reason.into());
        }
        Ok(())
    }
    fn refresh_seen(
        &self,
        device_fingerprint: &str,
        peer_device_name: &str,
        now_ms: u64,
    ) -> Result<(), PairingError> {
        let mut m = self.inner.lock().unwrap();
        if let Some(r) = m.get_mut(device_fingerprint) {
            r.last_seen_ts = now_ms;
            r.peer_device_name = peer_device_name.into();
        }
        Ok(())
    }
    fn forget(&self, device_fingerprint: &str) -> Result<(), PairingError> {
        self.inner.lock().unwrap().remove(device_fingerprint);
        Ok(())
    }
}
