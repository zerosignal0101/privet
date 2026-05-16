use std::net::SocketAddr;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub Uuid);

impl PeerId {
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: PeerId,
    pub name: String,
    pub addresses: Vec<SocketAddr>,
    pub fingerprint: String,
    pub is_trusted: bool,
    pub last_seen: SystemTime,
    pub platform: Option<String>,
    pub version: Option<String>,
}

impl PeerInfo {
    pub fn primary_address(&self) -> Option<SocketAddr> {
        self.addresses.first().copied()
    }

    pub fn display_fingerprint(&self) -> &str {
        // Show first 12 hex chars for display
        let end = self.fingerprint.len().min(12);
        &self.fingerprint[..end]
    }
}
