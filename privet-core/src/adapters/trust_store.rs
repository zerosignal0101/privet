use std::sync::{Arc, Mutex};

use privet_security::commit::{PendingProof, ProofStore};
use privet_security::trust::{PeerTrust, TrustRecord, TrustState, TrustStore};
use privet_security::PairingError;

pub struct StorageTrustStore {
    db: Arc<Mutex<rusqlite::Connection>>,
}

impl StorageTrustStore {
    pub fn new(db: Arc<Mutex<rusqlite::Connection>>) -> Self {
        Self { db }
    }
    fn conn(&self) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, PairingError> {
        self.db
            .lock()
            .map_err(|_| PairingError::TransportFailed("db lock poisoned".into()))
    }
}

fn to_record(r: privet_storage::trust::TrustRecord) -> TrustRecord {
    TrustRecord {
        device_fingerprint: r.device_fingerprint,
        peer_spki: r.peer_spki,
        peer_device_name: r.peer_device_name,
        trust_state: TrustState::from_db_str(&r.trust_state),
        share_with_peers: r.share_with_peers,
        first_paired_ts: r.first_paired_ts as u64,
        last_seen_ts: r.last_seen_ts as u64,
        revoked_ts: r.revoked_ts.map(|t| t as u64),
        revocation_reason: r.revocation_reason,
    }
}

impl TrustStore for StorageTrustStore {
    fn get(&self, device_fingerprint: &str) -> Result<Option<TrustRecord>, PairingError> {
        let c = self.conn()?;
        Ok(privet_storage::trust::get_trust(&c, device_fingerprint)
            .map_err(|e| PairingError::TransportFailed(e.to_string()))?
            .map(to_record))
    }
    fn commit_peer(&self, peer: PeerTrust) -> Result<(), PairingError> {
        let c = self.conn()?;
        let t = privet_storage::trust::PeerTrust {
            device_fingerprint: &peer.device_fingerprint,
            peer_spki: &peer.peer_spki,
            peer_device_name: &peer.peer_device_name,
            share_with_peers: peer.share_with_peers,
            first_paired_ts: peer.first_paired_ts as i64,
            last_seen_ts: peer.last_seen_ts as i64,
        };
        privet_storage::trust::insert_trust(&c, &t)
            .map_err(|e| PairingError::TransportFailed(e.to_string()))?;
        Ok(())
    }
    fn revoke(&self, device_fingerprint: &str, reason: &str, now_ms: u64) -> Result<(), PairingError> {
        let c = self.conn()?;
        privet_storage::trust::revoke(&c, device_fingerprint, reason, now_ms as i64)
            .map_err(|e| PairingError::TransportFailed(e.to_string()))
    }
    fn refresh_seen(
        &self,
        device_fingerprint: &str,
        peer_device_name: &str,
        now_ms: u64,
    ) -> Result<(), PairingError> {
        let c = self.conn()?;
        privet_storage::trust::refresh_seen(&c, device_fingerprint, peer_device_name, now_ms as i64)
            .map_err(|e| PairingError::TransportFailed(e.to_string()))
    }
    fn forget(&self, device_fingerprint: &str) -> Result<(), PairingError> {
        let c = self.conn()?;
        privet_storage::trust::forget(&c, device_fingerprint)
            .map_err(|e| PairingError::TransportFailed(e.to_string()))
    }
}


#[derive(serde::Serialize, serde::Deserialize)]
struct PendingProofSer {
    transcript_hash: [u8; 32],
    transcript_sig_i: Vec<u8>,
    peer_device_fingerprint: String,
    peer_device_name: String,
    peer_spki: Vec<u8>,
    local_spki: Vec<u8>,
}

fn proof_ser(p: &PendingProof) -> PendingProofSer {
    PendingProofSer {
        transcript_hash: p.transcript_hash,
        transcript_sig_i: p.transcript_sig_i.clone(),
        peer_device_fingerprint: p.peer_device_fingerprint.clone(),
        peer_device_name: p.peer_device_name.clone(),
        peer_spki: p.peer_spki.clone(),
        local_spki: p.local_spki.clone(),
    }
}
fn proof_de(s: &PendingProofSer) -> PendingProof {
    PendingProof {
        transcript_hash: s.transcript_hash,
        transcript_sig_i: s.transcript_sig_i.clone(),
        peer_device_fingerprint: s.peer_device_fingerprint.clone(),
        peer_device_name: s.peer_device_name.clone(),
        peer_spki: s.peer_spki.clone(),
        local_spki: s.local_spki.clone(),
    }
}

impl ProofStore for StorageTrustStore {
    fn store_pending(&self, proof: PendingProof) -> Result<(), PairingError> {
        let c = self.conn()?;
        let bytes = bincode::serialize(&proof_ser(&proof))
            .map_err(|e| PairingError::TransportFailed(e.to_string()))?;
        c.execute(
            "CREATE TABLE IF NOT EXISTS core_kv(k TEXT PRIMARY KEY, v BLOB)",
            [],
        )
        .map_err(|e| PairingError::TransportFailed(e.to_string()))
        .map(|_| ())?;
        c.execute(
            "INSERT INTO core_kv(k,v) VALUES('pending_proof',?1) ON CONFLICT(k) DO UPDATE SET v=?1",
            rusqlite::params![bytes],
        )
        .map_err(|e| PairingError::TransportFailed(e.to_string()))
        .map(|_| ())
    }
    fn load_pending(&self) -> Result<Option<PendingProof>, PairingError> {
        let c = self.conn()?;
        let res: rusqlite::Result<Option<Vec<u8>>> =
            c.query_row("SELECT v FROM core_kv WHERE k='pending_proof'", [], |r| {
                r.get(0)
            });
        match res {
            Ok(Some(bytes)) => {
                let s: PendingProofSer = bincode::deserialize(&bytes)
                    .map_err(|e| PairingError::TransportFailed(e.to_string()))?;
                Ok(Some(proof_de(&s)))
            }
            Ok(None) => Ok(None),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(PairingError::TransportFailed(e.to_string())),
        }
    }
    fn clear_pending(&self) -> Result<(), PairingError> {
        let c = self.conn()?;
        c.execute("DELETE FROM core_kv WHERE k='pending_proof'", [])
            .map_err(|e| PairingError::TransportFailed(e.to_string()))
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_store() -> StorageTrustStore {
        let conn = privet_storage::migration::open_and_migrate(":memory:").unwrap();
        StorageTrustStore::new(Arc::new(Mutex::new(conn)))
    }

    #[test]
    fn commit_then_get_trusted() {
        let s = mem_store();
        s.commit_peer(PeerTrust {
            device_fingerprint: "dev1".into(),
            peer_spki: vec![1, 2, 3],
            peer_device_name: "peer".into(),
            share_with_peers: false,
            first_paired_ts: 100,
            last_seen_ts: 100,
        })
        .unwrap();
        let r = s.get("dev1").unwrap().unwrap();
        assert_eq!(r.trust_state, TrustState::Trusted);
        assert_eq!(r.peer_spki, vec![1, 2, 3]);
    }

    #[test]
    fn revoke_then_state_revoked() {
        let s = mem_store();
        s.commit_peer(PeerTrust {
            device_fingerprint: "d".into(),
            peer_spki: vec![1],
            peer_device_name: "p".into(),
            share_with_peers: false,
            first_paired_ts: 1,
            last_seen_ts: 1,
        })
        .unwrap();
        s.revoke("d", "user", 999).unwrap();
        assert_eq!(
            s.get("d").unwrap().unwrap().trust_state,
            TrustState::Revoked
        );
    }

    #[test]
    fn proof_store_roundtrip() {
        let s = mem_store();
        let p = PendingProof {
            transcript_hash: [0u8; 32],
            transcript_sig_i: vec![9, 9],
            peer_device_fingerprint: "d".into(),
            peer_device_name: "p".into(),
            peer_spki: vec![1],
            local_spki: vec![2],
        };
        s.store_pending(p.clone()).unwrap();
        assert_eq!(s.load_pending().unwrap().unwrap().peer_device_fingerprint, "d");
        s.clear_pending().unwrap();
        assert!(s.load_pending().unwrap().is_none());
    }
}
