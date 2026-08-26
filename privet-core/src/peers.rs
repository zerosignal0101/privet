//! 多 peer 连接管理 + 每 peer 并发上限（MAX_CONCURRENT_TRANSFERS_PER_PEER=1）。
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::Semaphore;

pub struct PeerPool {
    sems: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
}

impl PeerPool {
    pub fn new() -> Self {
        Self {
            sems: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn sem(&self, device_id: &str) -> Arc<Semaphore> {
        let mut m = self.sems.lock().unwrap();
        m.entry(device_id.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(1)))
            .clone()
    }

    pub async fn acquire_slot(
        &self,
        device_id: &str,
    ) -> crate::Result<tokio::sync::OwnedSemaphorePermit> {
        let sem = self.sem(device_id);
        let permit = tokio::time::timeout(std::time::Duration::from_secs(30), sem.acquire_owned())
            .await
            .map_err(|_| crate::CoreError::Internal("peer slot acquire timeout".into()))?
            .map_err(|_| crate::CoreError::Internal("semaphore closed".into()))?;
        Ok(permit)
    }

    pub fn try_acquire_slot(&self, device_id: &str) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let sem = self.sem(device_id);
        sem.try_acquire_owned().ok()
    }
}

impl Default for PeerPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn one_concurrent_transfer_per_peer() {
        let pool = PeerPool::new();
        let _g1 = pool.acquire_slot("dev1").await.unwrap();
        let g2 = pool.try_acquire_slot("dev1");
        assert!(
            g2.is_none(),
            "second concurrent transfer to same peer must block"
        );
        drop(_g1);
        let g3 = pool.try_acquire_slot("dev1");
        assert!(g3.is_some(), "after release, slot available");
    }

    #[tokio::test]
    async fn different_peers_independent() {
        let pool = PeerPool::new();
        let _a = pool.acquire_slot("dev1").await.unwrap();
        let b = pool.acquire_slot("dev2").await.unwrap();
        let _ = b;
    }
}
