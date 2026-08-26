
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChunkKey {
    pub file_id: String,
    pub segment_id: u32,
    pub chunk_index: u64,
}

#[derive(Debug, Clone)]
struct InFlightEntry {
    sent_at: tokio::time::Instant,
    retries: u32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum AckPhase {
    #[default]
    PreFirstAck,
    Armed,
}

#[derive(Default)]
pub struct InFlightTracker {
    map: HashMap<ChunkKey, InFlightEntry>,
    phase: AckPhase,
    #[allow(dead_code)]
    last_ack_at: Option<tokio::time::Instant>,
    frontier: HashMap<(String, u32), u64>,
}

impl InFlightTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn track(&mut self, key: ChunkKey) {
        self.map.insert(
            key,
            InFlightEntry {
                sent_at: tokio::time::Instant::now(),
                retries: 0,
            },
        );
    }

    pub fn on_ack(&mut self, file_id: &str, segment_id: u32, chunk_indices: &[u64]) -> usize {
        if !chunk_indices.is_empty() {
            self.phase = AckPhase::Armed;
            self.last_ack_at = Some(tokio::time::Instant::now());
            let key = (file_id.to_string(), segment_id);
            let frontier = self.frontier.entry(key).or_insert(0);
            for ci in chunk_indices {
                if *ci > *frontier {
                    *frontier = *ci;
                }
            }
        }
        let mut removed = 0;
        for ci in chunk_indices {
            if self
                .map
                .remove(&ChunkKey {
                    file_id: file_id.into(),
                    segment_id,
                    chunk_index: *ci,
                })
                .is_some()
            {
                removed += 1;
            }
        }
        removed
    }

    pub fn inflight_count(&self) -> usize {
        self.map.len()
    }

    pub fn rto_expired(&self, rto: Duration) -> Vec<ChunkKey> {
        let now = tokio::time::Instant::now();
        self.map
            .iter()
            .filter(|(_, e)| now.duration_since(e.sent_at) >= rto)
            .map(|(k, _)| k.clone())
            .collect()
    }

    ///
    ///
    pub fn rto_expired_selective(&self, rto: Duration) -> Vec<ChunkKey> {
        let now = tokio::time::Instant::now();
        let pre_first_ack = self.phase == AckPhase::PreFirstAck;
        self.map
            .iter()
            .filter(|(_, e)| now.duration_since(e.sent_at) >= rto)
            .filter(|(k, _)| {
                if pre_first_ack {
                    return true;
                }
                self.frontier
                    .get(&(k.file_id.clone(), k.segment_id))
                    .map(|&f| k.chunk_index < f)
                    .unwrap_or(false)
            })
            .map(|(k, _)| k.clone())
            .collect()
    }

    pub fn record_retry(&mut self, key: &ChunkKey) {
        if let Some(e) = self.map.get_mut(key) {
            e.retries += 1;
            e.sent_at = tokio::time::Instant::now();
        }
    }

    pub fn retries(&self, key: &ChunkKey) -> u32 {
        self.map.get(key).map(|e| e.retries).unwrap_or(0)
    }

    pub fn earliest_deadline(&self, rto: Duration) -> Option<tokio::time::Instant> {
        self.map.values().map(|e| e.sent_at + rto).min()
    }
}
