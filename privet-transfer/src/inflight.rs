//! 在途跟踪：已发未 ack 块 + RTO 调度 + 重试计数（超限 -> ChunkCorrupt）。
//! 纯逻辑 + tokio::time::Instant（测试用 pause/advance；无 I/O）。

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

/// 选择性重传裁决辅助：是否仍在“首 ack 到达前”的初始阶段。
/// 初始阶段允许按 RTO 重传（兼容全丢场景的 ChunkCorrupt 上限）；首个 ack 到达后
/// 仅重传“落后 ack 前沿”的块（见 `rto_expired_selective`）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum AckPhase {
    #[default]
    PreFirstAck,
    Armed,
}

#[derive(Default)]
pub struct InFlightTracker {
    map: HashMap<ChunkKey, InFlightEntry>,
    /// 是否已收到过任意 ChunkAck。
    phase: AckPhase,
    /// 最近一次收到 ack 的时刻（诊断/未来自适应 RTO 用）。
    #[allow(dead_code)]
    last_ack_at: Option<tokio::time::Instant>,
    /// (file_id, segment_id) -> 已 ack 的最大 chunk_index（ack 前沿）。
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
        // 任意 ack 到达即进入 Armed 阶段；记录前沿与时刻。
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

    /// 选择性重传：返回真正需要重传的 inflight 块。
    ///
    /// 仅在以下两种情形判定某块“丢失/需重传”：
    /// 1. **首 ack 到达前（PreFirstAck）**：尚未建立 ack 前沿，按 RTO 重传全部超时块
    ///    （兼容全丢场景触达 CHUNK_RETRANSMIT_MAX -> ChunkCorrupt 的上限语义）。
    /// 2. **Armed 阶段**：仅重传“落后 ack 前沿”的块——即同段内已有更高 index 的块被
    ///    ack，而本块仍未 ack。这表示本块在可靠传输中本应先到却未到 -> 视为丢失。
    ///
    /// 关键性质：QUIC/TCP 为有序可靠传输，接收方按序处理、ack 单调递增。因此
    /// Armed 阶段下“落后前沿”的块在真实链路上永不会出现（除非真丢），从而杜绝了
    /// 慢链路上“窗口填充耗时 > RTO 导致全体 inflight 块被判超时 -> 洪泛重传 ->
    /// ChunkCorrupt/连接死”的死锁。
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
                // Armed：仅保留落后 ack 前沿的块。
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
