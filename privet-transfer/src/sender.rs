//! Sender 状态机：
//! Preparing(已由调用方 prepare 好传入) -> offer + FileSetBatch 流式 -> SegmentManifest 逐段 -> chunk 发送队列(work-stealing, 窗口+RTO) -> inline -> TransferComplete -> 等 TransferVerified。

use std::collections::HashMap;
use std::path::PathBuf;

use privet_protocol::{
    control_frame::Payload as CPayload, data_frame::Payload as DPayload, ChunkHeader, ControlFrame,
    ControlMessage, DataFrame, SegmentManifest,
};

use crate::config::TransferEngineConfig;
use crate::constants::{CHUNK_RETRANSMIT_MAX, CHUNK_RETRANSMIT_RTO, INFLIGHT_TOTAL_CAP};
use crate::error::{Result, TransferError};
use crate::events::{TransferEvent, TransferEventSink};
use crate::fileset::{build_offer, FileSetBatcher};
use crate::inflight::{ChunkKey, InFlightTracker};
use crate::prepare::PreparedSet;
use crate::state::TransferState;

/// 源文件块读取（sender 读源数据；大文件测试用合成实现避免写 5GiB）。
pub trait ChunkReader: Send + Sync {
    /// 读 (file_id, offset, length) 的源字节。
    fn read_chunk(&self, file_id: &str, offset: u64, length: usize) -> Result<Vec<u8>>;
}

/// 带路径映射的文件读取器（file_id -> abs_path）。
pub struct MappedChunkReader {
    map: std::collections::HashMap<String, PathBuf>,
}
impl MappedChunkReader {
    pub fn from_prepared(set: &PreparedSet) -> Self {
        let map = set
            .files
            .iter()
            .map(|f| (f.file_id.clone(), f.abs_path.clone()))
            .collect();
        Self { map }
    }
}
impl ChunkReader for MappedChunkReader {
    fn read_chunk(&self, file_id: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let path = self
            .map
            .get(file_id)
            .ok_or_else(|| TransferError::Internal("unknown file_id".into()))?;
        let mut f = std::fs::File::open(path)?;
        f.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; length];
        let mut filled = 0;
        while filled < length {
            let n = f.read(&mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        buf.truncate(filled);
        tracing::trace!(file_id = %file_id, offset, length, filled, "read_chunk");
        Ok(buf)
    }
}

/// 合成读取器（按 seed 生成确定性字节，测大文件不写盘）。
pub struct SyntheticChunkReader {
    size: u64,
    seed: u64,
}
impl SyntheticChunkReader {
    #[allow(dead_code)]
    pub fn new(size: u64, seed: u64) -> Self {
        Self { size, seed }
    }
}
impl ChunkReader for SyntheticChunkReader {
    fn read_chunk(&self, _file_id: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; length];
        for i in 0..length {
            let pos = offset as usize + i;
            if pos as u64 >= self.size {
                out.truncate(i);
                break;
            }
            out[i] = ((self.seed ^ (pos as u64 * 2654435761)) & 0xff) as u8;
        }
        Ok(out)
    }
}

pub struct SenderInputs {
    pub control: Box<dyn crate::ControlChannel>,
    /// 数据流池（≥1）。单流 = vec![...]。
    pub data: Vec<Box<dyn crate::DataChannel>>,
    pub events: Box<dyn TransferEventSink>,
    pub config: TransferEngineConfig,
    pub prepared: PreparedSet,
    pub reader: Box<dyn ChunkReader>,
    pub transfer_id: String,
    /// 传输控制命令注入端（Engine::cancel/pause/resume 经此）。None = 不可控（旧测试）。
    pub cmd_rx: Option<tokio::sync::mpsc::Receiver<crate::control::TransferCommand>>,
}

pub async fn run_sender(mut inputs: SenderInputs) -> Result<()> {
    let tid = inputs.transfer_id.clone();
    let total_bytes = inputs.prepared.summary.total_bytes;

    inputs
        .events
        .emit(TransferEvent::Preparing {
            transfer_id: tid.clone(),
        })
        .await;

    // 1. offer
    let offer = build_offer(&tid, &inputs.prepared);
    inputs
        .control
        .send(ControlFrame {
            payload: Some(CPayload::TransferOffer(offer)),
        })
        .await?;
    inputs
        .events
        .emit(TransferEvent::Offered {
            transfer_id: tid.clone(),
            file_count: inputs.prepared.summary.file_count,
            total_bytes,
        })
        .await;
    inputs
        .events
        .emit(TransferEvent::StateChanged {
            transfer_id: tid.clone(),
            state: TransferState::Offered,
        })
        .await;

    // 2. FileSetBatch 流式
    let mut batcher = FileSetBatcher::new(tid.clone());
    for f in &inputs.prepared.files {
        batcher.push(f);
    }
    for d in &inputs.prepared.dirs {
        batcher.push_dir(d);
    }
    let frames = batcher.finish();
    for f in frames {
        inputs
            .control
            .send(ControlFrame {
                payload: Some(CPayload::FileSetBatch(f)),
            })
            .await?;
    }

    // 3. 等 accept
    let accept_frame = recv_control(&mut inputs.control).await?;
    let (resume, accepted) = match accept_frame.payload {
        Some(CPayload::TransferAccept(a)) => {
            use std::collections::HashMap;
            let r: HashMap<(String, u32), Vec<u8>> = a
                .resume
                .iter()
                .map(|bm| ((bm.file_id.clone(), bm.segment_id), bm.bitmask.clone()))
                .collect();
            (r, a.accept)
        }
        _ => return Err(TransferError::Protocol("expected TransferAccept".into())),
    };
    if !accepted {
        // decline —— receiver 拒绝，优雅终态。
        inputs
            .events
            .emit(TransferEvent::StateChanged {
                transfer_id: tid.clone(),
                state: TransferState::Cancelled,
            })
            .await;
        inputs
            .events
            .emit(TransferEvent::Cancelled {
                transfer_id: tid.clone(),
            })
            .await;
        return Ok(());
    }
    inputs
        .events
        .emit(TransferEvent::Accepted {
            transfer_id: tid.clone(),
            accept: true,
        })
        .await;
    inputs
        .events
        .emit(TransferEvent::StateChanged {
            transfer_id: tid.clone(),
            state: TransferState::Scheduled,
        })
        .await;

    // 4. 逐文件发送（inline 直发；分块文件走窗口式 RTO 重传）
    let chunk_size = inputs.config.default_chunk_size;
    let cs = chunk_size as u64;

    // 辅助结构：块工作条目
    struct ChunkWork_ {
        file_id: String,
        segment_id: u32,
        chunk_index: u64,
        offset: u64,
        length: usize,
        key: ChunkKey,
    }

    let mut work: Vec<ChunkWork_> = Vec::new();
    let mut work_map: HashMap<ChunkKey, usize> = HashMap::new();
    // 统计续传（跳过）的已验证块数，作为 verified_count 基线。
    let mut resumed_chunks: u64 = 0;

    for f in &inputs.prepared.files {
        if f.inline {
            let data = f.inline_data.clone().unwrap_or_default();
            let inline = privet_protocol::InlineFile {
                file_id: f.file_id.clone(),
                relative_path: f.relative_path.clone(),
                mtime_ms: f.mtime_ms,
                hash_type: "blake3".into(),
                hash_value: f.file_hash.clone(),
                data,
            };
            inputs.data[0]
                .send(
                    DataFrame {
                        payload: Some(DPayload::InlineFile(inline)),
                    },
                    None,
                )
                .await?;
            continue;
        }
        // 发 SegmentManifest（每段）+ 收集块工作
        for seg in &f.segments {
            let manifest = SegmentManifest {
                file_id: f.file_id.clone(),
                segment_id: seg.segment_id,
                chunk_hash_values: seg.chunk_hashes.clone(),
                hash_type: "blake3".into(),
                segment_hash_value: seg.blake3_root.clone(),
            };
            inputs
                .control
                .send(ControlFrame {
                    payload: Some(CPayload::SegmentManifest(manifest)),
                })
                .await?;
            let prev_bitmask = resume.get(&(f.file_id.clone(), seg.segment_id));
            let layout = privet_protocol::layout::derive_segment_layout(
                f.size,
                chunk_size,
                inputs.config.segment_max_chunks,
            );
            let seg_layout = layout
                .iter()
                .find(|l| l.segment_id == seg.segment_id)
                .ok_or_else(|| TransferError::Internal("layout mismatch".into()))?;
            for ci in 0..seg_layout.chunk_count as u64 {
                if let Some(bm) = prev_bitmask {
                    if is_bit_set(bm, ci as u32) {
                        resumed_chunks += 1; // 续传基线
                        continue;
                    }
                }
                let offset = seg_layout.offset + ci * cs;
                let len = cs.min(f.size.saturating_sub(offset)) as usize;
                let key = ChunkKey {
                    file_id: f.file_id.clone(),
                    segment_id: seg.segment_id,
                    chunk_index: ci,
                };
                work_map.insert(key.clone(), work.len());
                work.push(ChunkWork_ {
                    file_id: f.file_id.clone(),
                    segment_id: seg.segment_id,
                    chunk_index: ci,
                    offset,
                    length: len,
                    key,
                });
            }
        }
    }

    // 窗口式发送 + ChunkAck 消费 + RTO 重传
    inputs
        .events
        .emit(TransferEvent::StateChanged {
            transfer_id: tid.clone(),
            state: TransferState::Transferring,
        })
        .await;
    let mut tracker = InFlightTracker::new();
    let mut cursor = 0usize;
    let mut verified_count: u64 = resumed_chunks; // 续传基线，防重连后进度归零
    let mut paused = false;

    // 重连后立即以续传基线更新进度条。
    if resumed_chunks > 0 {
        let baseline_bytes = (resumed_chunks * chunk_size as u64).min(total_bytes);
        inputs
            .events
            .emit(TransferEvent::Progress {
                transfer_id: tid.clone(),
                verified_bytes: baseline_bytes,
                total_bytes,
            })
            .await;
        tracing::info!(
            resumed_chunks,
            baseline_bytes,
            "transfer resumed from bitmap"
        );
    }

    while cursor < work.len() || tracker.inflight_count() > 0 {
        if !paused {
            // 填窗口至 INFLIGHT_TOTAL_CAP
            while tracker.inflight_count() < INFLIGHT_TOTAL_CAP && cursor < work.len() {
                let w = &work[cursor];
                let chunk_data = inputs.reader.read_chunk(&w.file_id, w.offset, w.length)?;
                let header = ChunkHeader {
                    file_id: w.file_id.clone(),
                    segment_id: w.segment_id,
                    chunk_index: w.chunk_index,
                    offset: w.offset,
                    length: w.length as u64,
                };
                inputs.data[0]
                    .send(
                        DataFrame {
                            payload: Some(DPayload::ChunkHeader(header)),
                        },
                        Some(&chunk_data),
                    )
                    .await?;
                tracker.track(w.key.clone());
                cursor += 1;
            }
        } // !paused

        if tracker.inflight_count() == 0 {
            break;
        }

        let deadline = tracker.earliest_deadline(CHUNK_RETRANSMIT_RTO);
        tokio::select! {
            biased;
            // 本地注入命令（transfer control）
            cmd = async { match &mut inputs.cmd_rx { Some(rx) => rx.recv().await, None => None } }, if inputs.cmd_rx.is_some() => {
                match cmd {
                    Some(crate::control::TransferCommand::Cancel) => {
                        let _ = inputs.control.send(ControlFrame {
                            payload: Some(CPayload::Control(ControlMessage {
                                msg: Some(privet_protocol::control_message::Msg::Cancel(
                                    privet_protocol::Cancel { transfer_id: tid.clone(), reason: "user".into() }))
                            })),
                        }).await;
                        inputs.events.emit(TransferEvent::StateChanged {
                            transfer_id: tid.clone(), state: TransferState::Cancelled }).await;
                        inputs.events.emit(TransferEvent::Cancelled { transfer_id: tid.clone() }).await;
                        return Ok(());
                    }
                    Some(crate::control::TransferCommand::Pause) => {
                        paused = true;
                        let _ = inputs.control.send(ControlFrame {
                            payload: Some(CPayload::Control(ControlMessage {
                                msg: Some(privet_protocol::control_message::Msg::Pause(
                                    privet_protocol::Pause { transfer_id: tid.clone() }))
                            })),
                        }).await;
                        inputs.events.emit(TransferEvent::Paused { transfer_id: tid.clone(), reason: crate::state::PausedReason::User }).await;
                        inputs.events.emit(TransferEvent::StateChanged { transfer_id: tid.clone(), state: TransferState::Paused { reason: crate::state::PausedReason::User } }).await;
                    }
                    Some(crate::control::TransferCommand::Resume) => {
                        paused = false;
                        let _ = inputs.control.send(ControlFrame {
                            payload: Some(CPayload::Control(ControlMessage {
                                msg: Some(privet_protocol::control_message::Msg::Resume(
                                    privet_protocol::Resume { transfer_id: tid.clone() }))
                            })),
                        }).await;
                        inputs.events.emit(TransferEvent::Resumed { transfer_id: tid.clone() }).await;
                    }
                    None => {}
                }
            }
            // 对端控制帧（原逻辑）
            result = inputs.control.recv() => {
                match result {
                    Ok(frame) => match frame.payload {
                        Some(CPayload::ChunkAck(a)) => {
                            let n = tracker.on_ack(&a.file_id, a.segment_id, &a.chunk_indices);
                            verified_count += n as u64;
                            // 记录每一条收到的 ack（含空 ack n=0），
                            // 区分“ack 到达但无已验证块”（对端未处理 manifest / 旧二进制）
                            // 与“完全无 ack 到达”（链路丢包）。索引/计数非敏感。
                            tracing::debug!(
                                file_id = %a.file_id,
                                segment_id = a.segment_id,
                                acked_in_frame = a.chunk_indices.len(),
                                newly_verified = n,
                                total_verified = verified_count,
                                "chunk ack received"
                            );
                            if n > 0 {
                                let verified_bytes = verified_count * chunk_size as u64;
                                inputs.events.emit(TransferEvent::Progress {
                                    transfer_id: tid.clone(),
                                    verified_bytes: verified_bytes.min(total_bytes),
                                    total_bytes,
                                }).await;
                            }
                        }
                        Some(CPayload::Control(ControlMessage {
                            msg: Some(privet_protocol::control_message::Msg::Cancel(_c)),
                        })) => {
                            inputs.events.emit(TransferEvent::StateChanged {
                                transfer_id: tid.clone(), state: TransferState::Cancelled,
                            }).await;
                            inputs.events.emit(TransferEvent::Cancelled { transfer_id: tid.clone() }).await;
                            return Ok(());
                        }
                        Some(CPayload::Control(ControlMessage {
                            msg: Some(privet_protocol::control_message::Msg::Pause(_)),
                        })) => {
                            paused = true;
                            inputs.events.emit(TransferEvent::Paused { transfer_id: tid.clone(), reason: crate::state::PausedReason::User }).await;
                            inputs.events.emit(TransferEvent::StateChanged { transfer_id: tid.clone(), state: TransferState::Paused { reason: crate::state::PausedReason::User } }).await;
                        }
                        Some(CPayload::Control(ControlMessage {
                            msg: Some(privet_protocol::control_message::Msg::Resume(_)),
                        })) => {
                            paused = false;
                            inputs.events.emit(TransferEvent::Resumed { transfer_id: tid.clone() }).await;
                        }
                        _ => {}
                    },
                    Err(_) => return Err(TransferError::Transport("control recv".into())),
                }
            }
            _ = tokio::time::sleep_until(deadline.unwrap_or(
                tokio::time::Instant::now() + CHUNK_RETRANSMIT_RTO,
            )) => {
                // 选择性重传--仅重传“落后 ack 前沿”或“首 ack 前全部超时”的块。
                // 旧 `rto_expired` 在慢链路下会把全部 inflight 块（接收方尚未处理、仍在前沿
                // 之前）一律判超时 -> 洪泛重传 -> ChunkCorrupt/连接死。
                let expired = tracker.rto_expired_selective(CHUNK_RETRANSMIT_RTO);
                for key in &expired {
                    if tracker.retries(key) >= CHUNK_RETRANSMIT_MAX {
                        tracing::error!(
                            file_id = %key.file_id, segment_id = key.segment_id,
                            chunk_index = key.chunk_index,
                            retries = CHUNK_RETRANSMIT_MAX,
                            "chunk corrupt: retransmit exhausted (compare prepare vs send read)"
                        );
                        let _ = inputs
                            .control
                            .send(ControlFrame {
                                payload: Some(CPayload::Control(ControlMessage {
                                    msg: Some(
                                        privet_protocol::control_message::Msg::Cancel(
                                            privet_protocol::Cancel {
                                                transfer_id: tid.clone(),
                                                reason: "chunk_corrupt".into(),
                                            },
                                        ),
                                    ),
                                })),
                            })
                            .await;
                        return Err(TransferError::ChunkCorrupt);
                    }
                    if let Some(&idx) = work_map.get(key) {
                        let w = &work[idx];
                        let chunk_data = inputs.reader.read_chunk(&w.file_id, w.offset, w.length)?;
                        tracing::debug!(
                            file_id = %w.file_id, segment_id = w.segment_id,
                            chunk_index = w.chunk_index, offset = w.offset, length = w.length,
                            retry = tracker.retries(key),
                            "chunk retransmit (RTO)"
                        );
                        let header = ChunkHeader {
                            file_id: w.file_id.clone(),
                            segment_id: w.segment_id,
                            chunk_index: w.chunk_index,
                            offset: w.offset,
                            length: w.length as u64,
                        };
                        inputs
                            .data[0]
                            .send(
                                DataFrame {
                                    payload: Some(DPayload::ChunkHeader(header)),
                                },
                                Some(&chunk_data),
                            )
                            .await?;
                        tracker.record_retry(key);
                    }
                }
            }
        }
    }

    inputs
        .events
        .emit(TransferEvent::StateChanged {
            transfer_id: tid.clone(),
            state: TransferState::SendingDone,
        })
        .await;
    inputs
        .events
        .emit(TransferEvent::SendingDone {
            transfer_id: tid.clone(),
        })
        .await;

    // 5. TransferComplete
    inputs
        .control
        .send(ControlFrame {
            payload: Some(CPayload::Control(ControlMessage {
                msg: Some(privet_protocol::control_message::Msg::Complete(
                    privet_protocol::TransferComplete {
                        transfer_id: tid.clone(),
                    },
                )),
            })),
        })
        .await?;

    // 6. 等 TransferVerified/Cancel（跳过期间可能插入的 ChunkAck）
    let verified = loop {
        let frame = recv_control(&mut inputs.control).await?;
        match frame.payload {
            Some(CPayload::ChunkAck(_)) => continue, // 过渡期跳过
            Some(CPayload::Control(ControlMessage {
                msg: Some(privet_protocol::control_message::Msg::Verified(v)),
            })) => {
                break v;
            }
            Some(CPayload::Control(ControlMessage {
                msg: Some(privet_protocol::control_message::Msg::Cancel(_c)),
            })) => {
                inputs
                    .events
                    .emit(TransferEvent::StateChanged {
                        transfer_id: tid.clone(),
                        state: TransferState::Cancelled,
                    })
                    .await;
                inputs
                    .events
                    .emit(TransferEvent::Cancelled { transfer_id: tid })
                    .await;
                return Ok(());
            }
            _ => {
                return Err(TransferError::Protocol(
                    "expected TransferVerified/Cancel".into(),
                ))
            }
        }
    };
    inputs
        .events
        .emit(TransferEvent::Verified {
            transfer_id: tid.clone(),
            ok: verified.ok,
        })
        .await;
    inputs
        .events
        .emit(TransferEvent::StateChanged {
            transfer_id: tid.clone(),
            state: TransferState::Verified { ok: verified.ok },
        })
        .await;
    if verified.ok {
        inputs
            .events
            .emit(TransferEvent::StateChanged {
                transfer_id: tid.clone(),
                state: TransferState::Completed,
            })
            .await;
        inputs
            .events
            .emit(TransferEvent::Completed { transfer_id: tid })
            .await;
        Ok(())
    } else {
        Err(TransferError::VerifyFailed(verified.error))
    }
}

fn is_bit_set(bitmask: &[u8], idx: u32) -> bool {
    let byte = (idx / 8) as usize;
    if byte >= bitmask.len() {
        return false;
    }
    bitmask[byte] & (1 << (idx % 8)) != 0
}

async fn recv_control(c: &mut Box<dyn crate::ControlChannel>) -> Result<ControlFrame> {
    tokio::time::timeout(std::time::Duration::from_secs(10), c.recv())
        .await
        .map_err(|_| TransferError::Transport("control recv timeout".into()))?
}
