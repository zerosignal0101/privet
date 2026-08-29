
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
use crate::state::{TransferFailed, TransferState};

pub trait ChunkReader: Send + Sync {
    fn read_chunk(&self, file_id: &str, offset: u64, length: usize) -> Result<Vec<u8>>;
}

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
    pub data: Vec<Box<dyn crate::DataChannel>>,
    pub events: Box<dyn TransferEventSink>,
    pub config: TransferEngineConfig,
    pub prepared: PreparedSet,
    pub reader: Box<dyn ChunkReader>,
    pub transfer_id: String,
    pub cmd_rx: Option<SharedCommandReceiver>,
}

pub type SharedCommandReceiver = std::sync::Arc<
    tokio::sync::Mutex<tokio::sync::mpsc::Receiver<crate::control::TransferCommand>>,
>;

async fn recv_command(
    receiver: Option<SharedCommandReceiver>,
) -> Option<crate::control::TransferCommand> {
    match receiver {
        Some(receiver) => receiver.lock().await.recv().await,
        None => None,
    }
}

/// Sends a data frame, translating a peer STOP_SENDING (the receiver cancelled
/// mid-transfer and dropped its read side) into the same Cancelled outcome as a
/// Cancel control frame: emit the terminal event and return `Cancelled` rather
/// than surfacing an abort the reconnect loop would otherwise retry. A receiver
/// cancel must never make the sender reconnect and re-send the whole transfer.
async fn send_data_frame(
    data: &mut Box<dyn crate::DataChannel>,
    events: &mut Box<dyn TransferEventSink>,
    tid: &str,
    frame: DataFrame,
    raw: Option<&[u8]>,
) -> Result<()> {
    if let Err(e) = data.send(frame, raw).await {
        if matches!(&e, TransferError::Aborted(_)) {
            events
                .emit(TransferEvent::StateChanged {
                    transfer_id: tid.to_string(),
                    state: TransferState::Cancelled,
                })
                .await;
            events
                .emit(TransferEvent::Cancelled {
                    transfer_id: tid.to_string(),
                })
                .await;
            return Err(TransferError::Cancelled("peer".into()));
        }
        return Err(e);
    }
    Ok(())
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

    // The receiver has its own 30s decision window; if it has not answered by
    // then, treat a silent connection as a decline so the transfer terminates
    // instead of hanging forever with no terminal event for the GUI. The tile
    // offers Cancel during this negotiation, so a user command must interrupt
    // the wait as well — before this the command channel was never polled here.
    let (resume, accepted) = loop {
        tokio::select! {
            biased;
            cmd = recv_command(inputs.cmd_rx.clone()), if inputs.cmd_rx.is_some() => {
                match cmd {
                    Some(crate::control::TransferCommand::Cancel) => {
                        let _ = inputs.control.send(ControlFrame {
                            payload: Some(CPayload::Control(ControlMessage {
                                msg: Some(privet_protocol::control_message::Msg::Cancel(
                                    privet_protocol::Cancel {
                                        transfer_id: tid.clone(),
                                        reason: "user".into(),
                                    },
                                )),
                            })),
                        }).await;
                        inputs.events.emit(TransferEvent::StateChanged {
                            transfer_id: tid.clone(), state: TransferState::Cancelled }).await;
                        inputs.events.emit(TransferEvent::Cancelled { transfer_id: tid.clone() }).await;
                        // Not a completion: the core relies on a Cancelled error
                        // here to skip recording this send as 'completed'.
                        return Err(TransferError::Cancelled("user".into()));
                    }
                    // Pause/resume have no meaning before the receiver accepts;
                    // ignore them and keep waiting for the decision.
                    Some(_) => continue,
                    // Channel closed means the registry dropped us; don't spin.
                    None => return Err(TransferError::Protocol("command channel closed".into())),
                }
            }
            result = tokio::time::timeout(
                std::time::Duration::from_secs(35),
                recv_control(&mut inputs.control),
            ) => {
                match result {
                    Ok(Ok(frame)) => match frame.payload {
                        Some(CPayload::TransferAccept(a)) => {
                            if a.accept {
                                let r: HashMap<(String, u32), Vec<u8>> = a
                                    .resume
                                    .iter()
                                    .map(|bm| {
                                        ((bm.file_id.clone(), bm.segment_id), bm.bitmask.clone())
                                    })
                                    .collect();
                                break (r, true);
                            }
                            // A decline with no reason (or the receiver's own
                            // "declined") is a user decision — the transfer is
                            // left resumable. Any other reason means the peer
                            // refused us because it no longer trusts us (it
                            // revoked or forgot us, or our key mismatches).
                            // That is terminal: keep retrying would never
                            // succeed, so fail fast and mark the history row.
                            let reason = a.reason.clone();
                            if reason.is_empty() || reason == "declined" {
                                break (HashMap::new(), false);
                            }
                            inputs
                                .events
                                .emit(TransferEvent::StateChanged {
                                    transfer_id: tid.clone(),
                                    state: TransferState::Failed(TransferFailed {
                                        error_code: "rejected",
                                        error_message: reason.clone(),
                                        retryable: false,
                                        part_kept: false,
                                    }),
                                })
                                .await;
                            inputs
                                .events
                                .emit(TransferEvent::Failed {
                                    transfer_id: tid.clone(),
                                    error_code: "rejected".into(),
                                    retryable: false,
                                    part_kept: false,
                                })
                                .await;
                            return Err(TransferError::Rejected(reason));
                        }
                        _ => return Err(TransferError::Protocol("expected TransferAccept".into())),
                    },
                    // Transport failure: let the caller's reconnect loop decide.
                    Ok(Err(e)) => return Err(e),
                    // No answer within the window (the receiver's reject was
                    // lost, or it never made a decision): declined.
                    Err(_) => break (HashMap::new(), false),
                }
            }
        };
    };
    if !accepted {
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
        // A silent connection treated as a decline is not a completion either;
        // leave the history row 'partial' instead of 'completed'.
        return Err(TransferError::Declined("no_answer".into()));
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

    let chunk_size = inputs.config.default_chunk_size;
    let cs = chunk_size as u64;

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
            send_data_frame(
                &mut inputs.data[0],
                &mut inputs.events,
                &tid,
                DataFrame {
                    payload: Some(DPayload::InlineFile(inline)),
                },
                None,
            )
            .await?;
            continue;
        }
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
                        resumed_chunks += 1;
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

    inputs
        .events
        .emit(TransferEvent::StateChanged {
            transfer_id: tid.clone(),
            state: TransferState::Transferring,
        })
        .await;
    let mut tracker = InFlightTracker::new();
    let mut cursor = 0usize;
    let mut verified_count: u64 = resumed_chunks;
    let mut paused = false;

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
                send_data_frame(
                    &mut inputs.data[0],
                    &mut inputs.events,
                    &tid,
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
            cmd = recv_command(inputs.cmd_rx.clone()), if inputs.cmd_rx.is_some() => {
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
                        return Err(TransferError::Cancelled("user".into()));
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
            result = inputs.control.recv() => {
                match result {
                    Ok(frame) => match frame.payload {
                        Some(CPayload::ChunkAck(a)) => {
                            let n = tracker.on_ack(&a.file_id, a.segment_id, &a.chunk_indices);
                            verified_count += n as u64;
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
                            return Err(TransferError::Cancelled("peer".into()));
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
                        send_data_frame(
                            &mut inputs.data[0],
                            &mut inputs.events,
                            &tid,
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

    let verified = loop {
        let frame = recv_control(&mut inputs.control).await?;
        match frame.payload {
            Some(CPayload::ChunkAck(_)) => continue,
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
                return Err(TransferError::Cancelled("peer".into()));
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
