
use std::collections::HashMap;

use privet_protocol::{
    control_frame::Payload as CPayload, data_frame::Payload as DPayload, ChunkAck, ControlFrame,
    ControlMessage, DataFrame, FileEntry, SegmentManifest, TransferAccept, TransferVerified,
};

use crate::bitmask::VerifiedBitmask;
use crate::config::TransferEngineConfig;
use crate::constants::CHUNK_ACK_INTERVAL;
use crate::error::{Result, TransferError};
use crate::events::{TransferEvent, TransferEventSink};
use crate::fileset::FileSetAccumulator;
use crate::manifest_store::{ArrivalVerdict, PendingChunk, ReceiverManifestStore};
use crate::part_store::{FinalizeOutcome, PartStore};
use crate::state::{TransferFailed, TransferState};

/// A finalized received file, reported to the core so it can record history.
pub struct ReceivedFileRecord {
    pub file_id: String,
    pub relative_path: String,
    pub size: u64,
    pub hash_type: Option<String>,
    pub hash_value: Option<String>,
    pub status: String,
}

/// Optional hooks the core supplies so the receiver can persist transfer
/// history. The receiver never touches the database; it only reports.
pub struct ReceiveHistory {
    /// Called once the offer is known: (transfer_id, root_name, file_count,
    /// total_bytes). The core inserts the partial history row here.
    pub on_offer: Box<dyn Fn(&str, Option<String>, u64, u64) + Send + Sync>,
    /// Called once the sender's file manifest is fully known (after the last
    /// FileSetBatch), before data flows: (transfer_id, Vec<FileEntry>). The
    /// core persists the per-file rows here so a partial/interrupted receive
    /// still lists its files, mirroring the sender's insert_send_files.
    pub on_fileset: Box<dyn Fn(&str, Vec<privet_protocol::FileEntry>) + Send + Sync>,
    /// Called right before the terminal event once all files are finalized.
    pub on_complete: Box<dyn Fn(&str, Vec<ReceivedFileRecord>) + Send + Sync>,
}

pub struct ReceiverInputs {
    pub control: Box<dyn crate::ControlChannel>,
    pub data: Vec<Box<dyn crate::DataChannel>>,
    pub store: Box<dyn PartStore>,
    pub events: Box<dyn TransferEventSink>,
    pub config: TransferEngineConfig,
    pub accept_policy: crate::control::AcceptPolicy,
    pub registry: Option<std::sync::Arc<crate::control::TransferRegistry>>,
    pub history: Option<ReceiveHistory>,
}

#[derive(Default)]
struct FileRecvState {
    entry: Option<FileEntry>,
    inline_done: bool,
    bitmasks: HashMap<u32, VerifiedBitmask>,
    verified_count: HashMap<u32, u32>,
    last_acked_count: HashMap<u32, u32>,
    meta_inited: bool,
}

/// Applies a user command (cancel/pause/resume) read from the transfer registry.
/// Returns `true` when the transfer was cancelled and the receiver must return,
/// `false` after a pause/resume (the loop keeps running).
async fn apply_command(
    inputs: &mut ReceiverInputs,
    tid: &str,
    cmd: crate::control::TransferCommand,
) -> Result<bool> {
    match cmd {
        crate::control::TransferCommand::Cancel => {
            let _ = inputs
                .control
                .send(ControlFrame {
                    payload: Some(CPayload::Control(ControlMessage {
                        msg: Some(privet_protocol::control_message::Msg::Cancel(
                            privet_protocol::Cancel {
                                transfer_id: tid.to_string(),
                                reason: "user".into(),
                            },
                        )),
                    })),
                })
                .await;
            if let Some(r) = &inputs.registry {
                r.unregister(tid);
            }
            inputs
                .events
                .emit(TransferEvent::StateChanged {
                    transfer_id: tid.to_string(),
                    state: TransferState::Cancelled,
                })
                .await;
            inputs
                .events
                .emit(TransferEvent::Cancelled {
                    transfer_id: tid.to_string(),
                })
                .await;
            Ok(true)
        }
        crate::control::TransferCommand::Pause => {
            let _ = inputs
                .control
                .send(ControlFrame {
                    payload: Some(CPayload::Control(ControlMessage {
                        msg: Some(privet_protocol::control_message::Msg::Pause(
                            privet_protocol::Pause {
                                transfer_id: tid.to_string(),
                            },
                        )),
                    })),
                })
                .await;
            inputs
                .events
                .emit(TransferEvent::Paused {
                    transfer_id: tid.to_string(),
                    reason: crate::state::PausedReason::User,
                })
                .await;
            inputs
                .events
                .emit(TransferEvent::StateChanged {
                    transfer_id: tid.to_string(),
                    state: TransferState::Paused {
                        reason: crate::state::PausedReason::User,
                    },
                })
                .await;
            Ok(false)
        }
        crate::control::TransferCommand::Resume => {
            let _ = inputs
                .control
                .send(ControlFrame {
                    payload: Some(CPayload::Control(ControlMessage {
                        msg: Some(privet_protocol::control_message::Msg::Resume(
                            privet_protocol::Resume {
                                transfer_id: tid.to_string(),
                            },
                        )),
                    })),
                })
                .await;
            inputs
                .events
                .emit(TransferEvent::Resumed {
                    transfer_id: tid.to_string(),
                })
                .await;
            Ok(false)
        }
    }
}

/// Non-blocking poll of the transfer's command channel (cancel/pause/resume).
/// Returns `None` when no command is pending or the channel is not wired.
async fn poll_command(
    rx: Option<&mut tokio::sync::mpsc::Receiver<crate::control::TransferCommand>>,
) -> Option<crate::control::TransferCommand> {
    match rx {
        Some(rx) => tokio::time::timeout(std::time::Duration::from_millis(0), rx.recv())
            .await
            .ok()
            .flatten(),
        None => None,
    }
}

/// Outcome of draining control after a mid-transfer data-stream abort.
#[derive(PartialEq)]
enum PeerDataStop {
    /// A terminal Cancelled/Failed event was emitted; the receiver must return.
    Terminated,
    /// The transfer actually finished (a Complete frame is pending); finalize.
    Finalize,
}

/// Handles a data-stream end/error while files are still incomplete — how a
/// peer cancel (the sender writes a Cancel control frame, then ends the data
/// stream) or a vanished peer shows up to the receiver. The receiver used to
/// return on the data error before reading the Cancel frame, so a sender
/// cancel produced NO terminal event: the GUI tile froze at its last progress
/// and History never refreshed to show the 'partial' row.
///
/// A pending Complete means the transfer actually finished and the caller
/// should finalize; every other case terminates the transfer (Cancelled, or
/// Failed for a chunk-corrupt stop) with a real event and unregisters.
async fn drain_peer_data_abort(inputs: &mut ReceiverInputs, tid: &str) -> Result<PeerDataStop> {
    // The Cancel frame the peer wrote is on the control stream already (it was
    // written before the data stream ended); give the wire a bounded window to
    // deliver it rather than racing the FIN.
    let pending = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        inputs.control.recv(),
    )
    .await;
    match pending {
        Ok(Ok(frame)) => match frame.payload {
            Some(CPayload::Control(ControlMessage {
                msg: Some(privet_protocol::control_message::Msg::Cancel(c)),
            })) if c.reason == "chunk_corrupt" => {
                inputs
                    .events
                    .emit(TransferEvent::StateChanged {
                        transfer_id: tid.to_string(),
                        state: TransferState::Failed(TransferFailed {
                            error_code: "chunk_corrupt",
                            error_message: "retryable".into(),
                            retryable: true,
                            part_kept: true,
                        }),
                    })
                    .await;
                inputs
                    .events
                    .emit(TransferEvent::Failed {
                        transfer_id: tid.to_string(),
                        error_code: "chunk_corrupt".into(),
                        retryable: true,
                        part_kept: true,
                    })
                    .await;
                if let Some(r) = &inputs.registry {
                    r.unregister(tid);
                }
                Ok(PeerDataStop::Terminated)
            }
            Some(CPayload::Control(ControlMessage {
                msg: Some(privet_protocol::control_message::Msg::Cancel(_)),
            })) => {
                inputs
                    .events
                    .emit(TransferEvent::StateChanged {
                        transfer_id: tid.to_string(),
                        state: TransferState::Cancelled,
                    })
                    .await;
                inputs
                    .events
                    .emit(TransferEvent::Cancelled {
                        transfer_id: tid.to_string(),
                    })
                    .await;
                if let Some(r) = &inputs.registry {
                    r.unregister(tid);
                }
                Ok(PeerDataStop::Terminated)
            }
            Some(CPayload::Control(ControlMessage {
                msg: Some(privet_protocol::control_message::Msg::Complete(_)),
            })) => Ok(PeerDataStop::Finalize),
            // A stray frame while the data stream stopped: treat the peer as
            // stopped rather than guessing.
            _ => {
                inputs
                    .events
                    .emit(TransferEvent::StateChanged {
                        transfer_id: tid.to_string(),
                        state: TransferState::Cancelled,
                    })
                    .await;
                inputs
                    .events
                    .emit(TransferEvent::Cancelled {
                        transfer_id: tid.to_string(),
                    })
                    .await;
                if let Some(r) = &inputs.registry {
                    r.unregister(tid);
                }
                Ok(PeerDataStop::Terminated)
            }
        },
        // No control frame within the window: the peer vanished. Emit
        // Cancelled (the history row stays 'partial', matching the peer) so the
        // GUI tile resolves instead of freezing.
        Ok(Err(_)) | Err(_) => {
            inputs
                .events
                .emit(TransferEvent::StateChanged {
                    transfer_id: tid.to_string(),
                    state: TransferState::Cancelled,
                })
                .await;
            inputs
                .events
                .emit(TransferEvent::Cancelled {
                    transfer_id: tid.to_string(),
                })
                .await;
            if let Some(r) = &inputs.registry {
                r.unregister(tid);
            }
            Ok(PeerDataStop::Terminated)
        }
    }
}

pub async fn run_receiver(mut inputs: ReceiverInputs) -> Result<()> {
    let mut manifests = ReceiverManifestStore::new();
    let mut files: HashMap<String, FileRecvState> = HashMap::new();
    let mut dir_entries: Vec<privet_protocol::DirEntry> = Vec::new();
    let mut fileset_done = false;

    let offer = recv_control(&mut inputs.control).await?;
    let (tid, summary) = match offer.payload {
        Some(CPayload::TransferOffer(o)) => {
            let s = o.summary.unwrap_or_default();
            (o.transfer_id, s)
        }
        _ => return Err(TransferError::Protocol("expected TransferOffer".into())),
    };
    let root_name = if summary.root_name.is_empty() {
        None
    } else {
        Some(summary.root_name.clone())
    };
    // Record the (partial) history row before publishing the offer event so the
    // transfer is visible in History as soon as it is offered.
    if let Some(h) = &inputs.history {
        (h.on_offer)(&tid, root_name.clone(), summary.file_count, summary.total_bytes);
    }
    // Register before publishing the offer event so an IPC client can respond immediately.
    let decision_rx = match &inputs.accept_policy {
        crate::control::AcceptPolicy::Resolver(resolver) => {
            Some(resolver.await_decision(&tid))
        }
        crate::control::AcceptPolicy::AutoAccept => None,
    };
    tracing::info!(transfer_id = %tid, file_count = summary.file_count, total_bytes = summary.total_bytes, "incoming transfer offered (receiver-side)");
    inputs
        .events
        .emit(TransferEvent::Offered {
            transfer_id: tid.clone(),
            file_count: summary.file_count,
            total_bytes: summary.total_bytes,
        })
        .await;
    inputs
        .events
        .emit(TransferEvent::StateChanged {
            transfer_id: tid.clone(),
            state: TransferState::Offered,
        })
        .await;

    let mut cmd_rx = inputs.registry.as_ref().map(|r| r.register(&tid));
    let accepted = match &inputs.accept_policy {
        crate::control::AcceptPolicy::AutoAccept => true,
        crate::control::AcceptPolicy::Resolver(_) => {
            match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                decision_rx.expect("resolver decision receiver"),
            )
            .await
            {
                Ok(Ok(d)) => d,
                _ => false,
            }
        }
    };
    tracing::info!(transfer_id = %tid, accepted, "offer decision");
    let resume = if accepted {
        build_resume_bitmasks(&inputs.config.save_dir, &tid)?
    } else {
        Vec::new()
    };
    let resume_saved = resume.clone();
    let send_accept = TransferAccept {
        accept: accepted,
        reason: if accepted {
            String::new()
        } else {
            "declined".into()
        },
        resume,
    };
    let send_accept_result = inputs
        .control
        .send(ControlFrame {
            payload: Some(CPayload::TransferAccept(send_accept)),
        })
        .await;
    if !accepted {
        if let Some(r) = &inputs.registry {
            r.unregister(&tid);
        }
        if let crate::control::AcceptPolicy::Resolver(res) = &inputs.accept_policy {
            res.cancel(&tid);
        }
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
        // The reject frame is best-effort: if the peer is already gone, the
        // local terminal event above still must reach the UI. Only surface
        // non-transport errors.
        return send_accept_result.map(|_| ()).or_else(|e| match e {
            TransferError::Transport(_) | TransferError::TransportLost => Ok(()),
            e => Err(e),
        });
    }
    send_accept_result?;
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

    let mut acc = FileSetAccumulator::new(&summary);
    while !fileset_done {
        let frame = recv_control(&mut inputs.control).await?;
        match frame.payload {
            Some(CPayload::FileSetBatch(b)) => {
                for e in &b.files {
                    files.entry(e.file_id.clone()).or_default().entry = Some(e.clone());
                }
                dir_entries.extend_from_slice(&b.dirs);
                let is_last = b.is_last;
                acc.ingest(&b)?;
                if is_last {
                    fileset_done = true;
                }
            }
            Some(CPayload::SegmentManifest(m)) => {
                on_manifest(&mut manifests, &mut files, &*inputs.store, &tid, &m).await?;
            }
            Some(CPayload::Control(ControlMessage {
                msg: Some(privet_protocol::control_message::Msg::Cancel(c)),
            })) => {
                if c.reason == "chunk_corrupt" {
                    inputs
                        .events
                        .emit(TransferEvent::StateChanged {
                            transfer_id: tid.clone(),
                            state: TransferState::Failed(TransferFailed {
                                error_code: "chunk_corrupt",
                                error_message: "retryable".into(),
                                retryable: true,
                                part_kept: true,
                            }),
                        })
                        .await;
                    inputs
                        .events
                        .emit(TransferEvent::Failed {
                            transfer_id: tid.clone(),
                            error_code: "chunk_corrupt".into(),
                            retryable: true,
                            part_kept: true,
                        })
                        .await;
                    return Ok(());
                }
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
            Some(CPayload::Control(ControlMessage {
                msg: Some(privet_protocol::control_message::Msg::Pause(_)),
            })) => {
                inputs
                    .events
                    .emit(TransferEvent::Paused {
                        transfer_id: tid.clone(),
                        reason: crate::state::PausedReason::User,
                    })
                    .await;
                inputs
                    .events
                    .emit(TransferEvent::StateChanged {
                        transfer_id: tid.clone(),
                        state: TransferState::Paused {
                            reason: crate::state::PausedReason::User,
                        },
                    })
                    .await;
            }
            Some(CPayload::Control(ControlMessage {
                msg: Some(privet_protocol::control_message::Msg::Resume(_)),
            })) => {
                inputs
                    .events
                    .emit(TransferEvent::Resumed {
                        transfer_id: tid.clone(),
                    })
                    .await;
            }
            _ => {}
        }
    }

    // The last FileSetBatch was seen, so the full file manifest is known and
    // data is about to flow. Persist the per-file rows now (status "failed"
    // sentinel) so a partial/interrupted receive still lists its files in
    // history; complete_history upgrades them once the transfer finishes.
    if let Some(h) = &inputs.history {
        let entries: Vec<privet_protocol::FileEntry> = files
            .values()
            .filter_map(|st| st.entry.clone())
            .collect();
        (h.on_fileset)(&tid, entries);
    }

    for bm in &resume_saved {
        if let Some(st) = files.get_mut(&bm.file_id) {
            let seg_id = bm.segment_id;
            let n = bm.bitmask.len() as u32 * 8;
            if n == 0 {
                continue;
            }
            let vb = VerifiedBitmask::from_bytes(&bm.bitmask, n);
            let set_count = vb.count_set();
            if set_count > 0 {
                st.bitmasks.insert(seg_id, vb);
                *st.verified_count.entry(seg_id).or_insert(0) += set_count;
            }
        }
    }

    let mut last_flush = std::time::Instant::now();
    let mut last_progress_log = std::time::Instant::now();
    // Whether any progress report with verified_bytes > 0 has been emitted yet.
    // The first report is never throttled: a fast receive can verify every byte
    // and reach the terminal state inside the 1s window, which used to leave the
    // GUI tile at 0% forever. See emit_progress_if_due.
    let mut progress_reported = false;
    loop {
        let data_recv =
            tokio::time::timeout(crate::constants::CHUNK_ACK_TIME_BASE, inputs.data[0].recv())
                .await;
        match data_recv {
            Ok(Ok((frame, raw))) => {
                handle_data(
                    &mut manifests,
                    &mut files,
                    &*inputs.store,
                    &mut inputs.control,
                    &tid,
                    &root_name,
                    &inputs.config,
                    &*inputs.events,
                    frame,
                    raw,
                )
                .await?;
                // Drain any pending user command (cancel/pause/resume) while
                // data flows. Before, only the idle-timeout branch polled the
                // command channel, so cancel could not interrupt an active
                // transfer on the receiving side.
                if let Some(cmd) = poll_command(cmd_rx.as_mut()).await {
                    if apply_command(&mut inputs, &tid, cmd).await? {
                        return Ok(());
                    }
                }
                emit_progress_if_due(
                    &files,
                    &inputs.config,
                    &*inputs.events,
                    &tid,
                    summary.total_bytes,
                    &mut last_progress_log,
                    &mut progress_reported,
                    false,
                )
                .await;
            }
            Ok(Err(_)) => {
                // A mid-transfer data-stream end/error: the peer cancelled (it
                // writes a Cancel frame, then ends the data stream) or vanished.
                // The receiver used to return on this error without reading the
                // frame — no terminal event, a frozen tile, stale History.
                // Drain control and terminate with the matching event; only a
                // pending Complete finalizes normally below.
                if drain_peer_data_abort(&mut inputs, &tid).await? != PeerDataStop::Finalize {
                    return Ok(());
                }
                break;
            }
            Err(_) => {
                flush_pending_chunk_acks(&mut files, &mut inputs.control).await?;
                if let Some(cmd) = poll_command(cmd_rx.as_mut()).await {
                    if apply_command(&mut inputs, &tid, cmd).await? {
                        return Ok(());
                    }
                }
                if let Some(frame) = try_recv_control(&mut inputs.control).await? {
                    match frame.payload {
                        Some(CPayload::SegmentManifest(m)) => {
                            on_manifest(&mut manifests, &mut files, &*inputs.store, &tid, &m)
                                .await?;
                            // on_manifest can verify a batch of chunks that
                            // arrived before their manifest, so progress must
                            // be reconsidered on the control path too.
                            emit_progress_if_due(
                                &files,
                                &inputs.config,
                                &*inputs.events,
                                &tid,
                                summary.total_bytes,
                                &mut last_progress_log,
                                &mut progress_reported,
                                false,
                            )
                            .await;
                        }
                        Some(CPayload::Control(ControlMessage {
                            msg: Some(privet_protocol::control_message::Msg::Complete(_)),
                        })) => {
                            break;
                        }
                        Some(CPayload::Control(ControlMessage {
                            msg: Some(privet_protocol::control_message::Msg::Cancel(c)),
                        })) => {
                            if c.reason == "chunk_corrupt" {
                                inputs
                                    .events
                                    .emit(TransferEvent::StateChanged {
                                        transfer_id: tid.clone(),
                                        state: TransferState::Failed(TransferFailed {
                                            error_code: "chunk_corrupt",
                                            error_message: "retryable".into(),
                                            retryable: true,
                                            part_kept: true,
                                        }),
                                    })
                                    .await;
                                inputs
                                    .events
                                    .emit(TransferEvent::Failed {
                                        transfer_id: tid.clone(),
                                        error_code: "chunk_corrupt".into(),
                                        retryable: true,
                                        part_kept: true,
                                    })
                                    .await;
                                return Ok(());
                            }
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
                        Some(CPayload::Control(ControlMessage {
                            msg: Some(privet_protocol::control_message::Msg::Pause(_)),
                        })) => {
                            inputs
                                .events
                                .emit(TransferEvent::Paused {
                                    transfer_id: tid.clone(),
                                    reason: crate::state::PausedReason::User,
                                })
                                .await;
                            inputs
                                .events
                                .emit(TransferEvent::StateChanged {
                                    transfer_id: tid.clone(),
                                    state: TransferState::Paused {
                                        reason: crate::state::PausedReason::User,
                                    },
                                })
                                .await;
                        }
                        Some(CPayload::Control(ControlMessage {
                            msg: Some(privet_protocol::control_message::Msg::Resume(_)),
                        })) => {
                            inputs
                                .events
                                .emit(TransferEvent::Resumed {
                                    transfer_id: tid.clone(),
                                })
                                .await;
                        }
                        _ => {}
                    }
                }
            }
        }
        if last_flush.elapsed() >= crate::constants::CHUNK_ACK_TIME_BASE {
            last_flush = std::time::Instant::now();
            flush_pending_chunk_acks(&mut files, &mut inputs.control).await?;
            if let Some(frame) = try_recv_control(&mut inputs.control).await? {
                match frame.payload {
                    Some(CPayload::SegmentManifest(m)) => {
                        on_manifest(&mut manifests, &mut files, &*inputs.store, &tid, &m).await?;
                        // on_manifest can verify a batch of chunks that arrived
                        // before their manifest, so progress must be
                        // reconsidered on the control path too.
                        emit_progress_if_due(
                            &files,
                            &inputs.config,
                            &*inputs.events,
                            &tid,
                            summary.total_bytes,
                            &mut last_progress_log,
                            &mut progress_reported,
                            false,
                        )
                        .await;
                    }
                    Some(CPayload::Control(ControlMessage {
                        msg: Some(privet_protocol::control_message::Msg::Complete(_)),
                    })) => {
                        break;
                    }
                    Some(CPayload::Control(ControlMessage {
                        msg: Some(privet_protocol::control_message::Msg::Cancel(c)),
                    })) => {
                        if c.reason == "chunk_corrupt" {
                            inputs
                                .events
                                .emit(TransferEvent::StateChanged {
                                    transfer_id: tid.clone(),
                                    state: TransferState::Failed(TransferFailed {
                                        error_code: "chunk_corrupt",
                                        error_message: "retryable".into(),
                                        retryable: true,
                                        part_kept: true,
                                    }),
                                })
                                .await;
                            inputs
                                .events
                                .emit(TransferEvent::Failed {
                                    transfer_id: tid.clone(),
                                    error_code: "chunk_corrupt".into(),
                                    retryable: true,
                                    part_kept: true,
                                })
                                .await;
                            return Ok(());
                        }
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
                    _ => {}
                }
            }
        }
    }

    let mut all_ok = true;
    let mut err_msg = String::new();
    for (fid, st) in &files {
        if let Some(e) = &st.entry {
            if !st.inline_done && e.size > 0 {
                for (&seg_id, bm) in &st.bitmasks {
                    if manifests.has_manifest(fid, seg_id) {
                        let expected = manifests.segment_chunk_count(fid, seg_id).unwrap_or(0);
                        if expected == 0 || bm.count_set() < expected {
                            all_ok = false;
                            err_msg = format!(
                                "file {} segment {seg_id} incomplete (have {}/{})",
                                e.relative_path,
                                bm.count_set(),
                                expected
                            );
                            break;
                        }
                        if !manifests.verify_segment_root(fid, seg_id) {
                            all_ok = false;
                            err_msg = format!(
                                "file {} segment {seg_id} root hash mismatch",
                                e.relative_path
                            );
                            break;
                        }
                    }
                }
                if !all_ok {
                    break;
                }
                let total_verified: u32 = st.verified_count.values().sum();
                let total_needed = manifests.chunk_count_for_file(fid);
                if total_needed > 0 && total_verified < total_needed {
                    all_ok = false;
                    err_msg = format!(
                        "file {} missing chunks (have {}/{})",
                        e.relative_path, total_verified, total_needed
                    );
                    break;
                }
            } else if st.inline_done || e.size == 0 {
            } else {
                all_ok = false;
                err_msg = format!("file {} not started", e.relative_path);
                break;
            }
        }
    }

    if let Some(r) = &inputs.registry {
        r.unregister(&tid);
    }
    if let crate::control::AcceptPolicy::Resolver(res) = &inputs.accept_policy {
        res.cancel(&tid);
    }

    if all_ok {
        inputs
            .store
            .mkdir_finalize_root(&inputs.config.save_dir, root_name.as_deref())?;
        for d in &dir_entries {
            let mut p = inputs.config.save_dir.clone();
            if let Some(r) = &root_name {
                p.push(r);
            }
            p.push(&d.relative_path);
            std::fs::create_dir_all(&p)?;
        }
        for st in files.values() {
            if let Some(e) = &st.entry {
                if !st.inline_done && e.size > 0 {
                    // file-level BLAKE3 verify before rename
                    if !e.hash_value.is_empty() {
                        let part_path = privet_storage::sidecar::part_path(
                            &inputs.config.save_dir,
                            &tid,
                            &e.relative_path,
                        )?;
                        let computed = blake3_hash_file(&part_path)?;
                        if computed != e.hash_value {
                            all_ok = false;
                            err_msg = format!("file {} BLAKE3 mismatch", e.relative_path);
                            break;
                        }
                    }
                    let final_path =
                        final_landing_path(&inputs.config.save_dir, &root_name, &e.relative_path);
                    let outcome = inputs.store.finalize_part(
                        &tid,
                        &e.relative_path,
                        &final_path,
                        inputs.config.on_collision,
                    )?;
                    if outcome == FinalizeOutcome::Landed {
                        let _ = filetime_set(&final_path, e.mtime_ms);
                    }
                }
            }
        }
        inputs.store.cleanup_staging(&tid)?;
    }

    // Commit the receive history (status -> completed, per-file rows) BEFORE the
    // Verified frame and the terminal events. The peer considers the transfer
    // finished the moment it receives Verified, and the GUI refreshes History on
    // the terminal event, so committing any later would race a refresh against a
    // still-"partial" row.
    if all_ok {
        if let Some(h) = &inputs.history {
            let records: Vec<ReceivedFileRecord> = files
                .iter()
                .filter_map(|(fid, st)| {
                    let e = st.entry.as_ref()?;
                    Some(ReceivedFileRecord {
                        file_id: fid.clone(),
                        relative_path: e.relative_path.clone(),
                        size: e.size,
                        hash_type: (!e.hash_type.is_empty()).then(|| e.hash_type.clone()),
                        hash_value: (!e.hash_value.is_empty()).then(|| e.hash_value.clone()),
                        status: "completed".to_string(),
                    })
                })
                .collect();
            (h.on_complete)(&tid, records);
        }
    } else {
        // A receive that ends with incomplete files must surface a terminal
        // event. Verified/StateChanged are discarded at the engine boundary, so
        // without this the GUI tile would sit frozen at its last progress and
        // History would not refresh to show the 'partial' row.
        inputs
            .events
            .emit(TransferEvent::StateChanged {
                transfer_id: tid.clone(),
                state: TransferState::Failed(TransferFailed {
                    error_code: "incomplete",
                    error_message: err_msg.clone(),
                    retryable: false,
                    part_kept: true,
                }),
            })
            .await;
        inputs
            .events
            .emit(TransferEvent::Failed {
                transfer_id: tid.clone(),
                error_code: "incomplete".into(),
                retryable: false,
                part_kept: true,
            })
            .await;
    }

    let verified = TransferVerified {
        transfer_id: tid.clone(),
        ok: all_ok,
        error: err_msg.clone(),
    };
    inputs
        .control
        .send(ControlFrame {
            payload: Some(CPayload::Control(ControlMessage {
                msg: Some(privet_protocol::control_message::Msg::Verified(verified)),
            })),
        })
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    inputs
        .events
        .emit(TransferEvent::Verified {
            transfer_id: tid.clone(),
            ok: all_ok,
        })
        .await;
    inputs
        .events
        .emit(TransferEvent::StateChanged {
            transfer_id: tid.clone(),
            state: TransferState::Verified { ok: all_ok },
        })
        .await;
    if all_ok {
        // Force one final progress report so the GUI tile reaches a real
        // percentage before the terminal event, even when every chunk was
        // verified on a path that never ticked the 1s throttle (small/fast
        // receives). One extra event per transfer, so this is not a flood.
        emit_progress_if_due(
            &files,
            &inputs.config,
            &*inputs.events,
            &tid,
            summary.total_bytes,
            &mut last_progress_log,
            &mut progress_reported,
            true,
        )
        .await;
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
        Err(TransferError::VerifyFailed(err_msg))
    }
}

/// Emit a receiver-side progress report when one is due.
///
/// `verified_count` is the only source of truth for receive progress, and it is
/// bumped from two different places: `handle_data` (chunk verified inline) and
/// `on_manifest` (chunks that arrived before their manifest and were verified
/// when the manifest showed up). Every place that can change it must funnel
/// through this helper, otherwise verified bytes can be known but never
/// reported and the GUI tile sticks at 0%.
///
/// The first report is never throttled: a fast receive can deliver and verify
/// every byte, then reach the terminal state, all inside the 1s window. After
/// the first report the 1s throttle resumes, so long transfers keep ticking at
/// ~1 Hz instead of flooding subscribers.
#[allow(clippy::too_many_arguments)]
async fn emit_progress_if_due(
    files: &HashMap<String, FileRecvState>,
    config: &TransferEngineConfig,
    events: &dyn TransferEventSink,
    tid: &str,
    total_bytes: u64,
    last_progress_log: &mut std::time::Instant,
    progress_reported: &mut bool,
    force: bool,
) {
    let verified_chunks: u64 = files
        .values()
        .map(|st| st.verified_count.values().sum::<u32>() as u64)
        .sum();
    // Mirror the sender's byte approximation so the GUI shows live progress
    // instead of sitting at 0% until completion.
    let verified_bytes = verified_chunks.saturating_mul(config.default_chunk_size as u64);
    if verified_bytes == 0 {
        return;
    }
    if !force
        && *progress_reported
        && last_progress_log.elapsed() < std::time::Duration::from_secs(1)
    {
        return;
    }
    tracing::debug!(transfer_id = %tid, verified_chunks = verified_chunks, "receiver progress");
    events
        .emit(TransferEvent::Progress {
            transfer_id: tid.to_string(),
            verified_bytes: verified_bytes.min(total_bytes),
            total_bytes,
        })
        .await;
    *progress_reported = true;
    *last_progress_log = std::time::Instant::now();
}

async fn on_manifest(
    manifests: &mut ReceiverManifestStore,
    files: &mut HashMap<String, FileRecvState>,
    store: &dyn PartStore,
    tid: &str,
    m: &SegmentManifest,
) -> Result<()> {
    if let Some(st) = files.get_mut(&m.file_id) {
        if !st.meta_inited {
            if let Some(e) = &st.entry {
                let _ = store.init_part_meta(
                    tid,
                    &e.relative_path,
                    &m.file_id,
                    e.size,
                    e.mtime_ms,
                    &e.hash_value,
                );
            }
            st.meta_inited = true;
        }
    }
    if let Some(st) = files.get(&m.file_id) {
        if let Some(e) = &st.entry {
            let _ = store.write_segment_meta(
                tid,
                &e.relative_path,
                &m.file_id,
                m.segment_id,
                &m.segment_hash_value,
                &m.chunk_hash_values,
            );
        }
    }
    manifests.store_manifest(m);
    let pending = manifests.drain_pending(&m.file_id, m.segment_id);
    for p in pending {
        let verdict = manifests.classify_arrival(&p.file_id, p.segment_id, p.chunk_index, &p.data);
        if verdict == ArrivalVerdict::Verified {
            if let Some(st) = files.get(&p.file_id) {
                if let Some(e) = &st.entry {
                    store.pwrite_part(tid, &e.relative_path, p.offset, &p.data)?;
                }
            }
            if let Some(st) = files.get_mut(&p.file_id) {
                let bm = st
                    .bitmasks
                    .entry(p.segment_id)
                    .or_insert_with(|| VerifiedBitmask::new(1024));
                bm.set(p.chunk_index as u32);
                *st.verified_count.entry(p.segment_id).or_insert(0) += 1;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_data(
    manifests: &mut ReceiverManifestStore,
    files: &mut HashMap<String, FileRecvState>,
    store: &dyn PartStore,
    control: &mut Box<dyn crate::ControlChannel>,
    tid: &str,
    root_name: &Option<String>,
    config: &TransferEngineConfig,
    events: &dyn TransferEventSink,
    frame: DataFrame,
    raw: Option<bytes::BytesMut>,
) -> Result<()> {
    match frame.payload {
        Some(DPayload::InlineFile(inline)) => {
            let ok = crate::integrity::verify_chunk(&inline.data, &inline.hash_value);
            if ok {
                let final_path =
                    final_landing_path(&config.save_dir, root_name, &inline.relative_path);
                if let Some(parent) = final_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&final_path, &inline.data)?;
                let _ = filetime_set(&final_path, inline.mtime_ms);
                if let Some(st) = files.get_mut(&inline.file_id) {
                    st.inline_done = true;
                }
            } else {
                return Err(TransferError::VerifyFailed(format!(
                    "inline {} hash mismatch",
                    inline.relative_path
                )));
            }
        }
        Some(DPayload::ChunkHeader(h)) => {
            let data =
                raw.ok_or_else(|| TransferError::Protocol("chunk header without raw".into()))?;
            let verdict =
                manifests.classify_arrival(&h.file_id, h.segment_id, h.chunk_index, &data);
            match verdict {
                ArrivalVerdict::Verified => {
                    if let Some(st) = files.get(&h.file_id) {
                        if let Some(e) = &st.entry {
                            store.pwrite_part(tid, &e.relative_path, h.offset, &data)?;
                        }
                    }
                    if let Some(st) = files.get_mut(&h.file_id) {
                        let bm = st
                            .bitmasks
                            .entry(h.segment_id)
                            .or_insert_with(|| VerifiedBitmask::new(1024));
                        bm.set(h.chunk_index as u32);
                        let cnt = st.verified_count.entry(h.segment_id).or_insert(0);
                        *cnt += 1;
                        let new_count = *cnt;
                        if (new_count as u64) % CHUNK_ACK_INTERVAL == 0 {
                            let indices = bm.set_bits();
                            control
                                .send(ControlFrame {
                                    payload: Some(CPayload::ChunkAck(ChunkAck {
                                        file_id: h.file_id.clone(),
                                        segment_id: h.segment_id,
                                        chunk_indices: indices,
                                    })),
                                })
                                .await?;
                        }
                    }
                }
                ArrivalVerdict::Mismatch => {}
                ArrivalVerdict::Pending => {
                    manifests.buffer_pending(PendingChunk {
                        file_id: h.file_id.clone(),
                        segment_id: h.segment_id,
                        chunk_index: h.chunk_index,
                        offset: h.offset,
                        data: data.to_vec(),
                    });
                }
            }
        }
        None => {}
    }
    let _ = events;
    let _ = tid;
    Ok(())
}

async fn flush_pending_chunk_acks(
    files: &mut HashMap<String, FileRecvState>,
    control: &mut Box<dyn crate::ControlChannel>,
) -> Result<()> {
    let pending: Vec<(String, u32, u64)> = files
        .iter()
        .flat_map(|(fid, st)| {
            let f = fid.clone();
            let lc: HashMap<u32, u32> = st.last_acked_count.clone();
            st.verified_count.iter().filter_map(move |(seg, cnt)| {
                let last = lc.get(seg).copied().unwrap_or(0);
                let cnt_val = *cnt;
                if cnt_val > last {
                    Some((f.clone(), *seg, cnt_val as u64))
                } else {
                    None
                }
            })
        })
        .collect();
    for (file_id, seg_id, verified) in pending {
        let st = files.get_mut(&file_id).unwrap();
        if verified as u32 > st.last_acked_count.get(&seg_id).copied().unwrap_or(0) {
            let indices = st
                .bitmasks
                .get(&seg_id)
                .map(|bm| bm.set_bits())
                .unwrap_or_default();
            let acked_count = indices.len();
            control
                .send(ControlFrame {
                    payload: Some(CPayload::ChunkAck(ChunkAck {
                        file_id: file_id.clone(),
                        segment_id: seg_id,
                        chunk_indices: indices,
                    })),
                })
                .await?;
            tracing::debug!(
                file_id = %file_id, segment_id = seg_id,
                acked_chunks = acked_count,
                "chunk ack sent"
            );
            st.last_acked_count.insert(seg_id, verified as u32);
        }
    }
    Ok(())
}

pub fn build_resume_bitmasks(
    save_dir: &std::path::Path,
    tid: &str,
) -> Result<Vec<privet_protocol::ChunkBitmask>> {
    let staging = save_dir.join(privet_storage::STAGING_DIR_NAME).join(tid);
    if !staging.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&staging).map_err(TransferError::Io)? {
        let entry = entry.map_err(TransferError::Io)?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "part") {
            let rel = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if let Ok(bitmasks) =
                privet_storage::resume::rebuild_verified_bitmap(save_dir, tid, rel)
            {
                for seg in &bitmasks {
                    if let Ok(meta) = privet_storage::sidecar::read_part_meta(
                        &privet_storage::sidecar::part_meta_path(save_dir, tid, rel)?,
                    ) {
                        out.push(privet_protocol::ChunkBitmask {
                            file_id: meta.file_id,
                            segment_id: seg.segment_id,
                            bitmask: seg.bitmask.clone(),
                        });
                    }
                }
            }
        }
    }
    Ok(out)
}

fn blake3_hash_file(path: &std::path::Path) -> Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = privet_crypto::hash::StreamingHasher::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn final_landing_path(
    save_dir: &std::path::Path,
    root_name: &Option<String>,
    relative_path: &str,
) -> std::path::PathBuf {
    let mut p = save_dir.to_path_buf();
    if let Some(r) = root_name {
        p.push(r);
    }
    p.push(relative_path);
    p
}

fn filetime_set(path: &std::path::Path, mtime_ms: u64) -> Result<()> {
    let secs = mtime_ms / 1000;
    let nsecs = ((mtime_ms % 1000) * 1_000_000) as u32;
    use std::time::SystemTime;
    let mt = SystemTime::UNIX_EPOCH + std::time::Duration::new(secs, nsecs);
    let ft = filetime::FileTime::from_system_time(mt);
    filetime::set_file_mtime(path, ft)?;
    Ok(())
}

async fn recv_control(c: &mut Box<dyn crate::ControlChannel>) -> Result<ControlFrame> {
    tokio::time::timeout(std::time::Duration::from_secs(10), c.recv())
        .await
        .map_err(|_| TransferError::Transport("control recv timeout".into()))?
}

async fn try_recv_control(c: &mut Box<dyn crate::ControlChannel>) -> Result<Option<ControlFrame>> {
    match tokio::time::timeout(std::time::Duration::from_millis(5), c.recv()).await {
        Ok(Ok(f)) => Ok(Some(f)),
        Ok(Err(_)) | Err(_) => Ok(None),
    }
}
