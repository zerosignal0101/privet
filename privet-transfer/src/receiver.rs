
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

pub struct ReceiverInputs {
    pub control: Box<dyn crate::ControlChannel>,
    pub data: Vec<Box<dyn crate::DataChannel>>,
    pub store: Box<dyn PartStore>,
    pub events: Box<dyn TransferEventSink>,
    pub config: TransferEngineConfig,
    pub accept_policy: crate::control::AcceptPolicy,
    pub registry: Option<std::sync::Arc<crate::control::TransferRegistry>>,
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
    inputs
        .control
        .send(ControlFrame {
            payload: Some(CPayload::TransferAccept(send_accept)),
        })
        .await?;
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
                if last_progress_log.elapsed() >= std::time::Duration::from_secs(1) {
                    let verified: u64 = files
                        .values()
                        .map(|st| st.verified_count.values().sum::<u32>() as u64)
                        .sum();
                    tracing::debug!(transfer_id = %tid, verified_chunks = verified, "receiver progress");
                    last_progress_log = std::time::Instant::now();
                }
            }
            Ok(Err(TransferError::Transport(_))) => break,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                flush_pending_chunk_acks(&mut files, &mut inputs.control).await?;
                if let Some(rx) = cmd_rx.as_mut() {
                    if let Ok(Some(cmd)) =
                        tokio::time::timeout(std::time::Duration::from_millis(0), rx.recv()).await
                    {
                        match cmd {
                            crate::control::TransferCommand::Cancel => {
                                let _ = inputs
                                    .control
                                    .send(ControlFrame {
                                        payload: Some(CPayload::Control(ControlMessage {
                                            msg: Some(
                                                privet_protocol::control_message::Msg::Cancel(
                                                    privet_protocol::Cancel {
                                                        transfer_id: tid.clone(),
                                                        reason: "user".into(),
                                                    },
                                                ),
                                            ),
                                        })),
                                    })
                                    .await;
                                if let Some(r) = &inputs.registry {
                                    r.unregister(&tid);
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
                            crate::control::TransferCommand::Pause => {
                                let _ = inputs
                                    .control
                                    .send(ControlFrame {
                                        payload: Some(CPayload::Control(ControlMessage {
                                            msg: Some(
                                                privet_protocol::control_message::Msg::Pause(
                                                    privet_protocol::Pause {
                                                        transfer_id: tid.clone(),
                                                    },
                                                ),
                                            ),
                                        })),
                                    })
                                    .await;
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
                            crate::control::TransferCommand::Resume => {
                                let _ = inputs
                                    .control
                                    .send(ControlFrame {
                                        payload: Some(CPayload::Control(ControlMessage {
                                            msg: Some(
                                                privet_protocol::control_message::Msg::Resume(
                                                    privet_protocol::Resume {
                                                        transfer_id: tid.clone(),
                                                    },
                                                ),
                                            ),
                                        })),
                                    })
                                    .await;
                                inputs
                                    .events
                                    .emit(TransferEvent::Resumed {
                                        transfer_id: tid.clone(),
                                    })
                                    .await;
                            }
                        }
                    }
                }
                if let Some(frame) = try_recv_control(&mut inputs.control).await? {
                    match frame.payload {
                        Some(CPayload::SegmentManifest(m)) => {
                            on_manifest(&mut manifests, &mut files, &*inputs.store, &tid, &m)
                                .await?;
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
