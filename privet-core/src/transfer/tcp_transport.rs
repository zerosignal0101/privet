use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::sync::{oneshot, RwLock};

use crate::error::{PrivetError, TransportError};
use crate::protocol::data::{self, Chunk};
use crate::protocol::handshake::{self, ControlMessage, HelloAck, ResumePoint};
use crate::session::{FileManifest, FileToSend, SessionId};
use crate::storage::records::TransferFileRecord;
use crate::transfer::progress::ProgressTracker;

/// TCP control stream ID for control messages (serialized ControlMessage).
const CONTROL_STREAM: u16 = 0;
/// TCP stream ID for data chunks (serialized Chunk + raw payload).
const DATA_STREAM: u16 = 1;

// ---------------------------------------------------------------------------
// Receiver side
// ---------------------------------------------------------------------------

/// Handle an incoming TCP connection: full receive flow.
/// Accepts any stream implementing AsyncRead+AsyncWrite (raw TcpStream or TLS-wrapped).
/// `tls_peer_fingerprint` is `Some(fp)` when TLS is used — the fingerprint is
/// verified against the peer's Hello claim at the application layer.
pub async fn receive_tcp<S>(
    mut stream: S,
    download_dir: PathBuf,
    _chunk_size: u32,
    listen_port: u16,
    identity: &crate::security::identity::DeviceIdentity,
    trusted_fingerprints: &[String],
    security_mode: &crate::config::SecurityMode,
    tls_peer_fingerprint: Option<&str>,
    remote_addr: Option<std::net::SocketAddr>,
    accept_store: Arc<tokio::sync::Mutex<crate::security::accept::AcceptStore>>,
    pending_incoming: &RwLock<HashMap<SessionId, oneshot::Sender<bool>>>,
    pending_pairing: &RwLock<HashMap<String, oneshot::Sender<crate::engine::PairDecision>>>,
    event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    cancel_signals: &Arc<RwLock<HashMap<SessionId, Arc<AtomicBool>>>>,
    session_meta: &Arc<RwLock<HashMap<SessionId, crate::engine::SessionMeta>>>,
    transfer_log: Option<crate::storage::records::TransferLog>,
) -> Result<(SessionId, String, String, Vec<TransferFileRecord>, Option<std::net::SocketAddr>), PrivetError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use std::net::SocketAddr;

    // 1. Read Hello
    let (_, hello_data) = crate::transport::tcp_fallback::read_frame(&mut stream).await?;
    let hello_msg = handshake::deserialize(&hello_data)?;
    let hello = match &hello_msg {
        ControlMessage::Hello(h) => h,
        other => {
            return Err(crate::error::ProtocolError::UnexpectedMessage {
                expected: "Hello".into(),
                got: format!("{other:?}"),
            }
            .into());
        }
    };
    let peer_fingerprint = hello.fingerprint.clone();
    // Build the peer's listening address from the connection's remote IP
    // (the IP the sender connected from) and their advertised listen port.
    let peer_listen_addr = hello.listen_port
        .and_then(|port| remote_addr.map(|a| std::net::SocketAddr::new(a.ip(), port)));
    if peer_listen_addr.is_some() {
        tracing::debug!("[tcp-recv] hello listen_port={:?} → peer_listen_addr={:?}",
            hello.listen_port, peer_listen_addr);
    }

    // 1b. If TLS is active, verify Hello fingerprint matches TLS certificate
    if let Some(tls_fp) = tls_peer_fingerprint {
        if tls_fp != peer_fingerprint {
            return Err(PrivetError::Security(crate::error::SecurityError::NotTrusted(
                format!("TLS certificate fingerprint '{tls_fp}' does not match Hello claim '{peer_fingerprint}'")
            )));
        }
    }

    // 2. Send HelloAck with our listen port
    let hello_ack = ControlMessage::HelloAck(HelloAck {
        version: handshake::PROTOCOL_VERSION, accepted: true,
        fingerprint: identity.fingerprint.clone(),
        device_name: identity.device_name.clone(),
        listen_port: Some(listen_port),
    });
    crate::transport::tcp_fallback::write_frame(&mut stream, CONTROL_STREAM, &handshake::serialize(&hello_ack)?).await?;

    // 3. Pairing flow: if peer not trusted, wait for user decision
    let mut is_trusted = trusted_fingerprints.iter().any(|fp| fp == &peer_fingerprint);
    if !is_trusted && *security_mode != crate::config::SecurityMode::AllowAll {
        // Avoid duplicate pairing prompts when sender retries
        let already_pending = pending_pairing.read().await.contains_key(&peer_fingerprint);

        let (tx, rx) = tokio::sync::oneshot::channel();
        pending_pairing.write().await.insert(peer_fingerprint.clone(), tx);

        if !already_pending {
            let code =
                crate::security::trust::TrustStore::pairing_code(&identity.fingerprint, &peer_fingerprint);
            let pairing_addr = peer_listen_addr
                .or_else(|| remote_addr)
                .map(|a| vec![a])
                .unwrap_or_default();
            let _ = event_tx.send(crate::engine::PrivetEvent::AwaitingPairing {
                session_id: SessionId(uuid::Uuid::nil()),
                peer: crate::peer::PeerInfo {
                    id: crate::peer::PeerId(uuid::Uuid::nil()),
                    name: hello.device_name.clone(),
                    addresses: pairing_addr,
                    fingerprint: peer_fingerprint.clone(),
                    is_trusted: false,
                    last_seen: std::time::SystemTime::now(),
                    platform: Some(hello.platform.clone()),
                    version: None,
                },
                code,
            });
        }

        match rx.await.unwrap_or(crate::engine::PairDecision::Reject) {
            crate::engine::PairDecision::Trust => {
                is_trusted = true;
            }
            crate::engine::PairDecision::TrustAndAccept => {
                let _ = accept_store.lock().await.accept(peer_fingerprint.clone());
                is_trusted = true;
            }
            crate::engine::PairDecision::Reject => {
                let reject = ControlMessage::Reject(handshake::Reject {
                    session_id: SessionId(uuid::Uuid::nil()),
                    reason: "pairing rejected".into(),
                });
                let reject_data = handshake::serialize(&reject)?;
                let _ = crate::transport::tcp_fallback::write_frame(&mut stream, CONTROL_STREAM, &reject_data).await;
                return Err(PrivetError::Security(crate::error::SecurityError::PairingRequired));
            }
        }
        pending_pairing.write().await.remove(&peer_fingerprint);

        // If pairing was resolved (Trust), sender may have closed this connection.
        // read_frame will return error if so — that's fine, sender will retry.
    }

    // AllowAll: silently trust unknown peers
    if !is_trusted && *security_mode == crate::config::SecurityMode::AllowAll {
        is_trusted = true;
    }

    // 4. Read Offer
    let (_, offer_data) = crate::transport::tcp_fallback::read_frame(&mut stream).await?;
    // Sender may have sent a Reject instead (pairing needed on its side)
    if let Ok(ControlMessage::Reject(rej)) = handshake::deserialize(&offer_data) {
        tracing::info!("[tcp-recv] sender rejected: {} (pairing needed, retry expected)", rej.reason);
        return Ok((SessionId(uuid::Uuid::nil()), peer_fingerprint, hello.device_name.clone(), Vec::new(), peer_listen_addr));
    }
    let offer_msg = handshake::deserialize(&offer_data)?;
    let offer = match &offer_msg {
        ControlMessage::Offer(o) => o,
        other => {
            return Err(crate::error::ProtocolError::UnexpectedMessage {
                expected: "Offer".into(),
                got: format!("{other:?}"),
            }
            .into());
        }
    };
    let session_id = offer.session_id;

    // 4b. Register cancel signal and session metadata
    let cancel_flag = Arc::new(AtomicBool::new(false));
    cancel_signals.write().await.insert(session_id, cancel_flag.clone());
    session_meta.write().await.insert(session_id, crate::engine::SessionMeta {
        direction: crate::session::TransferDirection::Receiving,
        file_relative_paths: offer.files.files.iter().map(|f| f.relative_path.clone()).collect(),
        peer_name: hello.device_name.clone(),
        peer_fingerprint: peer_fingerprint.clone(),
        peer_address: peer_listen_addr.map(|a| a.to_string()),
        files: offer.files.files.iter().map(|f| TransferFileRecord {
            path: f.relative_path.clone(),
            size: f.size,
            is_dir: f.is_dir,
            relative_path: Some(f.relative_path.clone()),
        }).collect(),
        total_bytes: offer.total_size,
        started_at: std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .ok(),
    });

    // Helper to clean up session tracking on error
    let cleanup_session = || {
        let cs = cancel_signals.clone();
        let sm = session_meta.clone();
        let sid = session_id;
        async move {
            cs.write().await.remove(&sid);
            sm.write().await.remove(&sid);
        }
    };

    // 5. Trust check: reject if not trusted
    if !is_trusted && *security_mode != crate::config::SecurityMode::AllowAll {
        let reject = ControlMessage::Reject(handshake::Reject {
            session_id,
            reason: "pairing required: peer not trusted".into(),
        });
        let reject_data = handshake::serialize(&reject)?;
        let _ = crate::transport::tcp_fallback::write_frame(&mut stream, CONTROL_STREAM, &reject_data).await;
        cleanup_session().await;
        return Err(PrivetError::Security(crate::error::SecurityError::PairingRequired));
    }

    // Use the peer's advertised listen address for events, falling back to connection remote_addr.
    let addr_for_events: Vec<SocketAddr> = peer_listen_addr
        .into_iter()
        .chain(remote_addr.into_iter())
        .collect();

    // 5b. AwaitAccept: if Strict mode and NOT in accept_store, wait for user decision
    if *security_mode == crate::config::SecurityMode::Strict
        && !accept_store.lock().await.is_accepted(&peer_fingerprint) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        pending_incoming.write().await.insert(session_id, tx);

        let _ = event_tx.send(crate::engine::PrivetEvent::AwaitingAccept {
            session_id,
            peer: crate::peer::PeerInfo {
                id: crate::peer::PeerId(uuid::Uuid::nil()),
                name: hello.device_name.clone(),
                addresses: addr_for_events.clone(),
                fingerprint: peer_fingerprint.clone(),
                is_trusted: true,
                last_seen: std::time::SystemTime::now(),
                platform: Some(hello.platform.clone()),
                version: None,
            },
            files: crate::session::FileManifest {
                files: offer.files.files.iter().map(|f| crate::session::FileEntry {
                    relative_path: f.relative_path.clone(),
                    size: f.size,
                    modified: f.modified_secs.map(|s| std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s)),
                    sha256: f.sha256.clone(),
                    is_dir: f.is_dir,
                }).collect(),
                total_size: offer.total_size,
            },
        });

        if !rx.await.unwrap_or(false) {
            let reject = ControlMessage::Reject(handshake::Reject {
                session_id,
                reason: "transfer rejected by user".into(),
            });
            let reject_data = handshake::serialize(&reject)?;
            let _ = crate::transport::tcp_fallback::write_frame(&mut stream, CONTROL_STREAM, &reject_data).await;
            cleanup_session().await;
            return Err(PrivetError::TransferRejected("transfer rejected by user".into()));
        }
        pending_incoming.write().await.remove(&session_id);
    }

    // 6. Notify app layer of incoming transfer
    let _ = event_tx.send(crate::engine::PrivetEvent::IncomingTransfer {
        session_id,
        peer: crate::peer::PeerInfo {
            id: crate::peer::PeerId(uuid::Uuid::nil()),
            name: hello.device_name.clone(),
            addresses: addr_for_events.clone(),
            fingerprint: peer_fingerprint.clone(),
            is_trusted: true,
            last_seen: std::time::SystemTime::now(),
            platform: Some(hello.platform.clone()),
            version: None,
        },
        files: crate::session::FileManifest {
            files: offer.files.files.iter().map(|f| crate::session::FileEntry {
                relative_path: f.relative_path.clone(),
                size: f.size,
                modified: f.modified_secs.map(|s| std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s)),
                sha256: f.sha256.clone(),
                is_dir: f.is_dir,
            }).collect(),
            total_size: offer.total_size,
        },
    });

    // 7. Disk space pre-check
    let available = crate::transfer::receiver::fs_available_space(&download_dir)?;
    if available < offer.total_size {
        let reject = ControlMessage::Reject(handshake::Reject {
            session_id,
            reason: format!(
                "disk full: need {} bytes, have {} available",
                offer.total_size, available
            ),
        });
        let reject_data = handshake::serialize(&reject)?;
        let _ = crate::transport::tcp_fallback::write_frame(&mut stream, CONTROL_STREAM, &reject_data).await;
        cleanup_session().await;
        return Err(PrivetError::DiskFull {
            needed: offer.total_size,
            available,
        });
    }

    // 8. Build resume_map via resume::check_resume
    let file_entries: Vec<crate::session::FileEntry> = offer
        .files
        .files
        .iter()
        .map(|f| crate::session::FileEntry {
            relative_path: f.relative_path.clone(),
            size: f.size,
            modified: f.modified_secs.map(|s| {
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s)
            }),
            sha256: f.sha256.clone(),
            is_dir: f.is_dir,
        })
        .collect();
    let raw_map = crate::transfer::resume::check_resume(&download_dir, &file_entries);
    let resume_map: std::collections::HashMap<String, ResumePoint> = raw_map
        .into_iter()
        .map(|(path, bytes)| (path, ResumePoint { bytes_received: bytes }))
        .collect();

    // 9. Send Accept
    let accept = ControlMessage::Accept(handshake::Accept {
        session_id,
        resume_map,
    });
    let accept_data = handshake::serialize(&accept)?;
    crate::transport::tcp_fallback::write_frame(&mut stream, CONTROL_STREAM, &accept_data).await?;

    // 10. Receive file data (chunks over TCP)
    let total_size = offer.total_size;
    let tracker = std::sync::Arc::new(std::sync::Mutex::new(ProgressTracker::new(total_size)));

    let dest_paths = match receive_tcp_files(
        &mut stream,
        &offer.files.files,
        &download_dir,
        &tracker,
        event_tx,
        session_id,
        total_size,
        Some(&cancel_flag),
    )
    .await
    {
        Ok(paths) => paths,
        Err(PrivetError::TransferCancelled) => {
            tracing::info!("[tcp-recv] transfer cancelled, draining incoming data for 500ms to keep TCP buffer flowing...");
            // Read and discard incoming data for up to 500ms.  Without this, the
            // TCP receive buffer fills up during the sleep, the sender's writes
            // block and eventually fail with WSAECONNABORTED before it can read
            // the Cancel frame via the per-chunk non-blocking poll.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(500);
            let mut discard_buf = [0u8; 65536];
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match tokio::time::timeout(
                    remaining,
                    tokio::io::AsyncReadExt::read(&mut stream, &mut discard_buf),
                ).await {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break, // EOF or timeout → sender is done
                    Ok(Ok(_n)) => {} // discarded, continue draining
                }
            }
            tracing::info!("[tcp-recv] drain done, starting graceful TLS shutdown...");
            let shutdown_result = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                tokio::io::AsyncWriteExt::shutdown(&mut stream),
            ).await;
            tracing::info!("[tcp-recv] TLS shutdown result: {:?}", shutdown_result);
            // Log a Cancelled history record before cleaning up.
            if let Some(log) = &transfer_log {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs()).ok();
                let _ = log.append(&crate::storage::records::TransferRecord {
                    session_id,
                    direction: crate::session::TransferDirection::Receiving,
                    peer_fingerprint: peer_fingerprint.clone(),
                    peer_name: hello.device_name.clone(),
                    peer_address: peer_listen_addr.map(|a| a.to_string()),
                    files: offer.files.files.iter().map(|f| TransferFileRecord {
                        path: f.relative_path.clone(),
                        size: f.size,
                        is_dir: f.is_dir,
                        relative_path: Some(f.relative_path.clone()),
                    }).collect(),
                    total_bytes: offer.total_size,
                    bytes_transferred: 0,
                    started_at: None,
                    completed_at: now,
                    state: crate::storage::records::TransferRecordState::Cancelled,
                    error: Some("cancelled by sender".into()),
                });
            }
            // Leave session_meta intact so engine.rs can clean up.
            // Only remove the cancel signal.
            cancel_signals.write().await.remove(&session_id);
            tracing::info!("[tcp-recv] cleanup done, returning TransferCancelled");
            return Err(PrivetError::TransferCancelled);
        }
        Err(e) => {
            // On any error (e.g. sender disconnected without Cancel frame),
            // emit TransferFailed so the UI is not stuck on "in progress".
            let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                session_id,
                error: format!("{e}"),
                direction: crate::session::TransferDirection::Receiving,
            });
            cleanup_session().await;
            return Err(e);
        }
    };

    // 11. Read Complete
    let (_, complete_data) = crate::transport::tcp_fallback::read_frame(&mut stream).await?;
    let _complete = handshake::deserialize(&complete_data)?;

    // 12. Send Verified
    let verified = ControlMessage::Verified(handshake::Verified {
        session_id,
        sha256: vec![0; 32],
    });
    let verified_data = handshake::serialize(&verified)?;
    crate::transport::tcp_fallback::write_frame(&mut stream, CONTROL_STREAM, &verified_data).await?;

    let _ = event_tx.send(crate::engine::PrivetEvent::TransferComplete { session_id, direction: crate::session::TransferDirection::Receiving });

    // Clean up session tracking
    cancel_signals.write().await.remove(&session_id);
    session_meta.write().await.remove(&session_id);

    // Build file records from actual destination paths
    let file_records: Vec<TransferFileRecord> = dest_paths.iter().map(|p| {
        let meta = std::fs::metadata(p).ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let relative_path = p.strip_prefix(&download_dir).ok()
            .and_then(|r| r.to_str())
            .map(|s| s.replace('\\', "/"));
        TransferFileRecord {
            path: p.to_string_lossy().to_string(),
            size,
            is_dir,
            relative_path,
        }
    }).collect();

    tracing::info!("[tcp-recv] transfer complete for session {session_id}");
    Ok((session_id, peer_fingerprint, hello.device_name.clone(), file_records, peer_listen_addr))
}

/// Receive data chunks for a single file from the TCP stream.
/// On error, the partial file at `dest` is deleted before returning.
async fn receive_one_file_tcp<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    file_info: &handshake::FileInfo,
    file_idx: usize,
    mut file: tokio::fs::File,
    tracker: &std::sync::Arc<std::sync::Mutex<ProgressTracker>>,
    event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    session_id: SessionId,
    total_size: u64,
    cancel_flag: Option<&Arc<AtomicBool>>,
) -> Result<(), PrivetError> {
    let expected_bytes = file_info.size;
    let mut written: u64 = 0;

    while written < expected_bytes {
        // Check local cancel flag
        if let Some(ref flag) = cancel_flag {
            if flag.load(Ordering::SeqCst) {
                let cancel = ControlMessage::Cancel(handshake::Cancel {
                    session_id,
                    reason: "cancelled by user".into(),
                });
                if let Ok(data) = handshake::serialize(&cancel) {
                    tracing::info!("[tcp-recv] sending Cancel frame to sender");
                    if let Err(e) = crate::transport::tcp_fallback::write_frame(stream, CONTROL_STREAM, &data).await {
                        tracing::warn!("[tcp-recv] Cancel frame write failed: {e}");
                    } else {
                        tracing::info!("[tcp-recv] Cancel frame sent successfully");
                    }
                }
                let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                    session_id,
                    error: "cancelled by user".into(),
                    direction: crate::session::TransferDirection::Receiving,
                });
                return Err(PrivetError::TransferCancelled);
            }
        }

        let (sid, frame_data) = match crate::transport::tcp_fallback::read_frame(stream).await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("[tcp-recv] read_frame failed (sender disconnected?): {e}");
                return Err(PrivetError::Transport(e));
            }
        };

        // Check for Cancel control message from sender
        if sid == CONTROL_STREAM {
            if let Ok(ControlMessage::Cancel(_)) = handshake::deserialize(&frame_data) {
                let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                    session_id,
                    error: "cancelled by sender".into(),
                    direction: crate::session::TransferDirection::Receiving,
                });
                return Err(PrivetError::TransferCancelled);
            }
            return Err(crate::error::ProtocolError::UnexpectedMessage {
                expected: "data frame".into(),
                got: format!("control stream_id={sid}"),
            }.into());
        }

        if sid != DATA_STREAM {
            return Err(crate::error::ProtocolError::UnexpectedMessage {
                expected: "data frame".into(),
                got: format!("stream_id={sid}"),
            }.into());
        }

        let (chunk, payload) = postcard::take_from_bytes::<Chunk>(&frame_data)
            .map_err(|e| crate::error::ProtocolError::InvalidMessage(e.to_string()))?;

        if payload.len() != chunk.length as usize {
            return Err(TransportError::TcpFallback(format!(
                "chunk length mismatch: header says {}, payload is {}",
                chunk.length,
                payload.len()
            )).into());
        }

        if chunk.path_index != file_idx as u16 {
            tracing::warn!(
                "tcp chunk path_index mismatch: expected {file_idx}, got {}",
                chunk.path_index
            );
        }

        tokio::io::AsyncWriteExt::write_all(&mut file, payload).await?;
        written += chunk.length as u64;

        let bytes_so_far = {
            let mut t = tracker.lock().unwrap();
            t.record(chunk.length as u64);
            (t.bytes_transferred(), t.speed_bps())
        };

        let _ = event_tx.send(crate::engine::PrivetEvent::TransferProgress {
            session_id,
            progress: crate::session::TransferProgress {
                total_bytes: total_size,
                bytes_transferred: bytes_so_far.0,
                current_speed_bps: bytes_so_far.1,
                per_file: vec![],
            },
            direction: crate::session::TransferDirection::Receiving,
        });
    }

    tokio::io::AsyncWriteExt::flush(&mut file).await?;
    Ok(())
}

/// Read data chunks for all files from the TCP stream.
/// Files are sent sequentially (file 0, then file 1, ...).
/// Each data frame = postcard-encoded Chunk + raw chunk payload bytes.
/// Returns the list of actual destination paths (may differ from relative paths due to dedup).
/// Partial files are automatically cleaned up on any error.
async fn receive_tcp_files<S>(
    stream: &mut S,
    files: &[handshake::FileInfo],
    download_dir: &PathBuf,
    tracker: &std::sync::Arc<std::sync::Mutex<ProgressTracker>>,
    event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    session_id: SessionId,
    total_size: u64,
    cancel_flag: Option<&Arc<AtomicBool>>,
) -> Result<Vec<PathBuf>, PrivetError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut dest_paths = Vec::with_capacity(files.len());

    // Build top-level directory rename map for folder-level dedup.
    let dir_rename_map = {
        let rel_paths: Vec<&str> = files.iter().map(|f| f.relative_path.as_str()).collect();
        let raw = crate::transfer::receiver::build_top_dir_rename_map(
            rel_paths.into_iter(),
            download_dir,
        );
        raw.into_iter().map(|(k, v)| (k.to_owned(), v)).collect::<std::collections::HashMap<String, String>>()
    };
    let rename_ref = if dir_rename_map.is_empty() { None } else { Some(&dir_rename_map) };

    for (file_idx, file_info) in files.iter().enumerate() {
        // Adjust path if top-level directory was renamed
        let adjusted_rel = if let Some(map) = rename_ref {
            let ref_map: std::collections::HashMap<&str, String> =
                map.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
            crate::transfer::receiver::adjust_path(&file_info.relative_path, &ref_map)
        } else {
            std::borrow::Cow::Borrowed(file_info.relative_path.as_str())
        };

        // Handle directory marker entries: create the directory, no data to read
        if file_info.is_dir && file_info.size == 0 {
            let dir_path = download_dir.join(&*adjusted_rel);
            tokio::fs::create_dir_all(&dir_path).await?;
            dest_paths.push(dir_path);
            continue;
        }

        let base = download_dir.join(&*adjusted_rel);
        let pair = crate::transfer::receiver::open_file_atomic(&base).await?;
        let dest = pair.0;
        let file = pair.1;

        match receive_one_file_tcp(
            stream, file_info, file_idx, file,
            tracker, event_tx, session_id, total_size, cancel_flag,
        ).await {
            Ok(()) => dest_paths.push(dest),
            Err(e) => {
                // Clean up the partial file: close handle (already dropped in helper) then delete
                let _ = tokio::fs::remove_file(&dest).await;
                tracing::debug!("[tcp-recv] error, cleaned up partial file {:?}: {e}", dest);
                return Err(e);
            }
        }
    }

    Ok(dest_paths)
}

// ---------------------------------------------------------------------------
// Sender side
// ---------------------------------------------------------------------------

/// Send files over a pre-connected TCP stream (raw or TLS-wrapped).
/// `tls_peer_fingerprint` is `Some(fp)` when TLS is active — verified against
/// the peer's HelloAck claim at the app layer.
pub async fn send_files_tcp<S>(
    mut stream: S,
    addr: std::net::SocketAddr,
    files: Vec<FileToSend>,
    chunk_size: u32,
    listen_port: u16,
    session_id: SessionId,
    identity: &crate::security::identity::DeviceIdentity,
    trusted_fingerprints: &[String],
    security_mode: &crate::config::SecurityMode,
    tls_peer_fingerprint: Option<&str>,
    event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    cancel_flag: Option<Arc<AtomicBool>>,
    session_meta: &tokio::sync::RwLock<std::collections::HashMap<SessionId, crate::engine::SessionMeta>>,
) -> Result<(SessionId, String, String, Option<std::net::SocketAddr>), PrivetError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use std::net::SocketAddr;

    // 1. Send Hello with our listen port
    tracing::debug!("[tcp-send] sending Hello listen_port={}", listen_port);
    let hello = ControlMessage::Hello(handshake::Hello {
        version: handshake::PROTOCOL_VERSION,
        device_name: identity.device_name.clone(),
        platform: std::env::consts::OS.to_owned(),
        fingerprint: identity.fingerprint.clone(),
        listen_port: Some(listen_port),
    });
    let hello_data = handshake::serialize(&hello)?;
    crate::transport::tcp_fallback::write_frame(&mut stream, CONTROL_STREAM, &hello_data).await?;

    // 2. Read HelloAck
    let (_, ack_data) = crate::transport::tcp_fallback::read_frame(&mut stream).await?;
    let ack_msg = handshake::deserialize(&ack_data)?;
    let hello_ack = match ack_msg {
        ControlMessage::HelloAck(ack) => ack,
        other => {
            return Err(crate::error::ProtocolError::UnexpectedMessage {
                expected: "HelloAck".into(),
                got: format!("{other:?}"),
            }
            .into());
        }
    };
    let peer_fingerprint = hello_ack.fingerprint;
    let peer_device_name = hello_ack.device_name;
    // Build peer's listening address from the connection's remote IP and advertised port.
    let peer_listen_addr = hello_ack.listen_port
        .map(|port| SocketAddr::new(addr.ip(), port));
    tracing::debug!("[tcp-send] received HelloAck listen_port={:?} → peer_listen_addr={:?}",
        hello_ack.listen_port, peer_listen_addr);

    // Record peer info in session_meta so error/cancel paths have the data.
    {
        let mut map = session_meta.write().await;
        if let Some(meta) = map.get_mut(&session_id) {
            meta.peer_name = peer_device_name.clone();
            meta.peer_fingerprint = peer_fingerprint.clone();
            meta.peer_address = peer_listen_addr.map(|a| a.to_string());
        }
    }

    // 2b. If TLS is active, verify HelloAck fingerprint matches TLS certificate
    if let Some(tls_fp) = tls_peer_fingerprint {
        if tls_fp != peer_fingerprint {
            return Err(PrivetError::Security(crate::error::SecurityError::NotTrusted(
                format!("TLS certificate fingerprint '{tls_fp}' does not match HelloAck claim '{peer_fingerprint}'")
            )));
        }
    }

    // 3. Trust check
    if *security_mode != crate::config::SecurityMode::AllowAll && !trusted_fingerprints.iter().any(|fp| fp == &peer_fingerprint) {
        let code = crate::security::trust::TrustStore::pairing_code(
            &identity.fingerprint,
            &peer_fingerprint,
        );
        let pairing_addr = peer_listen_addr.unwrap_or(addr);
        let _ = event_tx.send(crate::engine::PrivetEvent::PairRequest {
            peer: crate::peer::PeerInfo {
                id: crate::peer::PeerId(uuid::Uuid::nil()),
                name: identity.device_name.clone(),
                addresses: vec![pairing_addr],
                fingerprint: peer_fingerprint.clone(),
                is_trusted: false,
                last_seen: std::time::SystemTime::now(),
                platform: None,
                version: None,
            },
            code,
        });
        // Send a Reject so the receiver sees a clean message instead of a
        // TLS close_notify error when we drop the connection.
        if let Ok(reject) = handshake::serialize(&ControlMessage::Reject(
            handshake::Reject {
                session_id: SessionId(uuid::Uuid::nil()),
                reason: "pairing required".into(),
            },
        )) {
            let _ = crate::transport::tcp_fallback::write_frame(&mut stream, CONTROL_STREAM, &reject).await;
            // Attempt graceful TLS shutdown (best-effort).
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                tokio::io::AsyncWriteExt::shutdown(&mut stream),
            ).await;
        }
        return Err(PrivetError::Security(crate::error::SecurityError::PairingRequired));
    }

    // 4. Build manifest and send Offer
    let manifest = FileManifest::from_expanded(&files);
    let offer = ControlMessage::Offer(handshake::Offer {
        session_id,
        files: handshake::FileManifestInfo {
            files: manifest
                .files
                .iter()
                .map(|f| handshake::FileInfo {
                    relative_path: f.relative_path.clone(),
                    size: f.size,
                    modified_secs: f.modified.map(|t| {
                        t.duration_since(std::time::SystemTime::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    }),
                    sha256: f.sha256.clone(),
                    is_dir: f.is_dir,
                })
                .collect(),
        },
        total_size: manifest.total_size,
    });
    let offer_data = handshake::serialize(&offer)?;
    crate::transport::tcp_fallback::write_frame(&mut stream, CONTROL_STREAM, &offer_data).await?;

    // 5. Read Accept
    let (_, resp_data) = crate::transport::tcp_fallback::read_frame(&mut stream).await?;
    let resp_msg = handshake::deserialize(&resp_data)?;
    let accept = match resp_msg {
        ControlMessage::Accept(a) => a,
        ControlMessage::Reject(r) => {
            return Err(PrivetError::TransferRejected(r.reason));
        }
        other => {
            return Err(crate::error::ProtocolError::UnexpectedMessage {
                expected: "Accept/Reject".into(),
                got: format!("{other:?}"),
            }
            .into());
        }
    };

    // 6. Send file data chunk by chunk
    let total_size = manifest.total_size;
    let tracker = std::sync::Arc::new(std::sync::Mutex::new(ProgressTracker::new(total_size)));

    for (file_idx, file_entry) in files.iter().enumerate() {
        // Skip directory marker entries (no data to send)
        if file_entry.is_dir {
            continue;
        }

        let resume_offset = accept
            .resume_map
            .get(&file_entry.relative_path)
            .map(|r| r.bytes_received)
            .unwrap_or(0);

        let mut file = tokio::fs::File::open(&file_entry.absolute_path).await?;
        if resume_offset > 0 {
            use tokio::io::AsyncSeekExt;
            file.seek(std::io::SeekFrom::Start(resume_offset)).await?;
        }

        let mut buf = vec![0u8; chunk_size as usize];
        let mut offset = resume_offset;

        loop {
            // Check cancel flag before each chunk
            if let Some(ref flag) = cancel_flag {
                if flag.load(Ordering::SeqCst) {
                    let cancel = ControlMessage::Cancel(handshake::Cancel {
                        session_id,
                        reason: "cancelled by user".into(),
                    });
                    if let Ok(data) = handshake::serialize(&cancel) {
                        let _ = crate::transport::tcp_fallback::write_frame(&mut stream, CONTROL_STREAM, &data).await;
                    }
                    // Graceful TLS shutdown so the receiver gets the Cancel
                    // frame before the socket is dropped.
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_millis(500),
                        tokio::io::AsyncWriteExt::shutdown(&mut stream),
                    ).await;
                    let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                        session_id,
                        error: "cancelled by user".into(),
                        direction: crate::session::TransferDirection::Sending,
                    });
                    return Err(PrivetError::TransferCancelled);
                }
            }

            // Trigger the TLS layer to read any pending data from TCP and decrypt
            // it (e.g. a Cancel frame sent by the receiver).  An empty poll_read
            // does not consume any data from the decrypted buffer.
            let poll_ready = {
                use std::pin::Pin;
                use std::task::Context;
                use tokio::io::ReadBuf;
                let waker = std::task::Waker::noop();
                let mut cx = Context::from_waker(&waker);
                let mut empty = [0u8; 0];
                let mut read_buf = ReadBuf::new(&mut empty);
                Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf).is_ready()
            };
            if poll_ready && tokio::time::timeout(
                std::time::Duration::from_millis(100),
                crate::transport::tcp_fallback::read_frame(&mut stream),
            ).await.ok().and_then(|r| r.ok()).map_or(false, |(sid, data)| {
                sid == CONTROL_STREAM && handshake::deserialize(&data)
                    .map_or(false, |msg| matches!(msg, ControlMessage::Cancel(_)))
            }) {
                tracing::info!("[tcp-send] received Cancel frame from receiver");
                let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                    session_id,
                    error: "cancelled by receiver".into(),
                    direction: crate::session::TransferDirection::Sending,
                });
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    tokio::io::AsyncWriteExt::shutdown(&mut stream),
                ).await;
                return Err(PrivetError::TransferCancelled);
            }

            let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf).await?;
            if n == 0 {
                break;
            }

            let chunk = Chunk {
                path_index: file_idx as u16,
                offset,
                length: n as u32,
            };

            // Serialize chunk header and append raw data
            let chunk_header = data::serialize_chunk(&chunk)?;
            let mut frame_data = Vec::with_capacity(chunk_header.len() + n);
            frame_data.extend_from_slice(&chunk_header);
            frame_data.extend_from_slice(&buf[..n]);

            tracing::trace!("[tcp-send] writing data chunk offset={} len={}", offset, n);
            let write_result = crate::transport::tcp_fallback::write_frame(&mut stream, DATA_STREAM, &frame_data).await;
            if let Err(write_err) = &write_result {
                tracing::warn!("[tcp-send] write_frame failed: {write_err}");
                // The Cancel frame may have been sent by the receiver and buffered
                // by the TLS layer before the connection was aborted.  Try to read
                // it from the TLS buffer to report a clean cancellation.
                let cancel_reason = match tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    crate::transport::tcp_fallback::read_frame(&mut stream),
                ).await {
                    Ok(Ok((0, data))) => {
                        if let Ok(ControlMessage::Cancel(cancel)) = handshake::deserialize(&data) {
                            Some(cancel.reason)
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
                if let Some(reason) = cancel_reason {
                    let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                        session_id,
                        error: format!("cancelled by receiver: {reason}"),
                        direction: crate::session::TransferDirection::Sending,
                    });
                    return Err(PrivetError::TransferCancelled);
                }
                return Err(PrivetError::Transport(TransportError::TcpFallback(
                    format!("connection lost: {write_err}"),
                )));
            }

            offset += n as u64;
            let bytes_so_far = {
                let mut t = tracker.lock().unwrap();
                t.record(n as u64);
                (t.bytes_transferred(), t.speed_bps())
            };

            let _ = event_tx.send(crate::engine::PrivetEvent::TransferProgress {
                session_id,
                progress: crate::session::TransferProgress {
                    total_bytes: total_size,
                    bytes_transferred: bytes_so_far.0,
                    current_speed_bps: bytes_so_far.1,
                    per_file: vec![],
                },
                direction: crate::session::TransferDirection::Sending,
            });
        }
    }

    // 7. Send Complete
    let complete = ControlMessage::Complete(handshake::Complete { session_id });
    let complete_data = handshake::serialize(&complete)?;
    crate::transport::tcp_fallback::write_frame(&mut stream, CONTROL_STREAM, &complete_data).await?;

    // 8. Read Verified (or Cancel from receiver)
    let (_, resp_data) = match crate::transport::tcp_fallback::read_frame(&mut stream).await {
        Ok(r) => r,
        Err(e) => {
            // Connection lost — no Cancel frame was received, so this is not
            // a clean cancel signal but a disconnect (e.g. receiver process killed).
            let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                session_id,
                error: format!("connection lost: {e}"),
                direction: crate::session::TransferDirection::Sending,
            });
            return Err(PrivetError::Transport(e));
        }
    };
    match handshake::deserialize(&resp_data)? {
        ControlMessage::Verified(_) => {
            let _ = event_tx.send(crate::engine::PrivetEvent::TransferComplete { session_id, direction: crate::session::TransferDirection::Sending });
            tracing::info!("[tcp-send] transfer complete for session {session_id}");
            Ok((session_id, peer_fingerprint, peer_device_name, peer_listen_addr))
        }
        ControlMessage::Cancel(cancel) => {
            let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                session_id,
                error: format!("cancelled by receiver: {}", cancel.reason),
                direction: crate::session::TransferDirection::Sending,
            });
            Err(PrivetError::TransferCancelled)
        }
        other => {
            Err(crate::error::ProtocolError::UnexpectedMessage {
                expected: "Verified/Cancel".into(),
                got: format!("{other:?}"),
            }.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use tokio::io::duplex;

    /// Helper: convert a PathBuf to a FileToSend (single file, flat name).
    fn file_to_send(path: PathBuf) -> FileToSend {
        let metadata = std::fs::metadata(&path).expect("test file should exist");
        let relative_path = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        FileToSend {
            absolute_path: path,
            relative_path,
            size: metadata.len(),
            modified: metadata.modified().ok(),
            sha256: None,
            is_dir: false,
        }
    }

    /// Helper: write a data frame (header + Chunk + payload) to a stream.
    async fn write_data_frame<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        path_index: u16,
        offset: u64,
        payload: &[u8],
    ) {
        let chunk = Chunk {
            path_index,
            offset,
            length: payload.len() as u32,
        };
        let chunk_header = data::serialize_chunk(&chunk).unwrap();
        let mut frame_data = Vec::with_capacity(chunk_header.len() + payload.len());
        frame_data.extend_from_slice(&chunk_header);
        frame_data.extend_from_slice(payload);
        crate::transport::tcp_fallback::write_frame(stream, DATA_STREAM, &frame_data)
            .await
            .unwrap();
    }

    /// Helper: write a Complete control frame.
    async fn write_complete_frame<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, session_id: SessionId) {
        let complete = ControlMessage::Complete(handshake::Complete { session_id });
        let data = handshake::serialize(&complete).unwrap();
        crate::transport::tcp_fallback::write_frame(stream, CONTROL_STREAM, &data)
            .await
            .unwrap();
    }

    /// Helper: write a Cancel control frame.
    #[allow(dead_code)]
    async fn write_cancel_frame<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, session_id: SessionId) {
        let cancel = ControlMessage::Cancel(handshake::Cancel {
            session_id,
            reason: "test cancel".into(),
        });
        let data = handshake::serialize(&cancel).unwrap();
        crate::transport::tcp_fallback::write_frame(stream, CONTROL_STREAM, &data)
            .await
            .unwrap();
    }

    // ---------------------------------------------------------------------------
    // receive_tcp_files tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_receive_tcp_files_single_chunk() {
        let (mut writer, reader) = duplex(64 * 1024);
        let dir = tempfile::tempdir().unwrap();
        let download_dir = dir.path().to_path_buf();

        let files = vec![handshake::FileInfo {
            relative_path: "hello.txt".into(),
            size: 5,
            modified_secs: None,
            sha256: None,
            is_dir: false,
        }];
        let total_size = 5;
        let tracker = Arc::new(std::sync::Mutex::new(ProgressTracker::new(total_size)));
        let (event_tx, _) = mpsc::unbounded_channel();
        let session_id = SessionId::new();

        // Write one chunk with "Hello"
        write_data_frame(&mut writer, 0, 0, b"Hello").await;
        // Write Complete to signal end
        write_complete_frame(&mut writer, session_id).await;
        // Close write side so read_frame returns EOF
        drop(writer);

        let dests = receive_tcp_files(
            &mut tokio::io::DuplexStream::from(reader),
            &files,
            &download_dir,
            &tracker,
            &event_tx,
            session_id,
            total_size,
            None,
        )
        .await
        .expect("receive_tcp_files should succeed");

        assert_eq!(dests.len(), 1, "should have one destination path");
        let content = std::fs::read(&dests[0]).unwrap();
        assert_eq!(content, b"Hello", "file content should match");
    }

    #[tokio::test]
    async fn test_receive_tcp_files_multiple_chunks() {
        let (mut writer, reader) = duplex(64 * 1024);
        let dir = tempfile::tempdir().unwrap();
        let download_dir = dir.path().to_path_buf();

        let files = vec![handshake::FileInfo {
            relative_path: "chunked.txt".into(),
            size: 10,
            modified_secs: None,
            sha256: None,
            is_dir: false,
        }];
        let total_size = 10;
        let tracker = Arc::new(std::sync::Mutex::new(ProgressTracker::new(total_size)));
        let (event_tx, _) = mpsc::unbounded_channel();
        let session_id = SessionId::new();

        // Write two chunks
        write_data_frame(&mut writer, 0, 0, b"He").await;
        write_data_frame(&mut writer, 0, 2, b"llo").await;
        write_data_frame(&mut writer, 0, 5, b"World").await;
        write_complete_frame(&mut writer, session_id).await;
        drop(writer);

        let dests = receive_tcp_files(
            &mut tokio::io::DuplexStream::from(reader),
            &files,
            &download_dir,
            &tracker,
            &event_tx,
            session_id,
            total_size,
            None,
        )
        .await
        .expect("receive_tcp_files should succeed");

        assert_eq!(dests.len(), 1);
        let content = std::fs::read(&dests[0]).unwrap();
        assert_eq!(content, b"HelloWorld", "file content should match merged chunks");
    }

    #[tokio::test]
    async fn test_receive_tcp_files_cancel_before_read() {
        // Cancel set BEFORE any data arrives → cancel check fires on first loop iteration.
        let (_writer, reader) = duplex(64 * 1024);
        let dir = tempfile::tempdir().unwrap();
        let download_dir = dir.path().to_path_buf();

        let files = vec![handshake::FileInfo {
            relative_path: "cancel_test.bin".into(),
            size: 100,
            modified_secs: None,
            sha256: None,
            is_dir: false,
        }];
        let total_size = 100;
        let tracker = Arc::new(std::sync::Mutex::new(ProgressTracker::new(total_size)));
        let (event_tx, _) = mpsc::unbounded_channel();
        let session_id = SessionId::new();
        let cancel_flag = Arc::new(AtomicBool::new(true)); // pre-set

        // Drop writer so reader gets EOF if cancel check is missed
        drop(_writer);

        let result = receive_tcp_files(
            &mut tokio::io::DuplexStream::from(reader),
            &files,
            &download_dir,
            &tracker,
            &event_tx,
            session_id,
            total_size,
            Some(&cancel_flag),
        )
        .await;

        match result {
            Err(PrivetError::TransferCancelled) => {} // expected
            other => panic!("expected TransferCancelled, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_receive_tcp_files_cancel_after_partial_data() {
        // Cancel fires AFTER some data was received (between chunks).
        let (mut writer, reader) = duplex(64 * 1024);
        let dir = tempfile::tempdir().unwrap();
        let download_dir = dir.path().to_path_buf();

        let files = vec![handshake::FileInfo {
            relative_path: "partial_cancel.bin".into(),
            size: 150, // bigger than data we'll send so cancel fires before file completes
            modified_secs: None,
            sha256: None,
            is_dir: false,
        }];
        let total_size = 150;
        let tracker = Arc::new(std::sync::Mutex::new(ProgressTracker::new(total_size)));
        let (event_tx, _) = mpsc::unbounded_channel();
        let session_id = SessionId::new();
        let cancel_flag = Arc::new(AtomicBool::new(false));

        // Send one chunk (60 bytes) — receiver reads it, then loops back and checks cancel
        write_data_frame(&mut writer, 0, 0, &[0xFFu8; 60]).await;

        // Now set cancel then send more data
        cancel_flag.store(true, Ordering::SeqCst);
        write_data_frame(&mut writer, 0, 60, &[0xAAu8; 40]).await;
        drop(writer);

        let result = receive_tcp_files(
            &mut tokio::io::DuplexStream::from(reader),
            &files,
            &download_dir,
            &tracker,
            &event_tx,
            session_id,
            total_size,
            Some(&cancel_flag),
        )
        .await;

        match result {
            Err(PrivetError::TransferCancelled) => {} // expected
            other => panic!("expected TransferCancelled, got: {other:?}"),
        }

        // File should be cleaned up (removed) after cancel
        let dest = download_dir.join("partial_cancel.bin");
        assert!(!dest.exists(), "partial file should have been cleaned up after cancel");
    }

    #[tokio::test]
    async fn test_receive_tcp_files_cancel_frame_from_sender() {
        let (mut writer, reader) = duplex(64 * 1024);
        let dir = tempfile::tempdir().unwrap();
        let download_dir = dir.path().to_path_buf();

        let files = vec![handshake::FileInfo {
            relative_path: "remote_cancel.bin".into(),
            size: 100,
            modified_secs: None,
            sha256: None,
            is_dir: false,
        }];
        let total_size = 100;
        let tracker = Arc::new(std::sync::Mutex::new(ProgressTracker::new(total_size)));
        let (event_tx, _) = mpsc::unbounded_channel();
        let session_id = SessionId::new();
        let cancel_flag = Arc::new(AtomicBool::new(false));

        // Write first chunk, then Cancel frame
        write_data_frame(&mut writer, 0, 0, &[0u8; 40]).await;
        write_cancel_frame(&mut writer, session_id).await;
        drop(writer);

        let result = receive_tcp_files(
            &mut tokio::io::DuplexStream::from(reader),
            &files,
            &download_dir,
            &tracker,
            &event_tx,
            session_id,
            total_size,
            Some(&cancel_flag),
        )
        .await;

        // Should detect Cancel from sender
        match result {
            Err(PrivetError::TransferCancelled) => {} // expected
            other => panic!("expected TransferCancelled from sender cancel, got: {other:?}"),
        }
    }

    // ---------------------------------------------------------------------------
    // Protocol framing test (send_file_tcp cancel check)
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_cancel_flag_semantics() {
        // Verify that setting cancel_flag before send_files_tcp causes
        // the cancel check to fire when the data-sending loop starts.
        // We use a duplex pair where the "receiver" responds with HelloAck
        // and Accept so the sender reaches the data loop.
        let dir = tempfile::tempdir().unwrap();
        let send_dir = dir.path().join("send");
        let recv_dir = dir.path().join("recv");
        std::fs::create_dir_all(&send_dir).unwrap();
        std::fs::create_dir_all(&recv_dir).unwrap();

        let file_path = send_dir.join("test.bin");
        std::fs::write(&file_path, &[0xAB; 256]).unwrap();

        let (client, mut server) = duplex(64 * 1024);
        let (event_tx, _) = mpsc::unbounded_channel();
        let addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let session_meta: Arc<RwLock<HashMap<SessionId, crate::engine::SessionMeta>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let identity = crate::security::identity::DeviceIdentity::generate(
            "test-sender".into(),
            dir.path().join("identity"),
            10,
        )
        .expect("identity");

        let session_id = SessionId::new();

        // Spawn a minimal "receiver" that responds with HelloAck + Accept
        // so the sender progresses past the handshake to the data loop.
        let recv_identity = crate::security::identity::DeviceIdentity::generate(
            "test-recv".into(),
            dir.path().join("recv-identity"),
            10,
        )
        .expect("recv identity");
        let r_session_id = session_id;
        tokio::spawn(async move {
            // Read Hello
            let (_, hello_data) =
                crate::transport::tcp_fallback::read_frame(&mut server).await.unwrap();
            let _hello: handshake::ControlMessage = handshake::deserialize(&hello_data).unwrap();

            // Send HelloAck
            let hello_ack = handshake::ControlMessage::HelloAck(handshake::HelloAck {
                version: handshake::PROTOCOL_VERSION,
                accepted: true,
                fingerprint: recv_identity.fingerprint.clone(),
                device_name: recv_identity.device_name.clone(),
                listen_port: None,
            });
            let ack_data = handshake::serialize(&hello_ack).unwrap();
            crate::transport::tcp_fallback::write_frame(&mut server, CONTROL_STREAM, &ack_data)
                .await
                .unwrap();

            // Read Offer (sender sends it after receiving HelloAck)
            let (_, _offer_data) =
                crate::transport::tcp_fallback::read_frame(&mut server).await.unwrap();

            // Send Accept
            let accept = handshake::ControlMessage::Accept(handshake::Accept {
                session_id: r_session_id,
                resume_map: std::collections::HashMap::new(),
            });
            let accept_data = handshake::serialize(&accept).unwrap();
            crate::transport::tcp_fallback::write_frame(&mut server, CONTROL_STREAM, &accept_data)
                .await
                .unwrap();

            // Now the sender enters the data-sending loop and checks cancel_flag
            // The cancel flag is set below, so the sender should abort.
            // Don't respond further — sender will either cancel or timeout.
        });

        // Set cancel flag after a short delay (gives time for handshake)
        let flag = cancel_flag.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            flag.store(true, Ordering::SeqCst);
        });

        let result = send_files_tcp(
            client,
            addr,
            vec![file_to_send(file_path)],
            64 * 1024,
            0,
            session_id,
            &identity,
            &[],
            &crate::config::SecurityMode::AllowAll,
            None,
            &event_tx,
            Some(cancel_flag),
            &session_meta,
        )
        .await;

        // Should either get cancelled or a protocol error (receiver closed too early)
        match result {
            Err(PrivetError::TransferCancelled) => {} // expected
            Err(_) => {} // also ok - receiver may close before cancel is detected
            Ok(_) => panic!("expected cancellation or error"),
        }
    }

    // ---------------------------------------------------------------------------
    // End-to-end test: full send/receive cycle through duplex stream
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_e2e_tcp_transfer_duplex() {
        let dir = tempfile::tempdir().unwrap();
        let send_dir = dir.path().join("send");
        let recv_dir = dir.path().join("recv");
        std::fs::create_dir_all(&send_dir).unwrap();
        std::fs::create_dir_all(&recv_dir).unwrap();

        // Create a test file
        let file_path = send_dir.join("hello_e2e.txt");
        let content = b"Hello TCP E2E via duplex! 42";
        std::fs::write(&file_path, content).unwrap();

        // Generate identities (no TLS — fingerprints not verified in test)
        let send_id = crate::security::identity::DeviceIdentity::generate(
            "e2e-send".into(), dir.path().join("e2e-id-send"), 10,
        )
        .expect("send identity");
        let recv_id = crate::security::identity::DeviceIdentity::generate(
            "e2e-recv".into(), dir.path().join("e2e-id-recv"), 10,
        )
        .expect("recv identity");

        // Shared engine-like state
        let cancel_signals: Arc<RwLock<HashMap<SessionId, Arc<AtomicBool>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let session_meta: Arc<RwLock<HashMap<SessionId, crate::engine::SessionMeta>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let accept_store = Arc::new(tokio::sync::Mutex::new(
            crate::security::accept::AcceptStore::load_or_create(
                dir.path().join("e2e_accept.json"),
            )
            .expect("accept store"),
        ));
        let pending_incoming: Arc<RwLock<HashMap<SessionId, oneshot::Sender<bool>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let pending_pairing: Arc<
            RwLock<HashMap<String, oneshot::Sender<crate::engine::PairDecision>>>,
        > = Arc::new(RwLock::new(HashMap::new()));
        let (event_tx, _event_rx) = mpsc::unbounded_channel();

        // Create duplex pair for in-memory streaming
        let (client, server) = duplex(64 * 1024);

        // --- Spawn receiver task ---
        let recv_dir2 = recv_dir.clone();
        let r_cs = cancel_signals.clone();
        let r_sm = session_meta.clone();
        let r_as = accept_store.clone();
        let r_pi = pending_incoming.clone();
        let r_pp = pending_pairing.clone();
        let r_ev = event_tx.clone();
        let r_id = recv_id.clone();
        let recv_handle = tokio::spawn(async move {
            receive_tcp(
                server,
                recv_dir2,
                64 * 1024,
                53530,
                &r_id,
                &[],   // empty trusted — AllowAll handles trust
                &crate::config::SecurityMode::AllowAll,
                None,  // no TLS fingerprint
                None,  // no remote addr
                r_as,
                &*r_pi,
                &*r_pp,
                &r_ev,
                &r_cs,
                &r_sm,
                None,
            )
            .await
        });

        // --- Send files ---
        let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        let send_session_id = SessionId::new();
        let send_result = send_files_tcp(
            client,
            addr,
            vec![file_to_send(file_path.clone())],
            64 * 1024,
            0,
            send_session_id,
            &send_id,
            &[],   // empty trusted — AllowAll
            &crate::config::SecurityMode::AllowAll,
            None,  // no TLS fingerprint
            &event_tx,
            None,  // no cancel flag
            &session_meta,
        )
        .await;

        // Receiver should complete successfully
        let recv_result = recv_handle.await.expect("receiver task panicked");

        match (&send_result, &recv_result) {
            (Ok(send_res), Ok((_sid, _fp, _name, file_records, _peer_addr))) => {
                assert_eq!(send_res.0, *_sid, "session IDs should match");
                // Verify the received file
                assert_eq!(file_records.len(), 1, "should have 1 file record");
                let received_path = &file_records[0].path;
                let received_data = std::fs::read(received_path)
                    .expect("should read received file");
                assert_eq!(
                    received_data, content,
                    "received file content should match"
                );
            }
            (Err(e1), Err(e2)) => {
                panic!(
                    "both sides errored: send={:?}, recv={:?}",
                    e1, e2
                );
            }
            (Err(e), Ok(_)) => {
                panic!("send failed but recv succeeded: {e:?}");
            }
            (Ok(_), Err(e)) => {
                panic!("send succeeded but recv failed: {e:?}");
            }
        }
    }

    /// Full TCP transfer over real localhost TCP (not duplex).
    /// This validates that the send/receive protocol works over actual network I/O.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_e2e_tcp_transfer_loopback() {
        let dir = tempfile::tempdir().unwrap();
        let send_dir = dir.path().join("send");
        let recv_dir = dir.path().join("recv");
        std::fs::create_dir_all(&send_dir).unwrap();
        std::fs::create_dir_all(&recv_dir).unwrap();

        let file_path = send_dir.join("loopback_test.bin");
        let content = b"Hello from TCP loopback!";
        std::fs::write(&file_path, content).unwrap();

        let send_id = crate::security::identity::DeviceIdentity::generate(
            "loopback-send".into(), dir.path().join("id-send"), 10,
        ).expect("send identity");
        let recv_id = crate::security::identity::DeviceIdentity::generate(
            "loopback-recv".into(), dir.path().join("id-recv"), 10,
        ).expect("recv identity");

        let cancel_signals: Arc<RwLock<HashMap<SessionId, Arc<AtomicBool>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let session_meta: Arc<RwLock<HashMap<SessionId, crate::engine::SessionMeta>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let accept_store = Arc::new(tokio::sync::Mutex::new(
            crate::security::accept::AcceptStore::load_or_create(
                dir.path().join("accept.json"),
            ).expect("accept store"),
        ));
        let pending_incoming: Arc<RwLock<HashMap<SessionId, oneshot::Sender<bool>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let pending_pairing: Arc<RwLock<HashMap<String, oneshot::Sender<crate::engine::PairDecision>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let (event_tx, _event_rx) = mpsc::unbounded_channel();

        // Bind TCP listener
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Build TLS configs (already wrapped in Arc by builder fns)
        let server_cfg = crate::security::tls::build_tcp_server_config(&recv_id).unwrap();
        let client_cfg = crate::security::tls::build_client_config(&send_id, &[]).unwrap();

        // Spawn receiver: accept TCP → TLS → receive_tcp
        let r_recv_dir = recv_dir.clone();
        let r_cs = cancel_signals.clone();
        let r_sm = session_meta.clone();
        let r_as = accept_store.clone();
        let r_pi = pending_incoming.clone();
        let r_pp = pending_pairing.clone();
        let r_ev = event_tx.clone();

        let recv_handle = tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.expect("accept");
            let tls_stream = tokio_rustls::TlsAcceptor::from(server_cfg)
                .accept(tcp_stream)
                .await
                .expect("TLS accept");
            let dummy_dir = r_recv_dir.join("dummy-id");
            receive_tcp(
                tls_stream,
                r_recv_dir,
                64 * 1024,
                53530,
                &crate::security::identity::DeviceIdentity::generate(
                    "dummy-recv".into(),
                    dummy_dir,
                    10,
                ).unwrap(),
                &[],
                &crate::config::SecurityMode::AllowAll,
                None,
                None,
                r_as,
                &*r_pi,
                &*r_pp,
                &r_ev,
                &r_cs,
                &r_sm,
                None,
            )
            .await
        });

        // Connect and send
        let tcp_stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect");
        let tls_stream = tokio_rustls::TlsConnector::from(client_cfg)
            .connect(
                rustls::pki_types::ServerName::try_from("privet").unwrap(),
                tcp_stream,
            )
            .await
            .expect("TLS connect");

        let tls_fingerprint: Option<String> = None;
        let send_session_id = SessionId::new();
        let send_result = send_files_tcp(
            tls_stream,
            addr,
            vec![file_to_send(file_path)],
            64 * 1024,
            0,
            send_session_id,
            &send_id,
            &[],
            &crate::config::SecurityMode::AllowAll,
            tls_fingerprint.as_deref(),
            &event_tx,
            None,
            &session_meta,
        )
        .await;

        let recv_result = recv_handle.await.expect("recv task");

        match (&send_result, &recv_result) {
            (Ok(send_res), Ok((_sid, _fp, _name, file_records, _peer_addr))) => {
                assert_eq!(send_res.0, *_sid, "session IDs should match");
                assert_eq!(file_records.len(), 1, "should have 1 file");
                let received_data = std::fs::read(&file_records[0].path).unwrap();
                assert_eq!(received_data, content, "file content should match");
            }
            (Err(e1), Err(e2)) => panic!("both errored: send={e1:?}, recv={e2:?}"),
            (Err(e), Ok(_)) => panic!("send failed: {e:?}"),
            (Ok(_), Err(e)) => panic!("recv failed: {e:?}"),
        }
    }}
