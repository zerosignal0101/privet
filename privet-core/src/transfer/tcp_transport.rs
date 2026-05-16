use std::path::PathBuf;

use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::error::{PrivetError, TransportError};
use crate::protocol::data::{self, Chunk};
use crate::protocol::handshake::{self, ControlMessage, HelloAck, ResumePoint};
use crate::session::{FileManifest, SessionId};
use crate::transfer::progress::ProgressTracker;

/// TCP control stream ID for control messages (serialized ControlMessage).
const CONTROL_STREAM: u16 = 0;
/// TCP stream ID for data chunks (serialized Chunk + raw payload).
const DATA_STREAM: u16 = 1;

// ---------------------------------------------------------------------------
// Receiver side
// ---------------------------------------------------------------------------

/// Handle an incoming TCP connection: full receive flow.
/// Returns (session_id, peer_fingerprint) on success.
pub async fn receive_tcp(
    mut stream: TcpStream,
    download_dir: PathBuf,
    _chunk_size: u32,
    identity: &crate::security::identity::DeviceIdentity,
    trusted_fingerprints: &[String],
    auto_accept: bool,
    event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
) -> Result<(SessionId, String), PrivetError> {
    let remote_addr = stream.peer_addr().ok();

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

    // 2. Trust check: emit PairRequest if not trusted
    let is_trusted = trusted_fingerprints.iter().any(|fp| fp == &peer_fingerprint);
    if !is_trusted && !auto_accept {
        let code =
            crate::security::trust::TrustStore::pairing_code(&identity.fingerprint, &peer_fingerprint);
        let _ = event_tx.send(crate::engine::PrivetEvent::PairRequest {
            peer: crate::peer::PeerInfo {
                id: crate::peer::PeerId(uuid::Uuid::nil()),
                name: hello.device_name.clone(),
                addresses: remote_addr.map(|a| vec![a]).unwrap_or_default(),
                fingerprint: peer_fingerprint.clone(),
                is_trusted: false,
                last_seen: std::time::SystemTime::now(),
                platform: Some(hello.platform.clone()),
                version: None,
            },
            code,
        });
    }

    // 3. Send HelloAck
    let hello_ack = ControlMessage::HelloAck(HelloAck {
        version: handshake::PROTOCOL_VERSION,
        accepted: true,
        fingerprint: identity.fingerprint.clone(),
    });
    let ack_data = handshake::serialize(&hello_ack)?;
    crate::transport::tcp_fallback::write_frame(&mut stream, CONTROL_STREAM, &ack_data).await?;

    // 4. Read Offer
    let (_, offer_data) = crate::transport::tcp_fallback::read_frame(&mut stream).await?;
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

    // 5. Trust check: reject if not trusted
    if !is_trusted && !auto_accept {
        let reject = ControlMessage::Reject(handshake::Reject {
            session_id,
            reason: "pairing required: peer not trusted".into(),
        });
        let reject_data = handshake::serialize(&reject)?;
        let _ = crate::transport::tcp_fallback::write_frame(&mut stream, CONTROL_STREAM, &reject_data).await;
        return Err(PrivetError::Security(crate::error::SecurityError::PairingRequired));
    }

    // 6. Notify app layer
    let _ = event_tx.send(crate::engine::PrivetEvent::IncomingTransfer {
        session_id,
        peer: crate::peer::PeerInfo {
            id: crate::peer::PeerId(uuid::Uuid::nil()),
            name: hello.device_name.clone(),
            addresses: remote_addr.map(|a| vec![a]).unwrap_or_default(),
            fingerprint: peer_fingerprint.clone(),
            is_trusted: false,
            last_seen: std::time::SystemTime::now(),
            platform: Some(hello.platform.clone()),
            version: None,
        },
        files: crate::session::FileManifest {
            files: offer
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
                .collect(),
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

    receive_tcp_files(
        &mut stream,
        &offer.files.files,
        &download_dir,
        &tracker,
        event_tx,
        session_id,
        total_size,
    )
    .await?;

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

    let _ = event_tx.send(crate::engine::PrivetEvent::TransferComplete { session_id });

    tracing::info!("[tcp-recv] transfer complete for session {session_id}");
    Ok((session_id, peer_fingerprint))
}

/// Read data chunks for all files from the TCP stream.
/// Files are sent sequentially (file 0, then file 1, ...).
/// Each data frame = postcard-encoded Chunk + raw chunk payload bytes.
async fn receive_tcp_files(
    stream: &mut TcpStream,
    files: &[handshake::FileInfo],
    download_dir: &PathBuf,
    tracker: &std::sync::Arc<std::sync::Mutex<ProgressTracker>>,
    event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    session_id: SessionId,
    total_size: u64,
) -> Result<(), PrivetError> {
    for (file_idx, file_info) in files.iter().enumerate() {
        let dest = crate::transfer::receiver::resolve_conflict(download_dir, &file_info.relative_path);
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&dest)
            .await?;

        let expected_bytes = file_info.size;
        let mut written: u64 = 0;
        file.set_len(0).await?;

        while written < expected_bytes {
            let (sid, frame_data) =
                crate::transport::tcp_fallback::read_frame(stream).await?;
            if sid != DATA_STREAM {
                return Err(crate::error::ProtocolError::UnexpectedMessage {
                    expected: "data frame".into(),
                    got: format!("stream_id={sid}"),
                }
                .into());
            }

            // Use postcard::take_from_bytes to split serialized Chunk from raw payload
            let (chunk, payload) = postcard::take_from_bytes::<Chunk>(&frame_data)
                .map_err(|e| crate::error::ProtocolError::InvalidMessage(e.to_string()))?;

            if payload.len() != chunk.length as usize {
                return Err(TransportError::TcpFallback(format!(
                    "chunk length mismatch: header says {}, payload is {}",
                    chunk.length,
                    payload.len()
                ))
                .into());
            }

            // Verify path_index matches (best-effort sanity check)
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
            });
        }

        tokio::io::AsyncWriteExt::flush(&mut file).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sender side
// ---------------------------------------------------------------------------

/// Connect to a peer via TCP and send files.
/// Returns (session_id, peer_fingerprint) on success.
pub async fn send_files_tcp(
    addr: std::net::SocketAddr,
    files: Vec<PathBuf>,
    chunk_size: u32,
    identity: &crate::security::identity::DeviceIdentity,
    trusted_fingerprints: &[String],
    auto_accept: bool,
    event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
) -> Result<(SessionId, String), PrivetError> {
    let stream = crate::transport::tcp_fallback::connect_tcp(addr)
        .await
        .map_err(|e| PrivetError::Transport(e))?;

    let mut tcp = stream;
    let session_id = SessionId::new();

    // 1. Send Hello
    let hello = ControlMessage::Hello(handshake::Hello {
        version: handshake::PROTOCOL_VERSION,
        device_name: identity.device_name.clone(),
        platform: std::env::consts::OS.to_owned(),
        fingerprint: identity.fingerprint.clone(),
    });
    let hello_data = handshake::serialize(&hello)?;
    crate::transport::tcp_fallback::write_frame(&mut tcp, CONTROL_STREAM, &hello_data).await?;

    // 2. Read HelloAck
    let (_, ack_data) = crate::transport::tcp_fallback::read_frame(&mut tcp).await?;
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

    // 3. Trust check
    if !auto_accept && !trusted_fingerprints.iter().any(|fp| fp == &peer_fingerprint) {
        let code = crate::security::trust::TrustStore::pairing_code(
            &identity.fingerprint,
            &peer_fingerprint,
        );
        let _ = event_tx.send(crate::engine::PrivetEvent::PairRequest {
            peer: crate::peer::PeerInfo {
                id: crate::peer::PeerId(uuid::Uuid::nil()),
                name: identity.device_name.clone(),
                addresses: vec![addr],
                fingerprint: peer_fingerprint.clone(),
                is_trusted: false,
                last_seen: std::time::SystemTime::now(),
                platform: None,
                version: None,
            },
            code,
        });
        return Err(PrivetError::Security(crate::error::SecurityError::PairingRequired));
    }

    // 4. Build manifest and send Offer
    let manifest = FileManifest::from_paths(&files)?;
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
    crate::transport::tcp_fallback::write_frame(&mut tcp, CONTROL_STREAM, &offer_data).await?;

    // 5. Read Accept
    let (_, resp_data) = crate::transport::tcp_fallback::read_frame(&mut tcp).await?;
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

    for (file_idx, file_path) in files.iter().enumerate() {
        let entry = &manifest.files[file_idx];
        let resume_offset = accept
            .resume_map
            .get(&entry.relative_path)
            .map(|r| r.bytes_received)
            .unwrap_or(0);

        let mut file = tokio::fs::File::open(file_path).await?;
        if resume_offset > 0 {
            use tokio::io::AsyncSeekExt;
            file.seek(std::io::SeekFrom::Start(resume_offset)).await?;
        }

        let mut buf = vec![0u8; chunk_size as usize];
        let mut offset = resume_offset;

        loop {
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

            crate::transport::tcp_fallback::write_frame(&mut tcp, DATA_STREAM, &frame_data).await?;

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
            });
        }
    }

    // 7. Send Complete
    let complete = ControlMessage::Complete(handshake::Complete { session_id });
    let complete_data = handshake::serialize(&complete)?;
    crate::transport::tcp_fallback::write_frame(&mut tcp, CONTROL_STREAM, &complete_data).await?;

    // 8. Read Verified
    let (_, verified_data) = crate::transport::tcp_fallback::read_frame(&mut tcp).await?;
    let _verified = handshake::deserialize(&verified_data)?;

    let _ = event_tx.send(crate::engine::PrivetEvent::TransferComplete { session_id });

    tracing::info!("[tcp-send] transfer complete for session {session_id}");
    Ok((session_id, peer_fingerprint))
}
