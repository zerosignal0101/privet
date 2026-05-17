use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::error::{PrivetError, TransportError};
use crate::protocol::control;
use crate::protocol::data::{self, Chunk, StreamHeader};
use crate::protocol::handshake::{
    self, Accept, ControlMessage, HelloAck, ResumePoint,
};
use crate::session::SessionId;
use crate::transfer::progress::ProgressTracker;

/// Receive files from a peer over an accepted QUIC connection.
pub struct Receiver {
    conn: quinn::Connection,
    remote_addr: std::net::SocketAddr,
    download_dir: PathBuf,
    #[allow(dead_code)]
    chunk_size: u32,
    #[allow(dead_code)]
    fingerprint: String,
    #[allow(dead_code)]
    device_name: String,
    /// Shared trust store — checked dynamically (not a snapshot).
    trust_store: Arc<tokio::sync::Mutex<crate::security::trust::TrustStore>>,
    auto_accept: bool,
}

impl Receiver {
    pub fn new(
        conn: quinn::Connection,
        download_dir: PathBuf,
        chunk_size: u32,
        fingerprint: String,
        device_name: String,
        trust_store: Arc<tokio::sync::Mutex<crate::security::trust::TrustStore>>,
        auto_accept: bool,
    ) -> Self {
        let remote_addr = conn.remote_address();
        Self {
            conn,
            remote_addr,
            download_dir,
            chunk_size,
            fingerprint,
            device_name,
            trust_store,
            auto_accept,
        }
    }

    /// Handle an incoming connection: accept handshake, receive files.
    /// Returns (session_id, peer_fingerprint) on success.
    pub async fn receive(
        &self,
        event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    ) -> Result<(SessionId, String), PrivetError> {
        // 1. Accept control stream
        let (mut ctrl_send, mut ctrl_recv) = self
            .conn
            .accept_bi()
            .await
            .map_err(|e| TransportError::ConnectionLost(e.to_string()))?;

        // 2. Receive Hello (includes sender's fingerprint)
        let hello_data = control::read_control_frame(&mut ctrl_recv).await?;
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

        // 2b. Trust check: emit PairRequest immediately if peer not trusted
        //     (continue with handshake so pairing info can be exchanged)
        let is_trusted = self.trust_store.lock().await.trusted_fingerprints().iter().any(|fp| fp == &peer_fingerprint);
        if !is_trusted && !self.auto_accept {
            let code = crate::security::trust::TrustStore::pairing_code(&self.fingerprint, &peer_fingerprint);
            let _ = event_tx.send(crate::engine::PrivetEvent::PairRequest {
                peer: crate::peer::PeerInfo {
                    id: crate::peer::PeerId(uuid::Uuid::nil()),
                    name: hello.device_name.clone(),
                    addresses: vec![self.remote_addr],
                    fingerprint: peer_fingerprint.clone(),
                    is_trusted: false,
                    last_seen: std::time::SystemTime::now(),
                    platform: Some(hello.platform.clone()),
                    version: None,
                },
                code,
            });
        }

        // 3. Send HelloAck with our fingerprint
        let hello_ack = ControlMessage::HelloAck(HelloAck {
            version: handshake::PROTOCOL_VERSION,
            accepted: true,
            fingerprint: self.fingerprint.clone(),
        });
        let ack_data = handshake::serialize(&hello_ack)?;
        control::write_control_frame(&mut ctrl_send, &ack_data).await?;

        // 4. Receive Offer
        let offer_data = control::read_control_frame(&mut ctrl_recv).await?;
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

        // 4b. Trust check: reject Offer if peer not trusted
        if !is_trusted && !self.auto_accept {
            let reject = ControlMessage::Reject(handshake::Reject {
                session_id,
                reason: "pairing required: peer not trusted".into(),
            });
            let reject_data = handshake::serialize(&reject)?;
            let _ = control::write_control_frame(&mut ctrl_send, &reject_data).await;
            return Err(PrivetError::Security(crate::error::SecurityError::PairingRequired));
        }

        // 5. Notify app layer about incoming transfer
        let _ = event_tx.send(crate::engine::PrivetEvent::IncomingTransfer {
            session_id,
            peer: crate::peer::PeerInfo {
                id: crate::peer::PeerId(uuid::Uuid::nil()),
                name: hello.device_name.clone(),
                addresses: vec![self.remote_addr],
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
                            std::time::SystemTime::UNIX_EPOCH
                                + std::time::Duration::from_secs(s)
                        }),
                        sha256: f.sha256.clone(),
                        is_dir: f.is_dir,
                    })
                    .collect(),
                total_size: offer.total_size,
            },
        });

        // 6. Disk space pre-check
        let available = fs_available_space(&self.download_dir)?;
        if available < offer.total_size {
            let reject = ControlMessage::Reject(handshake::Reject {
                session_id,
                reason: format!(
                    "disk full: need {} bytes, have {} available",
                    offer.total_size, available
                ),
            });
            let reject_data = handshake::serialize(&reject)?;
            let _ = control::write_control_frame(&mut ctrl_send, &reject_data).await;
            return Err(PrivetError::DiskFull {
                needed: offer.total_size,
                available,
            });
        }

        // 7. Build resume map using resume::check_resume (name+size+mtime)
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
        let raw_map = crate::transfer::resume::check_resume(&self.download_dir, &file_entries);
        let resume_map: std::collections::HashMap<String, ResumePoint> = raw_map
            .into_iter()
            .map(|(path, bytes)| (path, ResumePoint { bytes_received: bytes }))
            .collect();

        let accept = ControlMessage::Accept(Accept {
            session_id,
            resume_map,
        });
        let accept_data = handshake::serialize(&accept)?;
        control::write_control_frame(&mut ctrl_send, &accept_data).await?;

        // 8. Receive data streams (one at a time; each stream may have multiple files)
        let file_count = offer.files.files.len();
        let total_size = offer.total_size;
        let tracker = std::sync::Arc::new(std::sync::Mutex::new(
            ProgressTracker::new(total_size),
        ));

        let mut files_received = 0usize;
        while files_received < file_count {
            let mut data_stream = self
                .conn
                .accept_uni()
                .await
                .map_err(|e| TransportError::ConnectionLost(e.to_string()))?;

            let header_data =
                control::read_control_frame(&mut data_stream).await?;
            let stream_header: StreamHeader = data::deserialize_stream_header(&header_data)?;
            files_received += stream_header.files.len();

            receive_stream_files(
                &mut data_stream,
                &stream_header,
                &self.download_dir,
                &tracker,
                &event_tx,
                session_id,
                total_size,
            )
            .await?;
        }

        // 9. Receive Complete
        let complete_data = control::read_control_frame(&mut ctrl_recv).await?;
        let _complete = handshake::deserialize(&complete_data)?;

        // 10. Send Verified (placeholder checksum)
        let verified = ControlMessage::Verified(handshake::Verified {
            session_id,
            sha256: vec![0; 32],
        });
        let verified_data = handshake::serialize(&verified)?;
        control::write_control_frame(&mut ctrl_send, &verified_data).await?;
        ctrl_send
            .finish()
            .map_err(|e| TransportError::ConnectionLost(format!("finish control: {e}")))?;

        // Wait for sender to close the connection.
        let mut buf = [0u8; 1];
        let _ = ctrl_recv.read(&mut buf).await;

        let _ = event_tx.send(crate::engine::PrivetEvent::TransferComplete { session_id });

        tracing::info!("[receiver] transfer complete for session {session_id}");
        Ok((session_id, peer_fingerprint))
    }
}

/// Receive files from an already-accepted uni stream (may contain multiple multiplexed files).
async fn receive_stream_files(
    data_stream: &mut quinn::RecvStream,
    stream_header: &StreamHeader,
    download_dir: &PathBuf,
    tracker: &std::sync::Arc<std::sync::Mutex<ProgressTracker>>,
    event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    session_id: SessionId,
    total_size: u64,
) -> Result<(), PrivetError> {
    // Read chunks and write to disk for each file in the batch.
    // The sender sends all chunks for file 0, then file 1, etc., sequentially.
    // We read exactly `total_size` bytes per file to delimit boundaries.
    for file_entry in &stream_header.files {
        // When resuming (start_offset > 0), use the original path directly.
        // Only resolve naming conflicts for fresh transfers.
        let dest = if file_entry.start_offset > 0 {
            download_dir.join(&file_entry.relative_path)
        } else {
            resolve_conflict(download_dir, &file_entry.relative_path)
        };
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&dest)
            .await?;

        // Compute how many bytes we expect for this file
        let expected_bytes = file_entry.total_size.saturating_sub(file_entry.start_offset);
        let mut written: u64 = 0;

        if file_entry.start_offset > 0 {
            use tokio::io::AsyncSeekExt;
            file.seek(std::io::SeekFrom::Start(file_entry.start_offset))
                .await?;
        } else {
            file.set_len(0).await?;
        }

        while written < expected_bytes {
            let chunk_header_data = match control::read_control_frame(data_stream).await {
                Ok(d) => d,
                Err(_) => break,
            };
            let chunk: Chunk = data::deserialize_chunk(&chunk_header_data)?;

            let mut buf = vec![0u8; chunk.length as usize];
            data_stream
                .read_exact(&mut buf)
                .await
                .map_err(|e| TransportError::ConnectionLost(e.to_string()))?;

            tokio::io::AsyncWriteExt::write_all(&mut file, &buf).await?;
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

/// Check available disk space (best-effort). Returns u64::MAX if unknown.
pub(crate) fn fs_available_space(_path: &PathBuf) -> std::io::Result<u64> {
    // TODO: implement platform-specific disk space check (fs2 crate or similar)
    Ok(u64::MAX)
}

/// Resolve filename conflicts by appending (1), (2), etc.
pub(crate) fn resolve_conflict(dir: &PathBuf, name: &str) -> PathBuf {
    let dest = dir.join(name);
    if !dest.exists() {
        return dest;
    }

    let stem = dest
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let ext = dest
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    for i in 1..1000 {
        let new_name = if ext.is_empty() {
            format!("{stem} ({i})")
        } else {
            format!("{stem} ({i}).{ext}")
        };
        let new_path = dir.join(&new_name);
        if !new_path.exists() {
            return new_path;
        }
    }

    dest
}
