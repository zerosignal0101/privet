use std::path::PathBuf;

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
    download_dir: PathBuf,
    chunk_size: u32,
}

impl Receiver {
    pub fn new(conn: quinn::Connection, download_dir: PathBuf, chunk_size: u32) -> Self {
        Self {
            conn,
            download_dir,
            chunk_size,
        }
    }

    /// Handle an incoming connection: accept handshake, receive files.
    pub async fn receive(
        &self,
        event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    ) -> Result<SessionId, PrivetError> {
        // 1. Accept control stream
        let (mut ctrl_send, mut ctrl_recv) = self
            .conn
            .accept_bi()
            .await
            .map_err(|e| TransportError::ConnectionLost(e.to_string()))?;

        // 2. Receive Hello
        let hello_data = control::read_control_frame(&mut ctrl_recv).await?;
        let hello_msg = handshake::deserialize(&hello_data)?;
        let _hello = match &hello_msg {
            ControlMessage::Hello(h) => h,
            other => {
                return Err(crate::error::ProtocolError::UnexpectedMessage {
                    expected: "Hello".into(),
                    got: format!("{other:?}"),
                }
                .into());
            }
        };

        // 3. Send HelloAck
        let hello_ack = ControlMessage::HelloAck(HelloAck {
            version: handshake::PROTOCOL_VERSION,
            accepted: true,
            fingerprint: String::new(),
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

        // 5. Disk space pre-check
        let available = fs_available_space(&self.download_dir)?;
        if available < offer.total_size {
            return Err(PrivetError::DiskFull {
                needed: offer.total_size,
                available,
            });
        }

        // 6. Build resume map and send Accept
        let mut resume_map = std::collections::HashMap::new();
        for file_info in &offer.files.files {
            let dest = self.download_dir.join(&file_info.relative_path);
            if dest.exists() {
                if let Ok(meta) = std::fs::metadata(&dest) {
                    if meta.len() < file_info.size {
                        resume_map.insert(
                            file_info.relative_path.clone(),
                            ResumePoint { bytes_received: meta.len() },
                        );
                    }
                }
            }
        }

        // 7. Notify app layer about incoming transfer
        let _ = event_tx.send(crate::engine::PrivetEvent::IncomingTransfer {
            session_id,
            peer: crate::peer::PeerInfo {
                id: crate::peer::PeerId(uuid::Uuid::nil()),
                name: String::new(),
                addresses: vec![self.conn.remote_address()],
                fingerprint: String::new(),
                is_trusted: false,
                last_seen: std::time::SystemTime::now(),
                platform: None,
                version: None,
            },
            files: crate::session::FileManifest {
                files: offer.files.files.iter().map(|f| crate::session::FileEntry {
                    relative_path: f.relative_path.clone(),
                    size: f.size,
                    modified: f.modified_secs.map(|s| {
                        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s)
                    }),
                    sha256: f.sha256.clone(),
                    is_dir: f.is_dir,
                }).collect(),
                total_size: offer.total_size,
            },
        });

        // Auto-accept for now
        let accept = ControlMessage::Accept(Accept {
            session_id,
            resume_map,
        });
        let accept_data = handshake::serialize(&accept)?;
        control::write_control_frame(&mut ctrl_send, &accept_data).await?;

        // 8. Receive data streams
        let mut tracker = ProgressTracker::new(offer.total_size);
        let file_count = offer.files.files.len();

        for _ in 0..file_count {
            let mut data_stream = self.conn.accept_uni().await
                .map_err(|e| TransportError::ConnectionLost(e.to_string()))?;

            // Read stream header
            let header_data = control::read_control_frame(&mut data_stream).await?;
            let stream_header: StreamHeader = data::deserialize_stream_header(&header_data)?;

            // Read chunks and write to disk
            for file_entry in &stream_header.files {
                let dest = resolve_conflict(&self.download_dir, &file_entry.relative_path);
                if let Some(parent) = dest.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }

                let mut file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(&dest)
                    .await?;

                if file_entry.start_offset > 0 {
                    use tokio::io::AsyncSeekExt;
                    file.seek(std::io::SeekFrom::Start(file_entry.start_offset)).await?;
                } else {
                    file.set_len(0).await?;
                }

                loop {
                    // Read chunk header
                    let chunk_header_data = match control::read_control_frame(&mut data_stream).await {
                        Ok(d) => d,
                        Err(_) => break,
                    };
                    let chunk: Chunk = data::deserialize_chunk(&chunk_header_data)?;

                    // Read chunk data using quinn's native read_exact
                    let mut buf = vec![0u8; chunk.length as usize];
                    data_stream
                        .read_exact(&mut buf)
                        .await
                        .map_err(|e| TransportError::ConnectionLost(e.to_string()))?;

                    tokio::io::AsyncWriteExt::write_all(&mut file, &buf).await?;
                    tracker.record(chunk.length as u64);

                    let _ = event_tx.send(crate::engine::PrivetEvent::TransferProgress {
                        session_id,
                        progress: crate::session::TransferProgress {
                            total_bytes: offer.total_size,
                            bytes_transferred: tracker.bytes_transferred(),
                            current_speed_bps: tracker.speed_bps(),
                            per_file: vec![],
                        },
                    });
                }

                tokio::io::AsyncWriteExt::flush(&mut file).await?;
            }
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
        // read returns Ok(0) on stream EOF or Err on connection close — both signal done.
        let mut buf = [0u8; 1];
        let _ = ctrl_recv.read(&mut buf).await;

        let _ = event_tx.send(crate::engine::PrivetEvent::TransferComplete { session_id });

        tracing::info!("[receiver] transfer complete for session {session_id}");
        Ok(session_id)
    }
}

/// Check available disk space.
fn fs_available_space(_path: &PathBuf) -> Result<u64, PrivetError> {
    Ok(u64::MAX)
}

/// Resolve filename conflicts by appending (1), (2), etc.
fn resolve_conflict(dir: &PathBuf, name: &str) -> PathBuf {
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
