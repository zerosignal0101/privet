use tokio::sync::{mpsc, Semaphore};

use std::net::SocketAddr;

use crate::error::{PrivetError, TransportError};
use crate::protocol::control;
use crate::protocol::data::{self, Chunk, StreamFileEntry, StreamHeader};
use crate::protocol::handshake::{self, ControlMessage, Hello, Offer};
use crate::session::{FileManifest, FileToSend, SessionId};
use crate::transfer::progress::ProgressTracker;

/// Maximum number of concurrent QUIC data streams per connection.
/// Prevents resource exhaustion when transferring many files.
const MAX_CONCURRENT_STREAMS: usize = 8;

/// Send files to a peer over an established QUIC connection.
pub struct Sender {
    conn: quinn::Connection,
    chunk_size: u32,
    fingerprint: String,
    device_name: String,
    remote_addr: SocketAddr,
    /// The sender's configured listen port (e.g. 53530), advertised in the Hello message.
    listen_port: u16,
    cancel_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Sender {
    pub fn new(
        conn: quinn::Connection,
        chunk_size: u32,
        fingerprint: String,
        device_name: String,
        remote_addr: SocketAddr,
        listen_port: u16,
    ) -> Self {
        Self {
            conn,
            chunk_size,
            fingerprint,
            device_name,
            remote_addr,
            listen_port,
            cancel_flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancel_flag.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Set the cancel flag and return a shared reference for external signaling.
    pub fn set_cancel_flag(
        &mut self,
        flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        self.cancel_flag = flag;
    }

    /// Execute the full send flow: handshake → trust check → offer → send data (parallel streams).
    /// Returns (session_id, peer_fingerprint, peer_device_name, peer_listen_addr) on success.
    pub async fn send(
        &self,
        session_id: SessionId,
        files: &[FileToSend],
        event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
        trusted_fingerprints: &[String],
        security_mode: &crate::config::SecurityMode,
    ) -> Result<(SessionId, String, String, Option<SocketAddr>), PrivetError> {
        if self.is_cancelled() {
            return Err(PrivetError::TransferCancelled);
        }

        // 1. Open control stream
        tracing::debug!("[sender] opening control stream");
        let (mut ctrl_send, mut ctrl_recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| TransportError::ConnectionLost(format!("step1: {e}")))?;

        // 2. Send Hello with our fingerprint and listen port
        tracing::debug!("[sender] sending Hello listen_port={}", self.listen_port);
        let hello = ControlMessage::Hello(Hello {
            version: handshake::PROTOCOL_VERSION,
            device_name: self.device_name.clone(),
            platform: std::env::consts::OS.to_owned(),
            fingerprint: self.fingerprint.clone(),
            listen_port: Some(self.listen_port),
        });
        let hello_data = handshake::serialize(&hello)?;
        control::write_control_frame(&mut ctrl_send, &hello_data)
            .await
            .map_err(|e| TransportError::ConnectionLost(format!("step2: {e}")))?;

        // 3. Receive HelloAck (contains peer's fingerprint)
        tracing::debug!("[sender] reading HelloAck");
        let ack_data = control::read_control_frame(&mut ctrl_recv)
            .await
            .map_err(|e| TransportError::ConnectionLost(format!("step3: {e}")))?;
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
        // Build the peer's listening address from the connection's remote IP
        // (the IP we connected to) and the peer's advertised listen port.
        let peer_listen_addr = hello_ack.listen_port
            .map(|port| SocketAddr::new(self.remote_addr.ip(), port));
        tracing::debug!("[sender] received HelloAck listen_port={:?} → peer_listen_addr={:?}",
            hello_ack.listen_port, peer_listen_addr);

        // 3c. Verify HelloAck fingerprint matches TLS certificate (MITM protection)
        // Extract fingerprint eagerly and drop the Box<dyn Any> before any .await.
        let tls_fp = {
            let tls_identity = self.conn.peer_identity()
                .ok_or_else(|| PrivetError::Security(
                    crate::error::SecurityError::NotTrusted("no peer certificate presented".into())
                ))?;
            let certs = tls_identity.downcast_ref::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .ok_or_else(|| PrivetError::Security(
                    crate::error::SecurityError::NotTrusted("unexpected peer identity type".into())
                ))?;
            let cert = certs.first()
                .ok_or_else(|| PrivetError::Security(
                    crate::error::SecurityError::NotTrusted("peer certificate chain is empty".into())
                ))?;
            crate::security::cert::fingerprint_from_der(cert.as_ref())
        };
        if tls_fp != peer_fingerprint {
            return Err(PrivetError::Security(crate::error::SecurityError::NotTrusted(
                format!("TLS certificate fingerprint '{tls_fp}' does not match HelloAck claim '{peer_fingerprint}'")
            )));
        }

        // 3b. Trust check: fail fast if peer not trusted
        if *security_mode != crate::config::SecurityMode::AllowAll && !trusted_fingerprints.iter().any(|fp| fp == &peer_fingerprint) {
            // Gracefully close the stream so the receiver sees a clean stream end
            // (Reject message via FinishedEarly) instead of a CONNECTION_CLOSE race.
            let reject = ControlMessage::Reject(handshake::Reject {
                session_id: SessionId(uuid::Uuid::nil()),
                reason: "pairing required".into(),
            });
            if let Ok(data) = handshake::serialize(&reject) {
                let _ = control::write_control_frame(&mut ctrl_send, &data).await;
                let _ = ctrl_send.finish();
                // Drive connection IO to flush stream data before the
                // endpoint is dropped (which sends CONNECTION_CLOSE).
                let mut buf = [0u8; 1];
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    ctrl_recv.read(&mut buf),
                ).await;
            }
            let code = crate::security::trust::TrustStore::pairing_code(&self.fingerprint, &peer_fingerprint);
            // Use the peer's advertised listen address (from HelloAck) if available,
            // otherwise fall back to the connection's remote address.
            let pairing_addr = peer_listen_addr.unwrap_or(self.remote_addr);
            let _ = event_tx.send(crate::engine::PrivetEvent::PairRequest {
                peer: crate::peer::PeerInfo {
                    id: crate::peer::PeerId(uuid::Uuid::nil()),
                    name: self.device_name.clone(),
                    addresses: vec![pairing_addr],
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
        tracing::debug!("[sender] sending Offer");
        let manifest = FileManifest::from_expanded(files);
        let offer = ControlMessage::Offer(Offer {
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
        control::write_control_frame(&mut ctrl_send, &offer_data)
            .await
            .map_err(|e| TransportError::ConnectionLost(format!("step4: {e}")))?;

        // 5. Receive Accept or Reject
        tracing::debug!("[sender] reading Accept");
        let resp_data = control::read_control_frame(&mut ctrl_recv)
            .await
            .map_err(|e| TransportError::ConnectionLost(format!("step5: {e}")))?;
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

        // 7. Send files as parallel data streams (batched)
        tracing::debug!(
            "[sender] sending {} file(s) in parallel batches",
            manifest.files.len()
        );
        let batches = group_file_batches(files);
        let tracker = std::sync::Arc::new(std::sync::Mutex::new(
            ProgressTracker::new(manifest.total_size),
        ));
        let chunk_size = self.chunk_size;

        // Cap concurrency to avoid resource exhaustion when sending many files
        let semaphore = std::sync::Arc::new(Semaphore::new(MAX_CONCURRENT_STREAMS));
        let mut handles = Vec::with_capacity(batches.len());
        for batch_indices in &batches {
            let permit = std::sync::Arc::clone(&semaphore)
                .acquire_owned()
                .await
                .unwrap();
            let conn = self.conn.clone();
            let files_clone: Vec<FileToSend> = files.to_vec();
            let batch = batch_indices.clone();
            let resume_map = accept.resume_map.clone();
            let tracker = std::sync::Arc::clone(&tracker);
            let event_tx = event_tx.clone();
            let batch_cancel = self.cancel_flag.clone();

            handles.push(tokio::spawn(async move {
                let _permit = permit; // holds capacity for the batch duration
                send_file_batch(
                    &conn,
                    &files_clone,
                    &batch,
                    &resume_map,
                    chunk_size,
                    session_id,
                    &event_tx,
                    &tracker,
                    Some(batch_cancel),
                )
                .await
            }));
        }

        // Wait for batches while monitoring the control stream for Cancel
        // (pairing-reject-style: sender reads Cancel from ctrl_recv)
        let mut batch_index = 0;
        while batch_index < handles.len() {
            // peek at cancel flag first (fast path)
            if self.is_cancelled() {
                // Send Cancel on the control stream and wait for the receiver
                // to acknowledge — keeps connection alive so Cancel is delivered.
                let cancel = ControlMessage::Cancel(handshake::Cancel {
                    session_id, reason: "cancelled by user".into(),
                });
                if let Ok(data) = handshake::serialize(&cancel) {
                    if control::write_control_frame(&mut ctrl_send, &data).await.is_ok() {
                        let _ = ctrl_send.finish();
                    }
                }
                let mut buf = [0u8; 1];
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    ctrl_recv.read(&mut buf),
                ).await;
                let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                    session_id,
                    error: "cancelled by remote peer".into(),
                    direction: crate::session::TransferDirection::Sending,
                });
                return Err(PrivetError::TransferCancelled);
            }

            tokio::select! {
                result = &mut handles[batch_index] => {
                    match result {
                        Ok(Ok(())) => batch_index += 1,
                        Ok(Err(PrivetError::TransferCancelled)) => {
                            // Batch was cancelled — notify receiver on control stream
                            let cancel = ControlMessage::Cancel(handshake::Cancel {
                                session_id, reason: "cancelled by user".into(),
                            });
                            if let Ok(data) = handshake::serialize(&cancel) {
                                if control::write_control_frame(&mut ctrl_send, &data).await.is_ok() {
                                    let _ = ctrl_send.finish();
                                }
                            }
                            let mut buf = [0u8; 1];
                            let _ = tokio::time::timeout(
                                std::time::Duration::from_secs(3),
                                ctrl_recv.read(&mut buf),
                            ).await;
                            let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                                session_id,
                                error: "cancelled by remote peer".into(),
                                direction: crate::session::TransferDirection::Sending,
                            });
                            return Err(PrivetError::TransferCancelled);
                        }
                        Ok(Err(e)) => return Err(e),
                        Err(e) => return Err(PrivetError::Io(std::io::Error::new(
                            std::io::ErrorKind::Other, e.to_string(),
                        ))),
                    }
                }
                msg = control::read_control_frame(&mut ctrl_recv) => {
                    match msg {
                        Ok(data) => {
                            if let Ok(ControlMessage::Cancel(_)) = handshake::deserialize(&data) {
                                // Receiver cancelled — acknowledge by finishing our send side
                                let _ = ctrl_send.finish();
                                self.cancel_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                                tracing::info!("[sender] cancelled by receiver for session {session_id}");
                                let _ = event_tx.send(crate::engine::PrivetEvent::TransferFailed {
                                    session_id,
                                    error: "cancelled by remote peer".into(),
                                    direction: crate::session::TransferDirection::Sending,
                                });
                                return Err(PrivetError::TransferCancelled);
                            }
                        }
                        Err(e) => {
                            // Control stream error (network issue, not a clean Cancel)
                            return Err(PrivetError::Transport(e));
                        }
                    }
                }
            }
        }

        // 8. Send Complete
        tracing::debug!("[sender] sending Complete");
        let complete = ControlMessage::Complete(handshake::Complete { session_id });
        let complete_data = handshake::serialize(&complete)?;
        control::write_control_frame(&mut ctrl_send, &complete_data)
            .await
            .map_err(|e| TransportError::ConnectionLost(format!("step8: {e}")))?;

        // 9. Receive Verified
        tracing::debug!("[sender] reading Verified");
        let verified_data = control::read_control_frame(&mut ctrl_recv)
            .await
            .map_err(|e| TransportError::ConnectionLost(format!("step9: {e}")))?;
        let _verified = handshake::deserialize(&verified_data)?;

        // 10. Graceful close: finish control stream then close the connection.
        ctrl_send
            .finish()
            .map_err(|e| TransportError::ConnectionLost(format!("step10-finish: {e}")))?;
        self.conn.close(0u32.into(), b"done");

        tracing::info!("[sender] transfer complete for session {session_id}");
        let _ = event_tx.send(crate::engine::PrivetEvent::TransferComplete { session_id, direction: crate::session::TransferDirection::Sending });

        Ok((session_id, peer_fingerprint, peer_device_name, peer_listen_addr))
    }
}

/// Group files into batches for parallel sending.
/// Small files (≤64KB) are batched together; each large file gets its own batch.
/// Directory marker entries (is_dir == true) are excluded from batches.
fn group_file_batches(files: &[FileToSend]) -> Vec<Vec<usize>> {
    use crate::protocol::data::SMALL_FILE_THRESHOLD;

    let mut batches: Vec<Vec<usize>> = Vec::new();
    let mut current_small_batch: Vec<usize> = Vec::new();

    for (idx, file) in files.iter().enumerate() {
        if file.is_dir {
            continue;
        }
        if file.size <= SMALL_FILE_THRESHOLD {
            current_small_batch.push(idx);
            if current_small_batch.len() >= 16 {
                batches.push(std::mem::take(&mut current_small_batch));
            }
        } else {
            if !current_small_batch.is_empty() {
                batches.push(std::mem::take(&mut current_small_batch));
            }
            batches.push(vec![idx]);
        }
    }

    if !current_small_batch.is_empty() {
        batches.push(current_small_batch);
    }

    batches
}

/// Send file data for a batch of file entries on a single uni stream.
async fn send_file_batch(
    conn: &quinn::Connection,
    files: &[FileToSend],
    batch_indices: &[usize],
    resume_map: &std::collections::HashMap<String, crate::protocol::handshake::ResumePoint>,
    chunk_size: u32,
    session_id: SessionId,
    event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    tracker: &std::sync::Arc<std::sync::Mutex<ProgressTracker>>,
    cancel_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<(), PrivetError> {
    let stream_header = StreamHeader {
        file_count: batch_indices.len() as u16,
        files: batch_indices
            .iter()
            .map(|&idx| {
                let file = &files[idx];
                let resume_offset = resume_map
                    .get(&file.relative_path)
                    .map(|r| r.bytes_received)
                    .unwrap_or(0);
                StreamFileEntry {
                    relative_path: file.relative_path.clone(),
                    start_offset: resume_offset,
                    total_size: file.size,
                    is_dir: file.is_dir,
                }
            })
            .collect(),
    };

    let mut data_stream = conn
        .open_uni()
        .await
        .map_err(|e| TransportError::ConnectionLost(format!("open-uni: {e}")))?;

    // Write stream header
    let header_bytes = data::serialize_stream_header(&stream_header)?;
    control::write_control_frame(&mut data_stream, &header_bytes)
        .await
        .map_err(|e| TransportError::ConnectionLost(format!("stream-header: {e}")))?;

    let total_size: u64 = files.iter().map(|f| f.size).sum();

    // Send each file in the batch
    for (batch_pos, &idx) in batch_indices.iter().enumerate() {
        let file_entry = &files[idx];

        // Skip directory marker entries (no data to send)
        if file_entry.is_dir {
            continue;
        }

        let resume_offset = resume_map
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
            if let Some(ref flag) = cancel_flag {
                if flag.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(PrivetError::TransferCancelled);
                }
            }
            let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf).await?;
            if n == 0 {
                break;
            }

            let chunk = Chunk {
                path_index: batch_pos as u16,
                offset,
                length: n as u32,
            };
            let chunk_header = data::serialize_chunk(&chunk)?;
            control::write_control_frame(&mut data_stream, &chunk_header)
                .await
                .map_err(|e| TransportError::ConnectionLost(format!("chunk-header: {e}")))?;
            data_stream
                .write_all(&buf[..n])
                .await
                .map_err(|e| TransportError::ConnectionLost(format!("chunk-data: {e}")))?;

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

    data_stream
        .finish()
        .map_err(|e| TransportError::ConnectionLost(format!("stream-finish: {e}")))?;

    Ok(())
}
