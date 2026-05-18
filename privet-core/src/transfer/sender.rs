use std::path::PathBuf;

use tokio::sync::{mpsc, Semaphore};

use crate::error::{PrivetError, TransportError};
use crate::protocol::control;
use crate::protocol::data::{self, Chunk, StreamFileEntry, StreamHeader};
use crate::protocol::handshake::{self, ControlMessage, Hello, Offer};
use crate::session::{FileManifest, SessionId};
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
}

impl Sender {
    pub fn new(
        conn: quinn::Connection,
        chunk_size: u32,
        fingerprint: String,
        device_name: String,
    ) -> Self {
        Self {
            conn,
            chunk_size,
            fingerprint,
            device_name,
        }
    }

    /// Execute the full send flow: handshake → trust check → offer → send data (parallel streams).
    /// Returns (session_id, peer_fingerprint) on success.
    pub async fn send(
        &self,
        files: &[PathBuf],
        event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
        trusted_fingerprints: &[String],
        security_mode: &crate::config::SecurityMode,
    ) -> Result<(SessionId, String), PrivetError> {
        let session_id = SessionId::new();

        // 1. Open control stream
        tracing::debug!("[sender] opening control stream");
        let (mut ctrl_send, mut ctrl_recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| TransportError::ConnectionLost(format!("step1: {e}")))?;

        // 2. Send Hello with our fingerprint
        tracing::debug!("[sender] sending Hello");
        let hello = ControlMessage::Hello(Hello {
            version: handshake::PROTOCOL_VERSION,
            device_name: self.device_name.clone(),
            platform: std::env::consts::OS.to_owned(),
            fingerprint: self.fingerprint.clone(),
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

        // 3c. Verify HelloAck fingerprint matches TLS certificate (MITM protection)
        if let Some(tls_identity) = self.conn.peer_identity() {
            if let Some(certs) = tls_identity.downcast_ref::<Vec<rustls::pki_types::CertificateDer<'static>>>() {
                if let Some(cert) = certs.first() {
                    let tls_fp = crate::security::cert::fingerprint_from_der(cert.as_ref());
                    if tls_fp != peer_fingerprint {
                        return Err(PrivetError::Security(crate::error::SecurityError::NotTrusted(
                            format!("TLS certificate fingerprint '{tls_fp}' does not match HelloAck claim '{peer_fingerprint}'")
                        )));
                    }
                }
            }
        }

        // 3b. Trust check: fail fast if peer not trusted
        if *security_mode != crate::config::SecurityMode::AllowAll && !trusted_fingerprints.iter().any(|fp| fp == &peer_fingerprint) {
            let code = crate::security::trust::TrustStore::pairing_code(&self.fingerprint, &peer_fingerprint);
            let _ = event_tx.send(crate::engine::PrivetEvent::PairRequest {
                peer: crate::peer::PeerInfo {
                    id: crate::peer::PeerId(uuid::Uuid::nil()),
                    name: self.device_name.clone(),
                    addresses: vec![],
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
        let manifest = FileManifest::from_paths(files)?;
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

        // 6. Send files as parallel data streams (batched)
        tracing::debug!(
            "[sender] sending {} file(s) in parallel batches",
            manifest.files.len()
        );
        let batches = group_file_batches(&manifest.files);
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
            let files_clone: Vec<PathBuf> = files.to_vec();
            let entries_clone = manifest.files.clone();
            let batch = batch_indices.clone();
            let resume_map = accept.resume_map.clone();
            let tracker = std::sync::Arc::clone(&tracker);
            let event_tx = event_tx.clone();

            handles.push(tokio::spawn(async move {
                let _permit = permit; // holds capacity for the batch duration
                send_file_batch(
                    &conn,
                    &files_clone,
                    &entries_clone,
                    &batch,
                    &resume_map,
                    chunk_size,
                    session_id,
                    &event_tx,
                    &tracker,
                )
                .await
            }));
        }

        // Wait for all batches to complete
        for handle in handles {
            handle
                .await
                .map_err(|e| {
                    PrivetError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
                })
                .and_then(|inner| inner)?;
        }

        // 7. Send Complete
        tracing::debug!("[sender] sending Complete");
        let complete = ControlMessage::Complete(handshake::Complete { session_id });
        let complete_data = handshake::serialize(&complete)?;
        control::write_control_frame(&mut ctrl_send, &complete_data)
            .await
            .map_err(|e| TransportError::ConnectionLost(format!("step7: {e}")))?;

        // 8. Receive Verified
        tracing::debug!("[sender] reading Verified");
        let verified_data = control::read_control_frame(&mut ctrl_recv)
            .await
            .map_err(|e| TransportError::ConnectionLost(format!("step8: {e}")))?;
        let _verified = handshake::deserialize(&verified_data)?;

        // 9. Graceful close: finish control stream then close the connection.
        ctrl_send
            .finish()
            .map_err(|e| TransportError::ConnectionLost(format!("step9-finish: {e}")))?;
        self.conn.close(0u32.into(), b"done");

        tracing::info!("[sender] transfer complete for session {session_id}");
        let _ = event_tx.send(crate::engine::PrivetEvent::TransferComplete { session_id });

        Ok((session_id, peer_fingerprint))
    }
}

/// Group files into batches for parallel sending.
/// Small files (≤64KB) are batched together; each large file gets its own batch.
fn group_file_batches(files: &[crate::session::FileEntry]) -> Vec<Vec<usize>> {
    use crate::protocol::data::SMALL_FILE_THRESHOLD;

    let mut batches: Vec<Vec<usize>> = Vec::new();
    let mut current_small_batch: Vec<usize> = Vec::new();

    for (idx, file) in files.iter().enumerate() {
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
    files: &[PathBuf],
    entries: &[crate::session::FileEntry],
    batch_indices: &[usize],
    resume_map: &std::collections::HashMap<String, crate::protocol::handshake::ResumePoint>,
    chunk_size: u32,
    session_id: SessionId,
    event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    tracker: &std::sync::Arc<std::sync::Mutex<ProgressTracker>>,
) -> Result<(), PrivetError> {
    let stream_header = StreamHeader {
        file_count: batch_indices.len() as u16,
        files: batch_indices
            .iter()
            .map(|&idx| {
                let entry = &entries[idx];
                let resume_offset = resume_map
                    .get(&entry.relative_path)
                    .map(|r| r.bytes_received)
                    .unwrap_or(0);
                StreamFileEntry {
                    relative_path: entry.relative_path.clone(),
                    start_offset: resume_offset,
                    total_size: entry.size,
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

    // Send each file in the batch
    for (batch_pos, &idx) in batch_indices.iter().enumerate() {
        let entry = &entries[idx];
        let resume_offset = resume_map
            .get(&entry.relative_path)
            .map(|r| r.bytes_received)
            .unwrap_or(0);

        let file_path = &files[idx];
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
                    total_bytes: entries.iter().map(|e| e.size).sum(),
                    bytes_transferred: bytes_so_far.0,
                    current_speed_bps: bytes_so_far.1,
                    per_file: vec![],
                },
            });
        }
    }

    data_stream
        .finish()
        .map_err(|e| TransportError::ConnectionLost(format!("stream-finish: {e}")))?;

    Ok(())
}
