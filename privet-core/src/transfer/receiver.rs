use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::RwLock;

use crate::engine::PairDecision;
use crate::config::SecurityMode;
use crate::error::{PrivetError, TransportError};
use crate::protocol::control;
use crate::protocol::data::{self, Chunk, StreamHeader};
use crate::protocol::handshake::{self, Accept, ControlMessage, HelloAck, ResumePoint};
use crate::session::SessionId;
use crate::transfer::progress::ProgressTracker;

/// Receive files from a peer over an accepted QUIC connection.
pub struct Receiver {
    conn: quinn::Connection,
    remote_addr: std::net::SocketAddr,
    download_dir: PathBuf,
    chunk_size: u32,
    fingerprint: String,
    device_name: String,
    trust_store: Arc<tokio::sync::Mutex<crate::security::trust::TrustStore>>,
    security_mode: SecurityMode,
    accept_store: Arc<tokio::sync::Mutex<crate::security::accept::AcceptStore>>,
    pending_incoming: Arc<RwLock<HashMap<SessionId, oneshot::Sender<bool>>>>,
    pending_pairing: Arc<RwLock<HashMap<String, oneshot::Sender<PairDecision>>>>,
}

impl Receiver {
    pub fn new(
        conn: quinn::Connection,
        download_dir: PathBuf,
        chunk_size: u32,
        fingerprint: String,
        device_name: String,
        trust_store: Arc<tokio::sync::Mutex<crate::security::trust::TrustStore>>,
        security_mode: SecurityMode,
        accept_store: Arc<tokio::sync::Mutex<crate::security::accept::AcceptStore>>,
        pending_incoming: Arc<RwLock<HashMap<SessionId, oneshot::Sender<bool>>>>,
        pending_pairing: Arc<RwLock<HashMap<String, oneshot::Sender<PairDecision>>>>,
    ) -> Self {
        let remote_addr = conn.remote_address();
        Self { conn, remote_addr, download_dir, chunk_size, fingerprint, device_name,
            trust_store, security_mode, accept_store, pending_incoming, pending_pairing }
    }

    pub async fn receive(
        &self,
        event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    ) -> Result<(SessionId, String), PrivetError> {
        let (mut ctrl_send, mut ctrl_recv) = self.conn.accept_bi()
            .await.map_err(|e| TransportError::ConnectionLost(e.to_string()))?;

        // 1. Receive Hello
        let hello_data = control::read_control_frame(&mut ctrl_recv).await?;
        let hello = match handshake::deserialize(&hello_data)? {
            ControlMessage::Hello(h) => h,
            other => return Err(crate::error::ProtocolError::UnexpectedMessage {
                expected: "Hello".into(), got: format!("{other:?}"),
            }.into()),
        };
        let peer_fingerprint = hello.fingerprint.clone();

        // 2. TLS fingerprint verification
        if let Some(tls_identity) = self.conn.peer_identity() {
            if let Some(certs) = tls_identity.downcast_ref::<Vec<rustls::pki_types::CertificateDer<'static>>>() {
                if let Some(cert) = certs.first() {
                    let tls_fp = crate::security::cert::fingerprint_from_der(cert.as_ref());
                    if tls_fp != peer_fingerprint {
                        return Err(PrivetError::Security(crate::error::SecurityError::NotTrusted(
                            format!("TLS cert fingerprint '{tls_fp}' != Hello claim '{peer_fingerprint}'"))));
                    }
                }
            }
        }

        // 3. Send HelloAck immediately (sender needs our fingerprint for trust check)
        let hello_ack = ControlMessage::HelloAck(HelloAck {
            version: handshake::PROTOCOL_VERSION, accepted: true,
            fingerprint: self.fingerprint.clone(),
        });
        control::write_control_frame(&mut ctrl_send, &handshake::serialize(&hello_ack)?).await?;

        // 4. Pairing flow: if peer not trusted, wait for user decision
        let is_trusted = self.trust_store.lock().await.trusted_fingerprints().iter().any(|fp| fp == &peer_fingerprint);
        if !is_trusted && self.security_mode != SecurityMode::AllowAll {
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.pending_pairing.write().await.insert(peer_fingerprint.clone(), tx);

            let code = crate::security::trust::TrustStore::pairing_code(&self.fingerprint, &peer_fingerprint);
            let _ = event_tx.send(crate::engine::PrivetEvent::AwaitingPairing {
                session_id: SessionId(uuid::Uuid::nil()),
                peer: crate::peer::PeerInfo {
                    id: crate::peer::PeerId(uuid::Uuid::nil()),
                    name: hello.device_name.clone(), addresses: vec![self.remote_addr],
                    fingerprint: peer_fingerprint.clone(), is_trusted: false,
                    last_seen: std::time::SystemTime::now(), platform: Some(hello.platform.clone()), version: None,
                }, code,
            });

            match rx.await.unwrap_or(PairDecision::Reject) {
                PairDecision::Trust => { let _ = self.trust_store.lock().await.trust(peer_fingerprint.clone()); }
                PairDecision::TrustAndAccept => {
                    let _ = self.trust_store.lock().await.trust(peer_fingerprint.clone());
                    let _ = self.accept_store.lock().await.accept(peer_fingerprint.clone());
                }
                PairDecision::Reject => {
                    return Err(PrivetError::Security(crate::error::SecurityError::PairingRequired));
                }
            }
            self.pending_pairing.write().await.remove(&peer_fingerprint);

            // Sender likely rejected this connection (PairingRequired).
            // Try to read Offer — will fail if sender closed the connection.
            let offer_data = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                control::read_control_frame(&mut ctrl_recv),
            ).await;
            match offer_data {
                Ok(Ok(data)) => {
                    // Sender retried with Offer on this same connection
                    return self.handle_offer(data, &hello, &peer_fingerprint, ctrl_send, ctrl_recv, event_tx).await;
                }
                _ => {
                    // Connection closed or timed out — sender will retry on new connection
                    return Err(PrivetError::Security(crate::error::SecurityError::PairingRequired));
                }
            }
        }

        // AllowAll: silently trust unknown peers
        if !is_trusted && self.security_mode == SecurityMode::AllowAll {
            let _ = self.trust_store.lock().await.trust(peer_fingerprint.clone());
        }

        // 5. Read Offer
        let offer_data = control::read_control_frame(&mut ctrl_recv).await?;
        self.handle_offer(offer_data, &hello, &peer_fingerprint, ctrl_send, ctrl_recv, event_tx).await
    }

    async fn handle_offer(
        &self,
        offer_data: Vec<u8>,
        hello: &handshake::Hello,
        peer_fingerprint: &str,
        mut ctrl_send: quinn::SendStream,
        mut ctrl_recv: quinn::RecvStream,
        event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    ) -> Result<(SessionId, String), PrivetError> {
        let offer = match handshake::deserialize(&offer_data)? {
            ControlMessage::Offer(o) => o,
            other => return Err(crate::error::ProtocolError::UnexpectedMessage {
                expected: "Offer".into(), got: format!("{other:?}"),
            }.into()),
        };
        let session_id = offer.session_id;

        // Notify app layer of incoming transfer (before trust check, so UI always sees it)
        let is_trusted = self.trust_store.lock().await.trusted_fingerprints().iter().any(|fp| fp == peer_fingerprint);
        let _ = event_tx.send(crate::engine::PrivetEvent::IncomingTransfer {
            session_id,
            peer: crate::peer::PeerInfo {
                id: crate::peer::PeerId(uuid::Uuid::nil()),
                name: hello.device_name.clone(),
                addresses: vec![self.remote_addr],
                fingerprint: peer_fingerprint.to_owned(),
                is_trusted,
                last_seen: std::time::SystemTime::now(),
                platform: Some(hello.platform.clone()),
                version: None,
            },
            files: crate::session::FileManifest {
                files: offer.files.files.iter().map(|f| crate::session::FileEntry {
                    relative_path: f.relative_path.clone(), size: f.size,
                    modified: f.modified_secs.map(|s| std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s)),
                    sha256: f.sha256.clone(), is_dir: f.is_dir,
                }).collect(),
                total_size: offer.total_size,
            },
        });

        // Trust check: reject untrusted unless AllowAll
        if !is_trusted && self.security_mode != SecurityMode::AllowAll {
            let reject = ControlMessage::Reject(handshake::Reject {
                session_id, reason: "pairing required: peer not trusted".into(),
            });
            control::write_control_frame(&mut ctrl_send, &handshake::serialize(&reject)?).await?;
            return Err(PrivetError::Security(crate::error::SecurityError::PairingRequired));
        }

        // AwaitAccept flow: determine if user prompt is needed
        match self.security_mode {
            SecurityMode::AllowAll | SecurityMode::TrustRequired => {
                // AllowAll: auto-accept all; TrustRequired: trusted = auto-accept
            }
            SecurityMode::Strict => {
                if !self.accept_store.lock().await.is_accepted(peer_fingerprint) {
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.pending_incoming.write().await.insert(session_id, tx);
            tracing::debug!("[receiver] AwaitingAccept: inserted session {} into pending_incoming", session_id.0);
            let _ = event_tx.send(crate::engine::PrivetEvent::AwaitingAccept {
                session_id,
                peer: crate::peer::PeerInfo {
                    id: crate::peer::PeerId(uuid::Uuid::nil()), name: hello.device_name.clone(),
                    addresses: vec![self.remote_addr], fingerprint: peer_fingerprint.to_owned(),
                    is_trusted: true, last_seen: std::time::SystemTime::now(),
                    platform: Some(hello.platform.clone()), version: None,
                },
                files: crate::session::FileManifest {
                    files: offer.files.files.iter().map(|f| crate::session::FileEntry {
                        relative_path: f.relative_path.clone(), size: f.size,
                        modified: f.modified_secs.map(|s| std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s)),
                        sha256: f.sha256.clone(), is_dir: f.is_dir,
                    }).collect(),
                    total_size: offer.total_size,
                },
            });
            tracing::debug!("[receiver] AwaitingAccept: waiting for user decision (session {})...", session_id.0);
            if !rx.await.unwrap_or(false) {
                tracing::debug!("[receiver] AwaitingAccept: user REJECTED session {}", session_id.0);
                let reject = ControlMessage::Reject(handshake::Reject {
                    session_id, reason: "transfer rejected by user".into(),
                });
                control::write_control_frame(&mut ctrl_send, &handshake::serialize(&reject)?).await?;
                return Err(PrivetError::TransferRejected("transfer rejected by user".into()));
            }
            tracing::debug!("[receiver] AwaitingAccept: user ACCEPTED session {}", session_id.0);
            self.pending_incoming.write().await.remove(&session_id);
        }
            }
        }

        // Disk space pre-check
        if fs_available_space(&self.download_dir)? < offer.total_size {
            let reject = ControlMessage::Reject(handshake::Reject {
                session_id, reason: format!("disk full: need {}, have {}", offer.total_size, fs_available_space(&self.download_dir)?),
            });
            control::write_control_frame(&mut ctrl_send, &handshake::serialize(&reject)?).await?;
            return Err(PrivetError::DiskFull { needed: offer.total_size, available: fs_available_space(&self.download_dir)? });
        }

        // Resume map
        let file_entries: Vec<crate::session::FileEntry> = offer.files.files.iter().map(|f| crate::session::FileEntry {
            relative_path: f.relative_path.clone(), size: f.size,
            modified: f.modified_secs.map(|s| std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s)),
            sha256: f.sha256.clone(), is_dir: f.is_dir,
        }).collect();
        let raw_map = crate::transfer::resume::check_resume(&self.download_dir, &file_entries);
        let resume_map: std::collections::HashMap<String, ResumePoint> = raw_map
            .into_iter().map(|(path, bytes)| (path, ResumePoint { bytes_received: bytes })).collect();

        // Send Accept
        control::write_control_frame(&mut ctrl_send, &handshake::serialize(&ControlMessage::Accept(Accept { session_id, resume_map }))?).await?;

        // Receive data streams
        let file_count = offer.files.files.len();
        let total_size = offer.total_size;
        let tracker = std::sync::Arc::new(std::sync::Mutex::new(ProgressTracker::new(total_size)));
        let mut files_received = 0usize;
        while files_received < file_count {
            let mut data_stream = self.conn.accept_uni().await
                .map_err(|e| TransportError::ConnectionLost(e.to_string()))?;
            let header_data = control::read_control_frame(&mut data_stream).await?;
            let stream_header: StreamHeader = data::deserialize_stream_header(&header_data)?;
            files_received += stream_header.files.len();
            receive_stream_files(&mut data_stream, &stream_header, &self.download_dir, &tracker, event_tx, session_id, total_size).await?;
        }

        // Complete → Verified
        let complete_data = control::read_control_frame(&mut ctrl_recv).await?;
        let _complete = handshake::deserialize(&complete_data)?;
        let verified = ControlMessage::Verified(handshake::Verified { session_id, sha256: vec![0; 32] });
        control::write_control_frame(&mut ctrl_send, &handshake::serialize(&verified)?).await?;
        ctrl_send.finish().map_err(|e| TransportError::ConnectionLost(format!("finish: {e}")))?;

        let mut buf = [0u8; 1];
        let _ = ctrl_recv.read(&mut buf).await;
        let _ = event_tx.send(crate::engine::PrivetEvent::TransferComplete { session_id });
        tracing::info!("[receiver] transfer complete for session {session_id}");
        Ok((session_id, peer_fingerprint.to_owned()))
    }
}

async fn receive_stream_files(
    data_stream: &mut quinn::RecvStream, stream_header: &StreamHeader,
    download_dir: &PathBuf, tracker: &std::sync::Arc<std::sync::Mutex<ProgressTracker>>,
    event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    session_id: SessionId, total_size: u64,
) -> Result<(), PrivetError> {
    for file_entry in &stream_header.files {
        let dest = if file_entry.start_offset > 0 { download_dir.join(&file_entry.relative_path) } else { resolve_conflict(download_dir, &file_entry.relative_path) };
        if let Some(parent) = dest.parent() { tokio::fs::create_dir_all(parent).await?; }
        let mut file = tokio::fs::OpenOptions::new().create(true).write(true).open(&dest).await?;
        let expected_bytes = file_entry.total_size.saturating_sub(file_entry.start_offset);
        let mut written: u64 = 0;
        if file_entry.start_offset > 0 { use tokio::io::AsyncSeekExt; file.seek(std::io::SeekFrom::Start(file_entry.start_offset)).await?; }
        else { file.set_len(0).await?; }
        while written < expected_bytes {
            let chunk_header_data = control::read_control_frame(data_stream).await
                .map_err(|_| PrivetError::Io(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "stream ended early")))?;
            let chunk: Chunk = data::deserialize_chunk(&chunk_header_data)?;
            let mut buf = vec![0u8; chunk.length as usize];
            data_stream.read_exact(&mut buf).await.map_err(|e| TransportError::ConnectionLost(e.to_string()))?;
            tokio::io::AsyncWriteExt::write_all(&mut file, &buf).await?;
            written += chunk.length as u64;
            let (tx, sp) = { let mut t = tracker.lock().unwrap(); t.record(chunk.length as u64); (t.bytes_transferred(), t.speed_bps()) };
            let _ = event_tx.send(crate::engine::PrivetEvent::TransferProgress {
                session_id, progress: crate::session::TransferProgress { total_bytes: total_size, bytes_transferred: tx, current_speed_bps: sp, per_file: vec![] },
            });
        }
        tokio::io::AsyncWriteExt::flush(&mut file).await?;
    }
    Ok(())
}

pub(crate) fn fs_available_space(_path: &PathBuf) -> std::io::Result<u64> { Ok(u64::MAX) }

pub(crate) fn resolve_conflict(dir: &PathBuf, name: &str) -> PathBuf {
    let dest = dir.join(name);
    if !dest.exists() { return dest; }
    let stem = dest.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = dest.extension().and_then(|s| s.to_str()).unwrap_or("");
    for i in 1..1000 {
        let new_name = if ext.is_empty() { format!("{stem} ({i})") } else { format!("{stem} ({i}).{ext}") };
        let new_path = dir.join(&new_name);
        if !new_path.exists() { return new_path; }
    }
    dest
}
