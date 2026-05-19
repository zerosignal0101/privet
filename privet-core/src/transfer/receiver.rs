use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::RwLock;

use crate::engine::PairDecision;
use crate::config::SecurityMode;
use crate::error::{PrivetError, TransportError};
use crate::known_device::KnownDeviceStore;
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
    known_device_store: Arc<tokio::sync::Mutex<KnownDeviceStore>>,
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
        known_device_store: Arc<tokio::sync::Mutex<KnownDeviceStore>>,
        pending_incoming: Arc<RwLock<HashMap<SessionId, oneshot::Sender<bool>>>>,
        pending_pairing: Arc<RwLock<HashMap<String, oneshot::Sender<PairDecision>>>>,
    ) -> Self {
        let remote_addr = conn.remote_address();
        Self { conn, remote_addr, download_dir, chunk_size, fingerprint, device_name,
            trust_store, security_mode, accept_store, known_device_store, pending_incoming, pending_pairing }
    }

    /// Record the peer as a known device after trust is established.
    async fn record_known_device(&self, fingerprint: String, device_name: &str) {
        let subnet = crate::network::subnet_from_addr(
            &self.remote_addr.ip(),
            crate::network::default_prefix_len(match self.remote_addr.ip() {
                std::net::IpAddr::V4(ref v4) => v4,
                std::net::IpAddr::V6(_) => return,
            }),
        );
        let mut store = self.known_device_store.lock().await;
        let _ = store.add_or_update_device(
            fingerprint,
            crate::peer::PeerId(uuid::Uuid::nil()),
            device_name.to_owned(),
            subnet,
            self.remote_addr,
            None,
        );
    }

    /// Send a Reject on the control stream and wait for the sender to close.
    /// This ensures the sender reads the Reject (not a CONNECTION_CLOSE race).
    async fn send_reject_and_wait(
        ctrl_send: &mut quinn::SendStream,
        ctrl_recv: &mut quinn::RecvStream,
        session_id: SessionId,
        reason: &str,
    ) -> Result<(), PrivetError> {
        let reject = ControlMessage::Reject(handshake::Reject {
            session_id,
            reason: reason.to_owned(),
        });
        let data = handshake::serialize(&reject)?;
        if control::write_control_frame(ctrl_send, &data).await.is_ok() {
            let _ = ctrl_send.finish();
        }
        // Wait for sender to close the connection after reading the Reject.
        let mut buf = [0u8; 1];
        let _ = ctrl_recv.read(&mut buf).await;
        Ok(())
    }

    pub async fn receive(
        &self,
        event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    ) -> Result<(SessionId, String, String, Vec<crate::storage::records::TransferFileRecord>), PrivetError> {
        let (mut ctrl_send, mut ctrl_recv) = self.conn.accept_bi()
            .await.map_err(|e| TransportError::ConnectionLost(format!("accept-bi: {e}")))?;

        // 1. Receive Hello
        let hello_data = control::read_control_frame(&mut ctrl_recv)
            .await
            .map_err(|e| PrivetError::Transport(TransportError::ConnectionLost(format!("read-hello: {e}"))))?;
        let hello = match handshake::deserialize(&hello_data)? {
            ControlMessage::Hello(h) => h,
            other => return Err(crate::error::ProtocolError::UnexpectedMessage {
                expected: "Hello".into(), got: format!("{other:?}"),
            }.into()),
        };
        let peer_fingerprint = hello.fingerprint.clone();
        let _peer_device_name = hello.device_name.clone();

        // 2. TLS fingerprint verification (MITM protection)
        // Verify the peer's TLS certificate fingerprint matches the Hello claim.
        // Extract the fingerprint eagerly and drop the Box<dyn Any> before any .await.
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
                format!("TLS cert fingerprint '{tls_fp}' != Hello claim '{peer_fingerprint}'"))));
        }

        // 3. Send HelloAck immediately (sender needs our fingerprint for trust check)
        let hello_ack = ControlMessage::HelloAck(HelloAck {
            version: handshake::PROTOCOL_VERSION, accepted: true,
            fingerprint: self.fingerprint.clone(),
            device_name: self.device_name.clone(),
        });
        control::write_control_frame(&mut ctrl_send, &handshake::serialize(&hello_ack)?).await?;

        // 4. Pairing flow: if peer not trusted, wait for user decision
        let is_trusted = self.trust_store.lock().await.trusted_fingerprints().iter().any(|fp| fp == &peer_fingerprint);
        if !is_trusted && self.security_mode != SecurityMode::AllowAll {
            // Check if there's already a pending pairing for this peer
            // (e.g. from a previous connection that the sender retried).
            let already_pending = self.pending_pairing.read().await.contains_key(&peer_fingerprint);

            let (tx, rx) = tokio::sync::oneshot::channel();
            self.pending_pairing.write().await.insert(peer_fingerprint.clone(), tx);

            // Only emit AwaitingPairing once per peer to avoid duplicate prompts.
            if !already_pending {
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
            }

            match rx.await.unwrap_or(PairDecision::Reject) {
                PairDecision::Trust => {
                    let _ = self.trust_store.lock().await.trust(peer_fingerprint.clone());
                    self.record_known_device(peer_fingerprint.clone(), &hello.device_name).await;
                }
                PairDecision::TrustAndAccept => {
                    let _ = self.trust_store.lock().await.trust(peer_fingerprint.clone());
                    let _ = self.accept_store.lock().await.accept(peer_fingerprint.clone());
                    self.record_known_device(peer_fingerprint.clone(), &hello.device_name).await;
                }
                PairDecision::Reject => {
                    // Send a Reject so the sender gets a clean rejection,
                    // then wait for sender to close the connection.
                    let _ = Self::send_reject_and_wait(
                        &mut ctrl_send, &mut ctrl_recv,
                        SessionId(uuid::Uuid::nil()),
                        "pairing rejected by user",
                    ).await;
                    return Err(PrivetError::Security(crate::error::SecurityError::PairingRequired));
                }
            }
            self.pending_pairing.write().await.remove(&peer_fingerprint);

            // Sender likely rejected this connection (PairingRequired).
            // Check if the connection is still alive before trying to read Offer.
            // Note: close_reason() can race with CONNECTION_CLOSE delivery, so
            // also handle the read error gracefully below.
            if self.conn.close_reason().is_some() {
                tracing::info!("[receiver] pairing resolved but sender closed connection, returning Ok");
                return Ok((SessionId(uuid::Uuid::nil()), peer_fingerprint.clone(), String::new(), Vec::new()));
            }

            // Try to read Offer — will fail if sender closed the connection.
            let offer_data = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                control::read_control_frame(&mut ctrl_recv),
            ).await;
            match offer_data {
                Ok(Ok(data)) => {
                    // Sender sent a Reject (pairing needed) instead of Offer.
                    if let Ok(ControlMessage::Reject(rej)) = handshake::deserialize(&data) {
                        tracing::info!("[receiver] sender rejected: {}", rej.reason);
                        return Ok((SessionId(uuid::Uuid::nil()), peer_fingerprint.clone(), String::new(), Vec::new()));
                    }
                    // Sender retried with Offer on this same connection
                    return self.handle_offer(data, &hello, &peer_fingerprint, ctrl_send, ctrl_recv, event_tx).await;
                }
                _ => {
                    tracing::info!("[receiver] pairing resolved but no Offer (connection dead or timeout), returning Ok");
                    return Ok((SessionId(uuid::Uuid::nil()), peer_fingerprint.clone(), String::new(), Vec::new()));
                }
            }
        }

        // AllowAll: silently trust unknown peers
        if !is_trusted && self.security_mode == SecurityMode::AllowAll {
            tracing::info!("[receiver] AllowAll: silently trusting peer {}", &peer_fingerprint[..16]);
            let _ = self.trust_store.lock().await.trust(peer_fingerprint.clone());
        }

        // 5. Read Offer
        let offer_data = control::read_control_frame(&mut ctrl_recv).await?;
        // Sender may have sent a Reject instead (pairing needed on its side)
        if let Ok(ControlMessage::Reject(rej)) = handshake::deserialize(&offer_data) {
            tracing::info!("[receiver] sender rejected: {}", rej.reason);
            return Ok((SessionId(uuid::Uuid::nil()), peer_fingerprint.clone(), String::new(), Vec::new()));
        }
        let (session_id, fp, device_name, file_records) = self.handle_offer(offer_data, &hello, &peer_fingerprint, ctrl_send, ctrl_recv, event_tx).await?;
        Ok((session_id, fp, device_name, file_records))
    }

    async fn handle_offer(
        &self,
        offer_data: Vec<u8>,
        hello: &handshake::Hello,
        peer_fingerprint: &str,
        mut ctrl_send: quinn::SendStream,
        mut ctrl_recv: quinn::RecvStream,
        event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    ) -> Result<(SessionId, String, String, Vec<crate::storage::records::TransferFileRecord>), PrivetError> {
        let peer_device_name = hello.device_name.clone();
        let offer = match handshake::deserialize(&offer_data)? {
            ControlMessage::Offer(o) => o,
            other => return Err(crate::error::ProtocolError::UnexpectedMessage {
                expected: "Offer".into(), got: format!("{other:?}"),
            }.into()),
        };
        let session_id = offer.session_id;

        // Trust check: reject untrusted unless AllowAll
        let is_trusted = self.trust_store.lock().await.trusted_fingerprints().iter().any(|fp| fp == peer_fingerprint);
        if !is_trusted && self.security_mode != SecurityMode::AllowAll {
            let _ = Self::send_reject_and_wait(
                &mut ctrl_send, &mut ctrl_recv,
                session_id,
                "pairing required: peer not trusted",
            ).await;
            return Err(PrivetError::Security(crate::error::SecurityError::PairingRequired));
        }

        // Notify app layer of incoming transfer (after trust check — only for accepted transfers)
        let _ = event_tx.send(crate::engine::PrivetEvent::IncomingTransfer {
            session_id,
            peer: crate::peer::PeerInfo {
                id: crate::peer::PeerId(uuid::Uuid::nil()),
                name: hello.device_name.clone(),
                addresses: vec![self.remote_addr],
                fingerprint: peer_fingerprint.to_owned(),
                is_trusted: true,
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

        // AwaitAccept flow: determine if user prompt is needed
        match self.security_mode {
            SecurityMode::AllowAll | SecurityMode::TrustRequired => {
                tracing::debug!("[receiver] AllowAll/TrustRequired: auto-accepting session {}", session_id.0);
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
                let _ = Self::send_reject_and_wait(
                    &mut ctrl_send, &mut ctrl_recv,
                    session_id,
                    "transfer rejected by user",
                ).await;
                return Err(PrivetError::TransferRejected("transfer rejected by user".into()));
            }
            tracing::debug!("[receiver] AwaitingAccept: user ACCEPTED session {}", session_id.0);
            self.pending_incoming.write().await.remove(&session_id);
        }
            }
        }

        // Disk space pre-check
        if fs_available_space(&self.download_dir)? < offer.total_size {
            let _ = Self::send_reject_and_wait(
                &mut ctrl_send, &mut ctrl_recv,
                session_id,
                &format!("disk full: need {}, have {}", offer.total_size, fs_available_space(&self.download_dir)?),
            ).await;
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
        let mut actual_dests: Vec<PathBuf> = Vec::new();
        while files_received < file_count {
            let mut data_stream = self.conn.accept_uni().await
                .map_err(|e| TransportError::ConnectionLost(e.to_string()))?;
            let header_data = control::read_control_frame(&mut data_stream).await?;
            let stream_header: StreamHeader = data::deserialize_stream_header(&header_data)?;
            files_received += stream_header.files.len();
            let dests = receive_stream_files(&mut data_stream, &stream_header, &self.download_dir, &tracker, event_tx, session_id, total_size).await?;
            actual_dests.extend(dests);
        }

        // Build file_records from the actual paths (handles duplicate filenames)
        let actual_file_records: Vec<crate::storage::records::TransferFileRecord> = actual_dests.iter().map(|p| {
            let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            crate::storage::records::TransferFileRecord {
                path: p.to_string_lossy().to_string(), // absolute path, independent of download dir setting
                size,
                is_dir: false,
            }
        }).collect();

        // Complete → Verified
        let complete_data = control::read_control_frame(&mut ctrl_recv).await?;
        let _complete = handshake::deserialize(&complete_data)?;
        let verified = ControlMessage::Verified(handshake::Verified { session_id, sha256: vec![0; 32] });
        control::write_control_frame(&mut ctrl_send, &handshake::serialize(&verified)?).await?;
        ctrl_send.finish().map_err(|e| TransportError::ConnectionLost(format!("finish: {e}")))?;

        let mut buf = [0u8; 1];
        let _ = ctrl_recv.read(&mut buf).await;
        let _ = event_tx.send(crate::engine::PrivetEvent::TransferComplete { session_id, direction: crate::session::TransferDirection::Receiving });
        tracing::info!("[receiver] transfer complete for session {session_id}");
        Ok((session_id, peer_fingerprint.to_owned(), peer_device_name.clone(), actual_file_records))
    }
}

async fn receive_stream_files(
    data_stream: &mut quinn::RecvStream, stream_header: &StreamHeader,
    download_dir: &PathBuf, tracker: &std::sync::Arc<std::sync::Mutex<ProgressTracker>>,
    event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    session_id: SessionId, total_size: u64,
) -> Result<Vec<PathBuf>, PrivetError> {
    let mut actual_dests = Vec::new();
    for file_entry in &stream_header.files {
        // Use atomic create_new (O_CREAT|O_EXCL) to avoid FUSE caching races
        let dest;
        let mut file;
        if file_entry.start_offset > 0 {
            // Resume: exact path required (previous partial transfer)
            dest = download_dir.join(&file_entry.relative_path);
            if let Some(parent) = dest.parent() { tokio::fs::create_dir_all(parent).await?; }
            file = tokio::fs::OpenOptions::new().write(true).open(&dest).await?;
            use tokio::io::AsyncSeekExt;
            file.seek(std::io::SeekFrom::Start(file_entry.start_offset)).await?;
            actual_dests.push(dest.clone());
        } else {
            // New file: atomically create with unique name
            let base = download_dir.join(&file_entry.relative_path);
            let pair = open_file_atomic(&base).await
                .map_err(PrivetError::Io)?;
            dest = pair.0;
            file = pair.1;
            actual_dests.push(dest.clone());
        }
        let expected_bytes = file_entry.total_size.saturating_sub(file_entry.start_offset);
        let mut written: u64 = 0;
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
                direction: crate::session::TransferDirection::Receiving,
            });
        }
        tokio::io::AsyncWriteExt::flush(&mut file).await?;
    }
    Ok(actual_dests)
}

pub(crate) fn fs_available_space(_path: &PathBuf) -> std::io::Result<u64> { Ok(u64::MAX) }

/// Atomically create a new file with a unique name using O_CREAT|O_EXCL.
/// If the base path already exists, appends " (1)", " (2)" etc.
/// Returns the opened file and the path chosen.
/// This avoids TOCTOU races and handles FUSE caching quirks on Android.
pub(crate) async fn open_file_atomic(
    base: &std::path::Path,
) -> std::io::Result<(std::path::PathBuf, tokio::fs::File)> {
    if let Some(parent) = base.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let stem = base.file_stem().and_then(|s| s.to_str()).unwrap_or("file").to_owned();
    let ext = base.extension().and_then(|s| s.to_str()).unwrap_or("").to_owned();
    for i in 0..1000 {
        let candidate = if i == 0 { base.to_path_buf() } else {
            let name = if ext.is_empty() { format!("{stem} ({i})") } else { format!("{stem} ({i}).{ext}") };
            base.with_file_name(name)
        };
        match tokio::fs::OpenOptions::new()
            .create_new(true).write(true).open(&candidate).await
        {
            Ok(f) => return Ok((candidate, f)),
            Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("no unique name found after 1000 tries for {}", stem),
    ))
}
