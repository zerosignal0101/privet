use std::path::PathBuf;

use tokio::sync::mpsc;

use crate::error::{PrivetError, TransportError};
use crate::protocol::control;
use crate::protocol::data::{self, Chunk, StreamFileEntry, StreamHeader};
use crate::protocol::handshake::{self, ControlMessage, Hello, Offer};
use crate::session::{FileManifest, SessionId};
use crate::transfer::progress::ProgressTracker;

/// Send files to a peer over an established QUIC connection.
pub struct Sender {
    conn: quinn::Connection,
    chunk_size: u32,
}

impl Sender {
    pub fn new(conn: quinn::Connection, chunk_size: u32) -> Self {
        Self { conn, chunk_size }
    }

    /// Execute the full send flow: handshake → offer → send data.
    pub async fn send(
        &self,
        files: &[PathBuf],
        event_tx: &mpsc::UnboundedSender<crate::engine::PrivetEvent>,
    ) -> Result<SessionId, PrivetError> {
        let session_id = SessionId::new();

        // 1. Open control stream
        tracing::debug!("[sender] opening control stream");
        let (mut ctrl_send, mut ctrl_recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| TransportError::ConnectionLost(format!("step1: {e}")))?;

        // 2. Send Hello
        tracing::debug!("[sender] sending Hello");
        let hello = ControlMessage::Hello(Hello {
            version: handshake::PROTOCOL_VERSION,
            device_name: String::new(),
            platform: std::env::consts::OS.to_owned(),
            fingerprint: String::new(),
        });
        let hello_data = handshake::serialize(&hello)?;
        control::write_control_frame(&mut ctrl_send, &hello_data)
            .await
            .map_err(|e| TransportError::ConnectionLost(format!("step2: {e}")))?;

        // 3. Receive HelloAck
        tracing::debug!("[sender] reading HelloAck");
        let ack_data = control::read_control_frame(&mut ctrl_recv)
            .await
            .map_err(|e| TransportError::ConnectionLost(format!("step3: {e}")))?;
        let ack_msg = handshake::deserialize(&ack_data)?;
        let _hello_ack = match ack_msg {
            ControlMessage::HelloAck(ack) => ack,
            other => {
                return Err(crate::error::ProtocolError::UnexpectedMessage {
                    expected: "HelloAck".into(),
                    got: format!("{other:?}"),
                }
                .into());
            }
        };

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

        // 6. Send files as data streams
        let mut tracker = ProgressTracker::new(manifest.total_size);

        for (_i, file_entry) in manifest.files.iter().enumerate() {
            let resume_offset = accept
                .resume_map
                .get(&file_entry.relative_path)
                .map(|r| r.bytes_received)
                .unwrap_or(0);

            let stream_header = StreamHeader {
                file_count: 1,
                files: vec![StreamFileEntry {
                    relative_path: file_entry.relative_path.clone(),
                    start_offset: resume_offset,
                    total_size: file_entry.size,
                }],
            };

            tracing::debug!("[sender] opening data stream for {}", file_entry.relative_path);
            let mut data_stream = self.conn.open_uni().await
                .map_err(|e| TransportError::ConnectionLost(format!("step6-open: {e}")))?;

            // Write stream header
            let header_bytes = data::serialize_stream_header(&stream_header)?;
            control::write_control_frame(&mut data_stream, &header_bytes)
                .await
                .map_err(|e| TransportError::ConnectionLost(format!("step6-header: {e}")))?;

            // Send file data in chunks
            let file_path = files
                .iter()
                .find(|p| {
                    p.file_name()
                        .map(|n| n.to_string_lossy() == file_entry.relative_path)
                        .unwrap_or(false)
                })
                .ok_or_else(|| PrivetError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("file not found: {}", file_entry.relative_path),
                )))?;

            let mut file = tokio::fs::File::open(file_path).await?;
            if resume_offset > 0 {
                use tokio::io::AsyncSeekExt;
                file.seek(std::io::SeekFrom::Start(resume_offset)).await?;
            }

            let mut buf = vec![0u8; self.chunk_size as usize];
            let mut offset = resume_offset;

            loop {
                let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf).await?;
                if n == 0 {
                    break;
                }

                let chunk = Chunk {
                    path_index: 0,
                    offset,
                    length: n as u32,
                };
                let chunk_header = data::serialize_chunk(&chunk)?;
                control::write_control_frame(&mut data_stream, &chunk_header)
                    .await
                    .map_err(|e| TransportError::ConnectionLost(format!("step6-chunk-header: {e}")))?;
                data_stream
                    .write_all(&buf[..n])
                    .await
                    .map_err(|e| TransportError::ConnectionLost(format!("step6-data: {e}")))?;

                offset += n as u64;
                tracker.record(n as u64);

                let _ = event_tx.send(crate::engine::PrivetEvent::TransferProgress {
                    session_id,
                    progress: crate::session::TransferProgress {
                        total_bytes: manifest.total_size,
                        bytes_transferred: tracker.bytes_transferred(),
                        current_speed_bps: tracker.speed_bps(),
                        per_file: vec![],
                    },
                });
            }

            tracing::debug!("[sender] finishing data stream");
            data_stream
                .finish()
                .map_err(|e| TransportError::ConnectionLost(format!("step6-finish: {e}")))?;
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
        // This signals the receiver that we received Verified, so it can safely exit.
        ctrl_send
            .finish()
            .map_err(|e| TransportError::ConnectionLost(format!("step9-finish: {e}")))?;
        self.conn.close(0u32.into(), b"done");

        tracing::info!("[sender] transfer complete for session {session_id}");
        let _ = event_tx.send(crate::engine::PrivetEvent::TransferComplete { session_id });

        Ok(session_id)
    }
}
