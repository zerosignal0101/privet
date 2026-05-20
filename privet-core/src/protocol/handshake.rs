use serde::{Deserialize, Serialize};

use crate::session::SessionId;

/// Protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// All control-stream messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ControlMessage {
    Hello(Hello),
    HelloAck(HelloAck),
    Offer(Offer),
    Accept(Accept),
    Reject(Reject),
    Progress(Progress),
    Pause(Pause),
    ResumeMsg(Resume),
    Cancel(Cancel),
    Complete(Complete),
    Verified(Verified),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Hello {
    pub version: u8,
    pub device_name: String,
    pub platform: String,
    pub fingerprint: String,
    /// The sender's configured listen port (e.g. 53530) so the receiver can
    /// combine it with the connection's remote IP for known-device discovery.
    /// `None` for backward compatibility with older versions.
    #[serde(default)]
    pub listen_port: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HelloAck {
    pub version: u8,
    pub accepted: bool,
    pub fingerprint: String,
    #[serde(default)]
    pub device_name: String,
    /// The receiver's configured listen port (e.g. 53530) so the sender can
    /// combine it with the connection's remote IP for known-device discovery.
    /// `None` for backward compatibility with older versions.
    #[serde(default)]
    pub listen_port: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Offer {
    pub session_id: SessionId,
    pub files: FileManifestInfo,
    pub total_size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileManifestInfo {
    pub files: Vec<FileInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileInfo {
    pub relative_path: String,
    pub size: u64,
    pub modified_secs: Option<u64>,
    pub sha256: Option<Vec<u8>>,
    pub is_dir: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Accept {
    pub session_id: SessionId,
    pub resume_map: std::collections::HashMap<String, ResumePoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResumePoint {
    pub bytes_received: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reject {
    pub session_id: SessionId,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Progress {
    pub session_id: SessionId,
    pub bytes_acked: u64,
    pub per_file: Vec<(String, u64)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pause {
    pub session_id: SessionId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resume {
    pub session_id: SessionId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cancel {
    pub session_id: SessionId,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Complete {
    pub session_id: SessionId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verified {
    pub session_id: SessionId,
    pub sha256: Vec<u8>,
}

/// Serialize a control message using postcard.
pub fn serialize(msg: &ControlMessage) -> Result<Vec<u8>, crate::error::ProtocolError> {
    postcard::to_allocvec(msg)
        .map_err(|e| crate::error::ProtocolError::Serialization(e.to_string()))
}

/// Deserialize a control message.
pub fn deserialize(data: &[u8]) -> Result<ControlMessage, crate::error::ProtocolError> {
    postcard::from_bytes(data)
        .map_err(|e| crate::error::ProtocolError::InvalidMessage(e.to_string()))
}
