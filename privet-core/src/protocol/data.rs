use serde::{Deserialize, Serialize};

/// Header at the start of each data stream, identifying which files are carried.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamHeader {
    /// Number of files in this stream.
    pub file_count: u16,
    /// Per-file descriptors.
    pub files: Vec<StreamFileEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamFileEntry {
    /// Relative path of the file.
    pub relative_path: String,
    /// Byte offset to start from (0 for fresh, >0 for resume).
    pub start_offset: u64,
    /// Total size of the file.
    pub total_size: u64,
}

/// A single data chunk within a stream.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Chunk {
    /// Index into the stream header's file list.
    pub path_index: u16,
    /// Byte offset within the file.
    pub offset: u64,
    /// Length of the data payload following this header.
    pub length: u32,
}

/// Maximum number of small files to multiplex on a single stream.
pub const MAX_MULTIPLEXED_FILES: u16 = 16;
/// Size threshold for "small file" multiplexing.
pub const SMALL_FILE_THRESHOLD: u64 = 64 * 1024; // 64 KB

/// Serialize a stream header using postcard.
pub fn serialize_stream_header(header: &StreamHeader) -> Result<Vec<u8>, crate::error::ProtocolError> {
    postcard::to_allocvec(header)
        .map_err(|e| crate::error::ProtocolError::Serialization(e.to_string()))
}

/// Deserialize a stream header.
pub fn deserialize_stream_header(data: &[u8]) -> Result<StreamHeader, crate::error::ProtocolError> {
    postcard::from_bytes(data)
        .map_err(|e| crate::error::ProtocolError::InvalidMessage(e.to_string()))
}

/// Serialize a chunk header using postcard.
pub fn serialize_chunk(chunk: &Chunk) -> Result<Vec<u8>, crate::error::ProtocolError> {
    postcard::to_allocvec(chunk)
        .map_err(|e| crate::error::ProtocolError::Serialization(e.to_string()))
}

/// Deserialize a chunk header.
pub fn deserialize_chunk(data: &[u8]) -> Result<Chunk, crate::error::ProtocolError> {
    postcard::from_bytes(data)
        .map_err(|e| crate::error::ProtocolError::InvalidMessage(e.to_string()))
}
