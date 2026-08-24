//! 帧级与路径错误类型。

use thiserror::Error;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("unexpected end of frame")]
    UnexpectedEof,
    #[error("frame exceeds MAX_CONTROL_FRAME_BYTES")]
    TooLarge,
    #[error("varint overflow (max 10 bytes for u64)")]
    VarintOverflow,
    #[error("protobuf decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("invalid stream id")]
    InvalidStreamId,
    #[error("malformed frame")]
    Malformed,
}

#[derive(Debug, Error)]
pub enum PathError {
    #[error("path is empty")]
    Empty,
    #[error("path is absolute")]
    Absolute,
    #[error("path contains parent segment '..'")]
    ParentRef,
    #[error("path contains a drive letter")]
    DriveLetter,
    #[error("path contains a NUL byte")]
    NullByte,
    #[error("path exceeds max depth ({0})")]
    TooDeep(usize),
    #[error("path exceeds max length ({0})")]
    TooLong(usize),
    #[error("root_name must be a single path component")]
    NotSingleComponent,
}
