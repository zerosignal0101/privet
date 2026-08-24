//! 帧编解码：控制流

use bytes::{Bytes, BytesMut};
use prost::Message;

use crate::constants::MAX_CONTROL_FRAME_BYTES;
use crate::error::FrameError;
use crate::varint::{decode_varint, encode_varint, varint_len};
use crate::{ChunkHeader, ControlFrame, DataFrame};

/// 编码控制流帧：`[varint_len][ControlFrame]`。
pub fn encode_control(msg: &ControlFrame) -> Result<Bytes, FrameError> {
    let body = msg.encode_to_vec();
    if body.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let mut out = BytesMut::with_capacity(varint_len(body.len() as u64) + body.len());
    out.extend_from_slice(&encode_varint(body.len() as u64));
    out.extend_from_slice(&body);
    Ok(out.freeze())
}

/// 从 `buf` 前缀解码一帧控制流消息，推进切片。
pub fn decode_control(buf: &mut &[u8]) -> Result<ControlFrame, FrameError> {
    let len = decode_varint(buf)? as usize;
    if len > MAX_CONTROL_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    if buf.len() < len {
        return Err(FrameError::UnexpectedEof);
    }
    let (data, rest) = buf.split_at(len);
    *buf = rest;
    ControlFrame::decode(data).map_err(FrameError::Decode)
}

/// 编码数据流帧：`[varint_len][DataFrame][? raw bytes]`。
/// 若 `Some(raw)`，则 raw 紧随 DataFrame 之后（零拷贝友好）。
pub fn encode_data(frame: &DataFrame, raw: Option<&[u8]>) -> Bytes {
    let body = frame.encode_to_vec();
    let raw_len = raw.map(|r| r.len()).unwrap_or(0);
    let mut out = BytesMut::with_capacity(varint_len(body.len() as u64) + body.len() + raw_len);
    out.extend_from_slice(&encode_varint(body.len() as u64));
    out.extend_from_slice(&body);
    if let Some(r) = raw {
        out.extend_from_slice(r);
    }
    out.freeze()
}

/// 解码数据流帧的 DataFrame 部分（不含后续 raw 字节），推进切片。
/// 调用方随后用 `read_raw_after_chunk` 读取 `ChunkHeader.length` 字节 raw。
pub fn decode_data_frame(buf: &mut &[u8]) -> Result<DataFrame, FrameError> {
    let len = decode_varint(buf)? as usize;
    if buf.len() < len {
        return Err(FrameError::UnexpectedEof);
    }
    let (data, rest) = buf.split_at(len);
    *buf = rest;
    DataFrame::decode(data).map_err(FrameError::Decode)
}

/// 读取 `header.length` 字节 raw 数据（ChunkHeader 后跟随的块字节），推进切片。
pub fn read_raw_after_chunk<'a>(
    buf: &mut &'a [u8],
    header: &ChunkHeader,
) -> Result<&'a [u8], FrameError> {
    let n = header.length as usize;
    if buf.len() < n {
        return Err(FrameError::UnexpectedEof);
    }
    let (data, rest) = buf.split_at(n);
    *buf = rest;
    Ok(data)
}

// ===== TCP 多路帧 =====

pub const CONTROL_STREAM_ID: u8 = 0;
pub const DATA_STREAM_ID: u8 = 1;

/// 编码 TCP 多路帧：`[stream_id: varint][varint_len][payload]`。
/// `stream_id` 必须为 0（控制）或 1（数据）。
pub fn encode_tcp_frame(stream_id: u8, payload: &[u8]) -> Result<Bytes, FrameError> {
    if stream_id > 1 {
        return Err(FrameError::InvalidStreamId);
    }
    let mut out = BytesMut::with_capacity(
        varint_len(stream_id as u64) + varint_len(payload.len() as u64) + payload.len(),
    );
    out.extend_from_slice(&encode_varint(stream_id as u64));
    out.extend_from_slice(&encode_varint(payload.len() as u64));
    out.extend_from_slice(payload);
    Ok(out.freeze())
}

/// 解码 TCP 多路帧，返回 (stream_id, payload)。推进 `buf`。
/// 返回的 payload 切片借用自 `buf` 原始缓冲。
pub fn decode_tcp_frame<'a>(buf: &mut &'a [u8]) -> Result<(u8, &'a [u8]), FrameError> {
    let sid = decode_varint(buf)?;
    if sid > 1 {
        return Err(FrameError::InvalidStreamId);
    }
    let len = decode_varint(buf)? as usize;
    if buf.len() < len {
        return Err(FrameError::UnexpectedEof);
    }
    let (data, rest) = buf.split_at(len);
    *buf = rest;
    Ok((sid as u8, data))
}
