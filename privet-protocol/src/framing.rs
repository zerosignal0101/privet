
use bytes::{Bytes, BytesMut};
use prost::Message;

use crate::constants::MAX_CONTROL_FRAME_BYTES;
use crate::error::FrameError;
use crate::varint::{decode_varint, encode_varint, varint_len};
use crate::{ChunkHeader, ControlFrame, DataFrame};

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

pub fn decode_data_frame(buf: &mut &[u8]) -> Result<DataFrame, FrameError> {
    let len = decode_varint(buf)? as usize;
    if buf.len() < len {
        return Err(FrameError::UnexpectedEof);
    }
    let (data, rest) = buf.split_at(len);
    *buf = rest;
    DataFrame::decode(data).map_err(FrameError::Decode)
}

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


pub const CONTROL_STREAM_ID: u8 = 0;
pub const DATA_STREAM_ID: u8 = 1;

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
