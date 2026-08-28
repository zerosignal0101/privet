
use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use privet_protocol::error::FrameError;
use privet_protocol::{ControlFrame, DataFrame};
use privet_transport::frame_io::{send_control, send_data};
use privet_transport::Stream;
use prost::Message;

use crate::error::{Result, TransferError};

// Frames are assembled from a retained buffer and only consumed once fully buffered,
// so a caller that cancels `recv()` (e.g. a timeout while waiting on a slow chunk)
// never loses the bytes already read off the stream. Refills read exactly the amount
// still missing, keeping progress small-grained enough for short caller timeouts.
const MAX_CONTROL_FRAME_BYTES: usize = privet_protocol::constants::MAX_CONTROL_FRAME_BYTES;
const DEFAULT_CHUNK_SIZE: usize = privet_protocol::constants::DEFAULT_CHUNK_SIZE;

pub struct StreamControlChannel {
    inner: Box<dyn Stream>,
    buf: BytesMut,
}
impl StreamControlChannel {
    pub fn new(inner: Box<dyn Stream>) -> Self {
        Self {
            inner,
            buf: BytesMut::new(),
        }
    }
}
#[async_trait]
impl crate::ControlChannel for StreamControlChannel {
    async fn send(&mut self, frame: ControlFrame) -> Result<()> {
        send_control(self.inner.as_mut(), &frame)
            .await
            .map_err(map_te)
    }
    async fn recv(&mut self) -> Result<ControlFrame> {
        loop {
            match parse_control_frame(&self.buf) {
                ParseControl::Ready(frame, used) => {
                    self.buf.advance(used);
                    return Ok(frame);
                }
                ParseControl::NeedMore(n) => {
                    let chunk = self.inner.recv_exact(n).await.map_err(map_te)?;
                    self.buf.extend_from_slice(&chunk);
                }
                ParseControl::Malformed(e) => return Err(e),
            }
        }
    }
}

pub struct StreamDataChannel {
    inner: Box<dyn Stream>,
    buf: BytesMut,
}
impl StreamDataChannel {
    pub fn new(inner: Box<dyn Stream>) -> Self {
        Self {
            inner,
            buf: BytesMut::new(),
        }
    }
}
#[async_trait]
impl crate::DataChannel for StreamDataChannel {
    async fn send(&mut self, frame: DataFrame, raw: Option<&[u8]>) -> Result<()> {
        send_data(self.inner.as_mut(), &frame, raw)
            .await
            .map_err(map_te)
    }
    async fn recv(&mut self) -> Result<(DataFrame, Option<BytesMut>)> {
        loop {
            match parse_data_frame(&self.buf) {
                ParseData::Ready(frame, raw, used) => {
                    self.buf.advance(used);
                    return Ok((frame, raw));
                }
                ParseData::NeedMore(n) => {
                    let chunk = self.inner.recv_exact(n).await.map_err(map_te)?;
                    self.buf.extend_from_slice(&chunk);
                }
                ParseData::Malformed(e) => return Err(e),
            }
        }
    }
}

enum ParseControl {
    Ready(ControlFrame, usize),
    NeedMore(usize),
    Malformed(TransferError),
}

fn parse_control_frame(buf: &[u8]) -> ParseControl {
    let mut varint_slice: &[u8] = buf;
    let body_len = match privet_protocol::varint::decode_varint(&mut varint_slice) {
        Ok(l) => l as usize,
        Err(FrameError::UnexpectedEof) => return ParseControl::NeedMore(1),
        Err(e) => return ParseControl::Malformed(frame_err(e)),
    };
    let header_end = buf.len() - varint_slice.len();
    if body_len > MAX_CONTROL_FRAME_BYTES {
        return ParseControl::Malformed(TransferError::Transport(
            "control frame too large".into(),
        ));
    }
    if buf.len() - header_end < body_len {
        return ParseControl::NeedMore(header_end + body_len - buf.len());
    }
    match ControlFrame::decode(&buf[header_end..header_end + body_len]) {
        Ok(frame) => ParseControl::Ready(frame, header_end + body_len),
        Err(e) => ParseControl::Malformed(TransferError::Transport(e.to_string())),
    }
}

enum ParseData {
    Ready(DataFrame, Option<BytesMut>, usize),
    NeedMore(usize),
    Malformed(TransferError),
}

fn parse_data_frame(buf: &[u8]) -> ParseData {
    let mut varint_slice: &[u8] = buf;
    let body_len = match privet_protocol::varint::decode_varint(&mut varint_slice) {
        Ok(l) => l as usize,
        Err(FrameError::UnexpectedEof) => return ParseData::NeedMore(1),
        Err(e) => return ParseData::Malformed(frame_err(e)),
    };
    let header_end = buf.len() - varint_slice.len();
    if buf.len() - header_end < body_len {
        return ParseData::NeedMore(header_end + body_len - buf.len());
    }
    let frame = match DataFrame::decode(&buf[header_end..header_end + body_len]) {
        Ok(f) => f,
        Err(e) => return ParseData::Malformed(TransferError::Transport(e.to_string())),
    };
    match &frame.payload {
        Some(privet_protocol::data_frame::Payload::ChunkHeader(h)) => {
            let raw_len = h.length as usize;
            if raw_len > DEFAULT_CHUNK_SIZE {
                return ParseData::Malformed(TransferError::Transport("chunk too large".into()));
            }
            let total = header_end + body_len + raw_len;
            if buf.len() < total {
                return ParseData::NeedMore(total - buf.len());
            }
            let raw = BytesMut::from(&buf[header_end + body_len..total]);
            ParseData::Ready(frame, Some(raw), total)
        }
        _ => ParseData::Ready(frame, None, header_end + body_len),
    }
}

fn frame_err(e: FrameError) -> TransferError {
    TransferError::Transport(e.to_string())
}

fn map_te(e: privet_transport::TransportError) -> TransferError {
    use privet_transport::TransportError as TE;
    // The peer issuing STOP_SENDING on our stream is a deliberate abort (the
    // receiver does exactly that when it cancels mid-transfer), NOT a resumable
    // transport loss — reconnecting would re-send the whole transfer after a
    // cancel. `run_sender` turns this into a proper Cancelled outcome.
    if e.is_peer_stream_stopped() {
        return TransferError::Aborted("peer stopped data stream".into());
    }
    let resumable = matches!(
        &e,
        TE::Closed(_) | TE::Quic(_) | TE::QuicRead(_) | TE::QuicReadExact(_) | TE::QuicWrite(_)
    );
    if resumable {
        tracing::warn!(error = ?e, "transport stream error -> TransportLost (resumable)");
    } else {
        tracing::debug!(error = ?e, "transport stream error (non-resumable)");
    }
    match e {
        TE::Closed(_) | TE::Quic(_) | TE::QuicRead(_) | TE::QuicReadExact(_) | TE::QuicWrite(_) => {
            TransferError::TransportLost
        }
        other => TransferError::Transport(other.to_string()),
    }
}
