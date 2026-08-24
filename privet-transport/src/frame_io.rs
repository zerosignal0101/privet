//! 在抽象 Stream 上收发帧（复用 privet-protocol framing）。

use bytes::BytesMut;
use privet_protocol::framing;
use privet_protocol::{ControlFrame, DataFrame};

use crate::transport::Stream;
use crate::TransportError;
use privet_protocol::constants::{DEFAULT_CHUNK_SIZE, MAX_CONTROL_FRAME_BYTES};

/// 发送控制帧：`[varint_len][ControlFrame]`。
pub async fn send_control(s: &mut dyn Stream, msg: &ControlFrame) -> Result<(), TransportError> {
    let bytes = framing::encode_control(msg)?;
    s.send_all(&bytes).await
}

/// 读 varint 长度前缀后接 body，返回完整帧 `[varint][body]`。
async fn recv_raw_frame(s: &mut dyn Stream) -> Result<BytesMut, TransportError> {
    let mut varint_buf = [0u8; 10];
    let mut varint_len = 0;
    for (i, slot) in varint_buf.iter_mut().enumerate() {
        let b = s.recv_exact(1).await?;
        *slot = b[0];
        varint_len = i + 1;
        if b[0] & 0x80 == 0 {
            break;
        }
    }
    let mut tmp: &[u8] = &varint_buf[..varint_len];
    let len = privet_protocol::varint::decode_varint(&mut tmp)? as usize;
    // 帧大小上限防 DoS — before alloc
    if len > MAX_CONTROL_FRAME_BYTES {
        return Err(TransportError::TooLarge);
    }
    let body = s.recv_exact(len).await?;
    let mut raw = BytesMut::with_capacity(varint_len + len);
    raw.extend_from_slice(&varint_buf[..varint_len]);
    raw.extend_from_slice(&body);
    Ok(raw)
}

/// 接收控制帧。
pub async fn recv_control(s: &mut dyn Stream) -> Result<ControlFrame, TransportError> {
    let raw = recv_raw_frame(s).await?;
    let mut rs: &[u8] = &raw;
    let frame = framing::decode_control(&mut rs)?;
    Ok(frame)
}

/// 发送数据帧 `[varint_len][DataFrame][? raw bytes]`。
pub async fn send_data(
    s: &mut dyn Stream,
    frame: &DataFrame,
    raw: Option<&[u8]>,
) -> Result<(), TransportError> {
    let bytes = framing::encode_data(frame, raw);
    s.send_all(&bytes).await
}

/// 收数据帧：(DataFrame, Option<Chunk raw bytes>)。
pub async fn recv_data(
    s: &mut dyn Stream,
) -> Result<(DataFrame, Option<BytesMut>), TransportError> {
    let raw = recv_raw_frame(s).await?;
    let mut rs: &[u8] = &raw;
    let frame = framing::decode_data_frame(&mut rs)?;
    match &frame.payload {
        Some(privet_protocol::data_frame::Payload::ChunkHeader(h)) => {
            // 块大小上限防 OOM — before recv_exact
            if h.length > DEFAULT_CHUNK_SIZE as u64 {
                return Err(TransportError::TooLarge);
            }
            let raw_body = s.recv_exact(h.length as usize).await?;
            Ok((frame, Some(raw_body)))
        }
        _ => Ok((frame, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Stream;
    use crate::TransportError;
    use async_trait::async_trait;
    use bytes::BytesMut;

    struct LoopbackStream {
        buf: Vec<u8>,
        pos: usize,
    }

    #[async_trait]
    impl Stream for LoopbackStream {
        async fn send_all(&mut self, buf: &[u8]) -> Result<(), TransportError> {
            self.buf.extend_from_slice(buf);
            Ok(())
        }
        async fn recv_exact(&mut self, n: usize) -> Result<BytesMut, TransportError> {
            if self.buf.len() - self.pos < n {
                return Err(TransportError::Closed("eof".into()));
            }
            let mut out = BytesMut::zeroed(n);
            out.copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            Ok(out)
        }
        async fn reset(self: Box<Self>, _code: u32) {}
    }

    #[tokio::test]
    async fn control_roundtrip() {
        let mut s = Box::new(LoopbackStream {
            buf: Vec::new(),
            pos: 0,
        }) as Box<dyn Stream>;
        let msg = privet_protocol::ControlFrame {
            payload: Some(privet_protocol::control_frame::Payload::Control(
                privet_protocol::ControlMessage {
                    msg: Some(privet_protocol::control_message::Msg::Cancel(
                        privet_protocol::Cancel {
                            transfer_id: "t1".into(),
                            reason: "user".into(),
                        },
                    )),
                },
            )),
        };
        send_control(s.as_mut(), &msg).await.unwrap();
        let got = recv_control(s.as_mut()).await.unwrap();
        assert_eq!(got.payload, msg.payload);
    }

    #[tokio::test]
    async fn data_roundtrip_with_raw() {
        let mut s = Box::new(LoopbackStream {
            buf: Vec::new(),
            pos: 0,
        }) as Box<dyn Stream>;
        let df = privet_protocol::DataFrame {
            payload: Some(privet_protocol::data_frame::Payload::ChunkHeader(
                privet_protocol::ChunkHeader {
                    file_id: "f".into(),
                    segment_id: 0,
                    chunk_index: 0,
                    offset: 0,
                    length: 4,
                },
            )),
        };
        let raw = b"abcd";
        send_data(s.as_mut(), &df, Some(raw)).await.unwrap();
        let (got, r) = recv_data(s.as_mut()).await.unwrap();
        assert!(matches!(
            got.payload,
            Some(privet_protocol::data_frame::Payload::ChunkHeader(_))
        ));
        assert_eq!(r.unwrap().as_ref(), b"abcd");
    }
}
