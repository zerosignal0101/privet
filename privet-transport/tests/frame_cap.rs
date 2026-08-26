//! DoS/OOM guard: oversized frames/chunks are rejected before allocation.

use async_trait::async_trait;
use bytes::BytesMut;
use privet_transport::transport::Stream;
use privet_transport::TransportError;
use privet_transport::{recv_control, recv_data};

struct MemStream {
    buf: Vec<u8>,
    pos: usize,
}

#[async_trait]
impl Stream for MemStream {
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
async fn oversized_control_frame_rejected() {
    // Encode a varint for 5 MiB, then 0 bytes of payload
    let evil = privet_protocol::varint::encode_varint(5 * 1024 * 1024 + 1);
    let mut s = MemStream { buf: evil, pos: 0 };
    let err = recv_control(&mut s).await.unwrap_err();
    assert!(matches!(err, TransportError::TooLarge));
}

#[tokio::test]
async fn oversized_chunk_length_rejected() {
    use privet_protocol::data_frame::Payload as DPayload;
    use privet_protocol::{ChunkHeader, DataFrame};

    let h = ChunkHeader {
        file_id: "f".into(),
        segment_id: 0,
        chunk_index: 0,
        offset: 0,
        length: 5 * 1024 * 1024, // 5 MiB > DEFAULT_CHUNK_SIZE
    };
    let df = DataFrame {
        payload: Some(DPayload::ChunkHeader(h)),
    };
    let mut s = MemStream {
        buf: Vec::new(),
        pos: 0,
    };
    s.buf.extend_from_slice(&privet_protocol::framing::encode_data(&df, None));
    s.pos = 0;
    let err = recv_data(&mut s).await.unwrap_err();
    assert!(matches!(err, TransportError::TooLarge));
}
