use std::net::SocketAddr;

use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::TransportError;

/// Simple length-prefixed framing over TCP for fallback when UDP is blocked.
/// Frame format: [4-byte length (big-endian)] [2-byte stream_id] [payload]
const FRAME_HEADER_SIZE: usize = 6;

/// Connect to a peer via TCP fallback.
pub async fn connect_tcp(addr: SocketAddr) -> Result<TcpStream, TransportError> {
    TcpStream::connect(addr)
        .await
        .map_err(|e| TransportError::TcpFallback(format!("connect: {e}")))
}

/// Write a framed message to any async read+write stream (TcpStream or TLS stream).
pub async fn write_frame<S>(
    stream: &mut S,
    stream_id: u16,
    data: &[u8],
) -> Result<(), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let len = data.len() as u32;
    let mut header = [0u8; FRAME_HEADER_SIZE];
    header[0..4].copy_from_slice(&len.to_be_bytes());
    header[4..6].copy_from_slice(&stream_id.to_be_bytes());

    stream
        .write_all(&header)
        .await
        .map_err(|e| TransportError::TcpFallback(format!("write header: {e}")))?;
    stream
        .write_all(data)
        .await
        .map_err(|e| TransportError::TcpFallback(format!("write payload: {e}")))?;

    Ok(())
}

/// Read a framed message from any async read+write stream.
pub async fn read_frame<S>(
    stream: &mut S,
) -> Result<(u16, Vec<u8>), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut header = [0u8; FRAME_HEADER_SIZE];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| TransportError::TcpFallback(format!("read header: {e}")))?;

    let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let stream_id = u16::from_be_bytes([header[4], header[5]]);

    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|e| TransportError::TcpFallback(format!("read payload: {e}")))?;

    Ok((stream_id, payload))
}
