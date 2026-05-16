use crate::error::TransportError;

/// Length-prefixed framing for control stream messages.
/// Format: [4-byte big-endian length] [postcard-encoded ControlMessage]

/// Write a control frame to a QUIC send stream.
pub async fn write_control_frame(
    send: &mut quinn::SendStream,
    data: &[u8],
) -> Result<(), TransportError> {
    let len = data.len() as u32;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| TransportError::ConnectionLost(e.to_string()))?;
    send.write_all(data)
        .await
        .map_err(|e| TransportError::ConnectionLost(e.to_string()))?;
    Ok(())
}

/// Read a control frame from a QUIC recv stream.
pub async fn read_control_frame(
    recv: &mut quinn::RecvStream,
) -> Result<Vec<u8>, TransportError> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| TransportError::ConnectionLost(e.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Sanity check: control messages should never be huge
    if len > 1024 * 1024 {
        return Err(TransportError::ConnectionLost("frame too large".into()));
    }
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload)
        .await
        .map_err(|e| TransportError::ConnectionLost(e.to_string()))?;
    Ok(payload)
}
