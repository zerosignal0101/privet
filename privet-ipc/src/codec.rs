use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{IpcError, Result};
use crate::protocol::MAX_IPC_MESSAGE_BYTES;

pub async fn read_message<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let length = match reader.read_u32().await {
        Ok(length) => length as usize,
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Err(IpcError::Closed),
        Err(error) => return Err(error.into()),
    };
    if length == 0 || length > MAX_IPC_MESSAGE_BYTES {
        return Err(IpcError::MessageTooLarge);
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

pub async fn write_message<W, T>(writer: &mut W, message: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(message)?;
    if body.is_empty() || body.len() > MAX_IPC_MESSAGE_BYTES {
        return Err(IpcError::MessageTooLarge);
    }
    writer.write_u32(body.len() as u32).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ClientMessage, Request};

    #[tokio::test]
    async fn framed_message_survives_partial_duplex_io() {
        let (mut left, mut right) = tokio::io::duplex(16);
        let expected = ClientMessage::new(Request::Ping);
        let sent = expected.clone();
        let writer = tokio::spawn(async move { write_message(&mut left, &sent).await.unwrap() });
        let received: ClientMessage = read_message(&mut right).await.unwrap();
        writer.await.unwrap();
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_allocation() {
        let (mut left, mut right) = tokio::io::duplex(8);
        left.write_u32((MAX_IPC_MESSAGE_BYTES + 1) as u32).await.unwrap();
        let error = read_message::<_, ClientMessage>(&mut right).await.unwrap_err();
        assert!(matches!(error, IpcError::MessageTooLarge));
    }
}
