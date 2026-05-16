use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio_rustls::rustls;

use crate::error::TransportError;

/// Wraps a Quinn connection with privet-specific helpers.
pub struct QuicConnection {
    pub conn: Connection,
}

impl QuicConnection {
    /// Open a bidirectional stream (used for control stream).
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        self.conn
            .open_bi()
            .await
            .map_err(|e| TransportError::ConnectionLost(e.to_string()))
    }

    /// Open a unidirectional stream (used for data streams).
    pub async fn open_uni(&self) -> Result<SendStream, TransportError> {
        self.conn
            .open_uni()
            .await
            .map_err(|e| TransportError::ConnectionLost(e.to_string()))
    }

    /// Accept an incoming bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        self.conn
            .accept_bi()
            .await
            .map_err(|e| TransportError::ConnectionLost(e.to_string()))
    }

    /// Accept an incoming unidirectional stream.
    pub async fn accept_uni(&self) -> Result<RecvStream, TransportError> {
        self.conn
            .accept_uni()
            .await
            .map_err(|e| TransportError::ConnectionLost(e.to_string()))
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    pub fn local_ip(&self) -> Option<std::net::IpAddr> {
        self.conn.local_ip()
    }
}

/// Connect to a peer at the given address.
pub async fn connect(
    endpoint: &Endpoint,
    addr: SocketAddr,
    server_name: &str,
    _client_config: Arc<rustls::ClientConfig>,
) -> Result<QuicConnection, TransportError> {
    let connect = endpoint.connect(addr, server_name)
        .map_err(|e| TransportError::Quic(format!("connect: {e}")))?;

    let conn = connect
        .await
        .map_err(|e| TransportError::Quic(format!("handshake: {e}")))?;

    Ok(QuicConnection { conn })
}
