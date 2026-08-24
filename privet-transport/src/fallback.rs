//! PreferQuic 降级

use std::net::SocketAddr;

use crate::constants::QUIC_CONNECT_TIMEOUT;
use crate::error::{Result, TransportError};
use crate::transport::{Connection, Transport, TransportMode};

/// `quic_port_addr`=QUIC 目标；`tcp_port_addr`=TCP 目标。
pub async fn connect_with_fallback(
    quic: &dyn Transport,
    tcp: Option<&dyn Transport>,
    quic_port_addr: SocketAddr,
    tcp_port_addr: SocketAddr,
    mode: TransportMode,
    bind_source: Option<SocketAddr>,
) -> Result<Box<dyn Connection>> {
    match mode {
        TransportMode::Quic => {
            quic.connect(quic_port_addr, TransportMode::Quic, bind_source)
                .await
        }
        TransportMode::Tcp => {
            let tcp = tcp.ok_or_else(|| TransportError::Unavailable("no tcp transport".into()))?;
            tcp.connect(tcp_port_addr, TransportMode::Tcp, bind_source)
                .await
        }
        TransportMode::PreferQuic => {
            let quic_try = tokio::time::timeout(
                QUIC_CONNECT_TIMEOUT,
                quic.connect(quic_port_addr, TransportMode::Quic, bind_source),
            )
            .await;
            match quic_try {
                Ok(Ok(c)) => {
                    tracing::info!(addr = %quic_port_addr, "quic connected");
                    Ok(c)
                }
                _ => {
                    tracing::warn!(addr = %quic_port_addr, "quic failed, falling back to tcp");
                    let tcp = tcp.ok_or_else(|| {
                        TransportError::Unavailable("quic failed and no tcp fallback".into())
                    })?;
                    tcp.connect(tcp_port_addr, TransportMode::Tcp, bind_source)
                        .await
                }
            }
        }
    }
}
