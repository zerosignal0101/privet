use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::Duration;

use quinn::{
    congestion::{CubicConfig, NewRenoConfig},
    ClientConfig, Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TokioRuntime,
    TransportConfig, VarInt,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{ClientConfig as RustlsClientConfig, ServerConfig as RustlsServerConfig};

use crate::config::{CongestionControl, TransportConfig as PrivetTransportConfig};
use crate::error::TransportError;

/// Build a Quinn endpoint for server use (incoming connections).
pub fn build_server_endpoint(
    config: &PrivetTransportConfig,
    rustls_server_config: Arc<RustlsServerConfig>,
    listen_addr: SocketAddr,
) -> Result<Endpoint, TransportError> {
    let quic_server_config = QuicServerConfig::try_from(Arc::clone(&rustls_server_config))
        .map_err(|e| TransportError::Quic(format!("server config: {e}")))?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
    let tp_cfg = build_transport_config(config);
    server_config.transport_config(tp_cfg);

    let socket = StdUdpSocket::bind(listen_addr)
        .map_err(|e| TransportError::Quic(format!("bind {listen_addr}: {e}")))?;

    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(TokioRuntime),
    )
    .map_err(|e| TransportError::Quic(format!("create endpoint: {e}")))?;

    Ok(endpoint)
}

/// Build a Quinn endpoint for client use (outgoing connections only).
pub fn build_client_endpoint(
    config: &PrivetTransportConfig,
    client_config: Arc<RustlsClientConfig>,
    listen_addr: SocketAddr,
) -> Result<Endpoint, TransportError> {
    let quic_client_config = QuicClientConfig::try_from(Arc::clone(&client_config))
        .map_err(|e| TransportError::Quic(format!("client config: {e}")))?;

    let mut quic_client = ClientConfig::new(Arc::new(quic_client_config));
    let tp_cfg = build_transport_config(config);
    quic_client.transport_config(tp_cfg);

    let socket = StdUdpSocket::bind(listen_addr)
        .map_err(|e| TransportError::Quic(format!("bind {listen_addr}: {e}")))?;

    let mut endpoint = Endpoint::new(
        EndpointConfig::default(),
        None,
        socket,
        Arc::new(TokioRuntime),
    )
    .map_err(|e| TransportError::Quic(format!("create endpoint: {e}")))?;

    endpoint.set_default_client_config(quic_client);

    Ok(endpoint)
}

/// Build the transport config.
pub fn build_transport_config(config: &PrivetTransportConfig) -> Arc<TransportConfig> {
    let mut tp_cfg = TransportConfig::default();

    tp_cfg
        .max_concurrent_bidi_streams(VarInt::from(config.max_concurrent_bidi_streams))
        .max_concurrent_uni_streams(VarInt::from(config.max_concurrent_uni_streams))
        .send_window(config.send_window)
        .stream_receive_window(VarInt::from_u32(config.receive_window as u32))
        .max_idle_timeout(Some(
            IdleTimeout::try_from(config.idle_timeout)
                .unwrap_or_else(|_| IdleTimeout::try_from(Duration::from_secs(30)).unwrap()),
        ))
        .enable_segmentation_offload(config.enable_gso)
        .mtu_discovery_config(if config.enable_mtu_discovery {
            Some(Default::default())
        } else {
            None
        });

    match config.congestion {
        CongestionControl::Cubic => {
            let mut cubic = CubicConfig::default();
            cubic.initial_window(config.initial_window);
            tp_cfg.congestion_controller_factory(Arc::new(cubic));
        }
        CongestionControl::NewReno => {
            let mut reno = NewRenoConfig::default();
            reno.initial_window(config.initial_window);
            tp_cfg.congestion_controller_factory(Arc::new(reno));
        }
    }

    Arc::new(tp_cfg)
}
