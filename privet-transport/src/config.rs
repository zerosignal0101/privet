
use std::time::Duration;

use crate::constants::{CONNECTION_IDLE_TIMEOUT, STREAM_POOL_SIZE};
use privet_protocol::constants::{QUIC_PORT, TCP_PORT};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Quic,
    Tcp,
    PreferQuic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Congestion {
    Bbr,
    Cubic,
}

#[derive(Debug, Clone)]
pub struct TransportConfigPrivet {
    pub mode: TransportMode,
    pub quic_port: u16,
    pub tcp_port: u16,
    pub stream_pool_size: usize,
    pub congestion: Congestion,
    pub idle_timeout: Duration,
    pub pairing_exporter: Option<PairingExporterLabel>,
}

#[derive(Debug, Clone)]
pub struct PairingExporterLabel {
    pub label: Vec<u8>,
    pub context: Vec<u8>,
}

impl Default for TransportConfigPrivet {
    fn default() -> Self {
        Self {
            mode: TransportMode::PreferQuic,
            quic_port: QUIC_PORT,
            tcp_port: TCP_PORT,
            stream_pool_size: STREAM_POOL_SIZE,
            congestion: Congestion::Bbr,
            idle_timeout: CONNECTION_IDLE_TIMEOUT,
            pairing_exporter: None,
        }
    }
}
