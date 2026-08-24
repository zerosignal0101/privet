//! 传输配置

use std::time::Duration;

use crate::constants::{CONNECTION_IDLE_TIMEOUT, STREAM_POOL_SIZE};
use privet_protocol::constants::{QUIC_PORT, TCP_PORT};

/// 传输模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// 仅 QUIC。
    Quic,
    /// 仅 TCP（受限网络调试或强制）。
    Tcp,
    /// 默认：QUIC 失败降级 TCP。
    PreferQuic,
}

/// 拥塞控制。
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
    /// 握手期预提取的配对 exporter 标签（core 用 crypto 常量填充；transport 保持 label-agnostic）。
    pub pairing_exporter: Option<PairingExporterLabel>,
}

/// 配对 exporter 标签（core 用 crypto::constants 填充）。
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
