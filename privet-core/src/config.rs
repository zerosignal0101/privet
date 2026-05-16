use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

const DEFAULT_PORT: u16 = 53530;
const DEFAULT_BEACON_PORT: u16 = 53531;
const DEFAULT_SEND_WINDOW: u64 = 8 * 1024 * 1024; // 8 MB
const DEFAULT_RECEIVE_WINDOW: u64 = 4 * 1024 * 1024; // 4 MB
const DEFAULT_INITIAL_WINDOW: u64 = 1024 * 1024; // 1 MB
const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024; // 64 KB
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivetConfig {
    pub device_name: String,
    pub download_dir: PathBuf,
    pub transport: TransportConfig,
    pub security: SecurityConfig,
    pub discovery: DiscoveryConfig,
    pub auto_accept_trusted: bool,
}

impl PrivetConfig {
    pub fn default_with_name(device_name: String) -> Self {
        let download_dir = dirs::download_dir()
            .or_else(|| dirs::home_dir().map(|h| h.join("Downloads")))
            .unwrap_or_else(|| PathBuf::from("."));

        Self {
            device_name,
            download_dir,
            transport: TransportConfig::default(),
            security: SecurityConfig::default(),
            discovery: DiscoveryConfig::default(),
            auto_accept_trusted: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransportConfig {
    pub listen_port: u16,
    pub congestion: CongestionControl,
    pub send_window: u64,
    pub receive_window: u64,
    pub initial_window: u64,
    pub max_concurrent_bidi_streams: u32,
    pub max_concurrent_uni_streams: u32,
    pub idle_timeout: Duration,
    pub chunk_size: u32,
    pub enable_gso: bool,
    pub enable_mtu_discovery: bool,
    pub handshake_timeout: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            listen_port: DEFAULT_PORT,
            congestion: CongestionControl::Cubic,
            send_window: DEFAULT_SEND_WINDOW,
            receive_window: DEFAULT_RECEIVE_WINDOW,
            initial_window: DEFAULT_INITIAL_WINDOW,
            max_concurrent_bidi_streams: 512,
            max_concurrent_uni_streams: 512,
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
            chunk_size: DEFAULT_CHUNK_SIZE,
            enable_gso: true,
            enable_mtu_discovery: true,
            handshake_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CongestionControl {
    #[default]
    Cubic,
    NewReno,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub cert_dir: Option<PathBuf>,
    pub cert_validity_years: u32,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            cert_dir: None,
            cert_validity_years: 10,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub enable_mdns: bool,
    pub enable_beacon: bool,
    pub beacon_port: u16,
    pub mdns_service_type: String,
    pub scan_timeout: Duration,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enable_mdns: true,
            enable_beacon: true,
            beacon_port: DEFAULT_BEACON_PORT,
            mdns_service_type: "_privet._udp.local.".to_owned(),
            scan_timeout: Duration::from_secs(3),
        }
    }
}
