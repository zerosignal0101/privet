//! EngineConfig。
use std::path::PathBuf;
use std::time::Duration;

use privet_security::PairingConfig;
use privet_transfer::TransferEngineConfig;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// 本机设备显示名（beacon Hello 用）。
    pub device_name: String,
    /// 平台串（"linux"/"macos"/"windows"）。
    pub platform: String,
    /// 数据库路径（SQLite）。
    pub db_path: PathBuf,
    /// 默认接收目录。
    pub save_dir: PathBuf,
    pub transport: privet_transport::config::TransportConfigPrivet,
    pub discovery: privet_discovery::config::DiscoveryConfigPrivet,
    pub pairing: PairingConfig,
    pub transfer: TransferEngineConfig,
    /// QUIC 连接超时。
    pub quic_connect_timeout: Duration,
    /// 身份 keystore 路径（None=临时生成；Some=load-or-create，0600）。
    pub identity_path: Option<PathBuf>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            device_name: "privet-device".into(),
            platform: std::env::consts::OS.into(),
            db_path: PathBuf::from("privet.db"),
            save_dir: PathBuf::from("."),
            transport: privet_transport::config::TransportConfigPrivet::default(),
            discovery: privet_discovery::config::DiscoveryConfigPrivet::default(),
            pairing: PairingConfig::default(),
            transfer: TransferEngineConfig::default(),
            quic_connect_timeout: Duration::from_secs(3),
            identity_path: None,
        }
    }
}
