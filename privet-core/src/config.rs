use std::path::PathBuf;
use std::time::Duration;

use privet_security::PairingConfig;
use privet_transfer::TransferEngineConfig;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub device_name: String,
    pub platform: String,
    pub db_path: PathBuf,
    pub save_dir: PathBuf,
    pub transport: privet_transport::config::TransportConfigPrivet,
    pub discovery: privet_discovery::config::DiscoveryConfigPrivet,
    pub pairing: PairingConfig,
    pub transfer: TransferEngineConfig,
    pub quic_connect_timeout: Duration,
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
