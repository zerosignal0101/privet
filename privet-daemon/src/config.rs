use std::path::{Path, PathBuf};

use privet_core::EngineConfig;
use privet_ipc::{CollisionPolicyDto, LocalEndpoint};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonConfig {
    pub device_name: String,
    pub data_dir: PathBuf,
    pub save_dir: PathBuf,
    pub ipc_endpoint: Option<PathBuf>,
    pub quic_port: u16,
    pub tcp_port: u16,
    pub discovery_port: u16,
    pub accept_all_trusted: bool,
    pub collision_policy: CollisionPolicyDto,
    pub pairing: privet_security::PairingConfig,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        let data_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("privet");
        Self {
            device_name: "privet-device".into(),
            save_dir: dirs::download_dir().unwrap_or_else(|| data_dir.join("received")),
            data_dir,
            ipc_endpoint: None,
            quic_port: privet_core::EngineConfig::default().transport.quic_port,
            tcp_port: privet_core::EngineConfig::default().transport.tcp_port,
            discovery_port: privet_core::EngineConfig::default().discovery.udp_port,
            accept_all_trusted: false,
            collision_policy: CollisionPolicyDto::Rename,
            pairing: Default::default(),
        }
    }
}

impl DaemonConfig {
    pub fn load(path: Option<&Path>) -> Result<Self, String> {
        let config = match path {
            Some(path) => {
                let bytes = std::fs::read(path).map_err(|error| format!("read config: {error}"))?;
                serde_json::from_slice(&bytes).map_err(|error| format!("parse config: {error}"))?
            }
            None => Self::default(),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.device_name.trim().is_empty() { return Err("device_name must not be empty".into()); }
        self.pairing.validate()?;
        Ok(())
    }

    pub fn endpoint(&self) -> LocalEndpoint {
        self.ipc_endpoint
            .clone()
            .map(LocalEndpoint::new)
            .unwrap_or_else(privet_ipc::default_endpoint)
    }

    pub fn engine_config(&self) -> EngineConfig {
        let mut config = EngineConfig::default();
        config.device_name = self.device_name.clone();
        config.db_path = self.data_dir.join("privet.db");
        config.identity_path = Some(self.data_dir.join("identity.bin"));
        config.save_dir = self.save_dir.clone();
        config.transport.quic_port = self.quic_port;
        config.transport.tcp_port = self.tcp_port;
        config.discovery.udp_port = self.discovery_port;
        config.pairing = self.pairing.clone();
        config.transfer.save_dir = self.save_dir.clone();
        config.transfer.on_collision = collision_from_dto(self.collision_policy);
        config
    }
}

pub fn collision_from_dto(value: CollisionPolicyDto) -> privet_transfer::CollisionPolicy {
    match value {
        CollisionPolicyDto::Rename => privet_transfer::CollisionPolicy::Rename,
        CollisionPolicyDto::Skip => privet_transfer::CollisionPolicy::Skip,
        CollisionPolicyDto::Overwrite => privet_transfer::CollisionPolicy::Overwrite,
    }
}

pub fn collision_to_dto(value: privet_transfer::CollisionPolicy) -> CollisionPolicyDto {
    match value {
        privet_transfer::CollisionPolicy::Rename => CollisionPolicyDto::Rename,
        privet_transfer::CollisionPolicy::Skip => CollisionPolicyDto::Skip,
        privet_transfer::CollisionPolicy::Overwrite => CollisionPolicyDto::Overwrite,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_json_uses_safe_defaults() {
        let config: DaemonConfig = serde_json::from_str(r#"{"device_name":"desk"}"#).unwrap();
        assert_eq!(config.device_name, "desk");
        assert!(!config.accept_all_trusted);
        config.validate().unwrap();
    }
}
