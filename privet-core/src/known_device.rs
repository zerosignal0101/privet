//! Known device store: persists device-to-network/IP mappings for
//! directed discovery in restricted networks (e.g. campus/corporate).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::peer::PeerId;

/// A network entry associated with a known device.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkEntry {
    /// Addresses (IP:port) where this device was seen on this network.
    pub addresses: Vec<String>,
    /// When the device was last seen on this network.
    pub last_seen: SystemTime,
    /// Human-readable label for this network, e.g. "家庭网络", "公司网络".
    pub label: Option<String>,
}

/// A known device with its network/IP associations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KnownDevice {
    /// SHA-256 fingerprint of the device's TLS certificate.
    pub fingerprint: String,
    /// Peer ID (UUID).
    pub peer_id: String,
    /// Human-readable device name.
    pub device_name: String,
    /// Map from subnet (e.g. "192.168.1.0/24") to network entry.
    pub networks: HashMap<String, NetworkEntry>,
}

impl KnownDevice {
    /// Display a short version of the fingerprint.
    pub fn display_fingerprint(&self) -> &str {
        let end = self.fingerprint.len().min(12);
        &self.fingerprint[..end]
    }
}

/// Persistent store for known devices, stored as JSON at `<cert_dir>/known_devices.json`.
#[derive(Debug)]
pub struct KnownDeviceStore {
    devices: Vec<KnownDevice>,
    store_path: PathBuf,
}

impl KnownDeviceStore {
    /// Load the store from disk, or create an empty one if it doesn't exist.
    pub fn load_or_create(store_path: PathBuf) -> Result<Self, crate::error::SecurityError> {
        let devices = if store_path.exists() {
            let json = std::fs::read_to_string(&store_path)
                .map_err(|e| crate::error::SecurityError::Certificate(
                    format!("read known device store: {e}")
                ))?;
            serde_json::from_str::<Vec<KnownDevice>>(&json)
                .map_err(|e| crate::error::SecurityError::Certificate(
                    format!("parse known device store: {e}")
                ))?
        } else {
            Vec::new()
        };

        Ok(Self { devices, store_path })
    }

    /// Save the store to disk.
    fn save(&self) -> Result<(), crate::error::SecurityError> {
        if let Some(parent) = self.store_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| crate::error::SecurityError::Certificate(
                    format!("create known device dir: {e}")
                ))?;
        }
        let json = serde_json::to_string_pretty(&self.devices)
            .map_err(|e| crate::error::SecurityError::Certificate(
                format!("serialize known device store: {e}")
            ))?;
        std::fs::write(&self.store_path, json)
            .map_err(|e| crate::error::SecurityError::Certificate(
                format!("write known device store: {e}")
            ))?;
        Ok(())
    }

    /// Add or update a known device. If the device already exists (by fingerprint),
    /// merge the network information.
    pub fn add_or_update_device(
        &mut self,
        fingerprint: String,
        peer_id: PeerId,
        device_name: String,
        subnet: String,
        addr: SocketAddr,
        label: Option<String>,
    ) -> Result<(), crate::error::SecurityError> {
        let addr_str = addr.to_string();

        if let Some(device) = self.devices.iter_mut().find(|d| d.fingerprint == fingerprint) {
            // Update device name if it changed
            device.device_name = device_name;
            device.peer_id = peer_id.to_string();

            // Add or update the network entry
            let entry = device.networks.entry(subnet).or_insert_with(|| NetworkEntry {
                addresses: Vec::new(),
                last_seen: SystemTime::now(),
                label: label.clone(),
            });
            if !entry.addresses.contains(&addr_str) {
                entry.addresses.push(addr_str);
            }
            entry.last_seen = SystemTime::now();
            if label.is_some() {
                entry.label = label;
            }
        } else {
            let mut networks = HashMap::new();
            networks.insert(subnet, NetworkEntry {
                addresses: vec![addr_str],
                last_seen: SystemTime::now(),
                label,
            });
            self.devices.push(KnownDevice {
                fingerprint,
                peer_id: peer_id.to_string(),
                device_name,
                networks,
            });
        }

        self.save()
    }

    /// Add an IP address for a device on a specific network.
    /// Creates the device entry if it doesn't exist.
    pub fn add_device_ip(
        &mut self,
        fingerprint: String,
        peer_id: PeerId,
        device_name: String,
        subnet: String,
        addr: SocketAddr,
        label: Option<String>,
    ) -> Result<(), crate::error::SecurityError> {
        self.add_or_update_device(fingerprint, peer_id, device_name, subnet, addr, label)
    }

    /// Remove a specific network IP mapping for a device.
    /// If the network entry becomes empty, remove it.
    pub fn remove_device_ip(
        &mut self,
        fingerprint: &str,
        subnet: &str,
        addr: &str,
    ) -> Result<(), crate::error::SecurityError> {
        if let Some(device) = self.devices.iter_mut().find(|d| d.fingerprint == fingerprint) {
            if let Some(entry) = device.networks.get_mut(subnet) {
                entry.addresses.retain(|a| a != addr);
                if entry.addresses.is_empty() {
                    device.networks.remove(subnet);
                }
            }
            // If the device has no networks left, remove it
            if device.networks.is_empty() {
                self.devices.retain(|d| d.fingerprint != fingerprint);
            }
        }
        self.save()
    }

    /// Remove an entire network entry for a device.
    pub fn remove_device_network(
        &mut self,
        fingerprint: &str,
        subnet: &str,
    ) -> Result<(), crate::error::SecurityError> {
        if let Some(device) = self.devices.iter_mut().find(|d| d.fingerprint == fingerprint) {
            device.networks.remove(subnet);
            if device.networks.is_empty() {
                self.devices.retain(|d| d.fingerprint != fingerprint);
            }
        }
        self.save()
    }

    /// Set a human-readable label for a network entry.
    pub fn set_network_label(
        &mut self,
        fingerprint: &str,
        subnet: &str,
        label: String,
    ) -> Result<(), crate::error::SecurityError> {
        if let Some(device) = self.devices.iter_mut().find(|d| d.fingerprint == fingerprint) {
            if let Some(entry) = device.networks.get_mut(subnet) {
                entry.label = Some(label);
            }
        }
        self.save()
    }

    /// Get all known devices.
    pub fn get_devices(&self) -> &[KnownDevice] {
        &self.devices
    }

    /// Get devices that have an entry for a specific subnet.
    pub fn get_devices_for_network(&self, subnet: &str) -> Vec<&KnownDevice> {
        self.devices
            .iter()
            .filter(|d| d.networks.contains_key(subnet))
            .collect()
    }

    /// Find a known device by fingerprint.
    pub fn get_device(&self, fingerprint: &str) -> Option<&KnownDevice> {
        self.devices.iter().find(|d| d.fingerprint == fingerprint)
    }

    /// Find a known device by name.
    pub fn get_device_by_name(&self, name: &str) -> Option<&KnownDevice> {
        self.devices.iter().find(|d| d.device_name == name)
    }

    /// Get addresses for a device on a specific network.
    pub fn get_addresses_for_network(
        &self,
        fingerprint: &str,
        subnet: &str,
    ) -> Vec<SocketAddr> {
        self.devices
            .iter()
            .find(|d| d.fingerprint == fingerprint)
            .and_then(|d| d.networks.get(subnet))
            .map(|entry| {
                entry.addresses
                    .iter()
                    .filter_map(|a| a.parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Remove a device entirely from the store.
    pub fn remove_device(&mut self, fingerprint: &str) -> Result<(), crate::error::SecurityError> {
        self.devices.retain(|d| d.fingerprint != fingerprint);
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn add_and_retrieve_device() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_devices.json");
        let mut store = KnownDeviceStore::load_or_create(path).unwrap();

        let fp = "abc123".to_string();
        let peer_id = PeerId(Uuid::new_v4());
        let addr: SocketAddr = "192.168.1.100:53530".parse().unwrap();

        store.add_or_update_device(
            fp.clone(),
            peer_id,
            "TestDevice".to_string(),
            "192.168.1.0/24".to_string(),
            addr,
            Some("家庭网络".to_string()),
        ).unwrap();

        let devices = store.get_devices_for_network("192.168.1.0/24");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_name, "TestDevice");
        assert_eq!(devices[0].fingerprint, "abc123");
    }

    #[test]
    fn update_existing_device_adds_new_network() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_devices.json");
        let mut store = KnownDeviceStore::load_or_create(path).unwrap();

        let fp = "abc123".to_string();
        let peer_id = PeerId(Uuid::new_v4());

        store.add_or_update_device(
            fp.clone(),
            peer_id,
            "TestDevice".to_string(),
            "192.168.1.0/24".to_string(),
            "192.168.1.100:53530".parse().unwrap(),
            None,
        ).unwrap();

        store.add_or_update_device(
            fp.clone(),
            peer_id,
            "TestDevice".to_string(),
            "10.0.0.0/8".to_string(),
            "10.0.0.50:53530".parse().unwrap(),
            Some("公司网络".to_string()),
        ).unwrap();

        assert_eq!(store.get_devices().len(), 1);
        let device = store.get_device(&fp).unwrap();
        assert_eq!(device.networks.len(), 2);
    }

    #[test]
    fn remove_device_ip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_devices.json");
        let mut store = KnownDeviceStore::load_or_create(path).unwrap();

        let fp = "abc123".to_string();
        let peer_id = PeerId(Uuid::new_v4());

        store.add_or_update_device(
            fp.clone(),
            peer_id,
            "TestDevice".to_string(),
            "192.168.1.0/24".to_string(),
            "192.168.1.100:53530".parse().unwrap(),
            None,
        ).unwrap();

        store.remove_device_ip(&fp, "192.168.1.0/24", "192.168.1.100:53530").unwrap();
        assert!(store.get_devices().is_empty());
    }

    #[test]
    fn set_network_label() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_devices.json");
        let mut store = KnownDeviceStore::load_or_create(path).unwrap();

        let fp = "abc123".to_string();
        let peer_id = PeerId(Uuid::new_v4());

        store.add_or_update_device(
            fp.clone(),
            peer_id,
            "TestDevice".to_string(),
            "192.168.1.0/24".to_string(),
            "192.168.1.100:53530".parse().unwrap(),
            None,
        ).unwrap();

        store.set_network_label(&fp, "192.168.1.0/24", "家庭网络".to_string()).unwrap();

        let device = store.get_device(&fp).unwrap();
        let entry = device.networks.get("192.168.1.0/24").unwrap();
        assert_eq!(entry.label.as_deref(), Some("家庭网络"));
    }

    #[test]
    fn persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_devices.json");
        let fp = "abc123".to_string();
        let peer_id = PeerId(Uuid::new_v4());

        {
            let mut store = KnownDeviceStore::load_or_create(path.clone()).unwrap();
            store.add_or_update_device(
                fp.clone(),
                peer_id,
                "TestDevice".to_string(),
                "192.168.1.0/24".to_string(),
                "192.168.1.100:53530".parse().unwrap(),
                None,
            ).unwrap();
        }

        let store = KnownDeviceStore::load_or_create(path).unwrap();
        assert_eq!(store.get_devices().len(), 1);
        assert_eq!(store.get_devices()[0].device_name, "TestDevice");
    }
}
