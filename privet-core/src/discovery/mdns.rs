use std::sync::Arc;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::sync::mpsc;

use crate::error::DiscoveryError;

pub(crate) const MDNS_SERVICE_TYPE: &str = "_privet._udp.local.";

pub(crate) struct MdnsDiscovery {
    daemon: Option<Arc<ServiceDaemon>>,
}

impl MdnsDiscovery {
    pub(crate) fn new() -> Self {
        match ServiceDaemon::new() {
            Ok(d) => {
                tracing::info!("mDNS daemon started");
                Self {
                    daemon: Some(Arc::new(d)),
                }
            }
            Err(e) => {
                tracing::warn!("Failed to start mDNS daemon: {e}");
                Self { daemon: None }
            }
        }
    }

    pub(crate) fn is_available(&self) -> bool {
        self.daemon.is_some()
    }

    pub(crate) fn register(
        &self,
        instance_name: &str,
        hostname: &str,
        port: u16,
        properties: &[(&str, &str)],
    ) -> Result<(), DiscoveryError> {
        let daemon = self
            .daemon
            .as_ref()
            .ok_or_else(|| DiscoveryError::Mdns("daemon not available".into()))?;

        let info = ServiceInfo::new(MDNS_SERVICE_TYPE, instance_name, hostname, "", port, properties)
            .map_err(|e| DiscoveryError::Mdns(format!("create: {e}")))?
            .enable_addr_auto();

        daemon
            .register(info)
            .map_err(|e| DiscoveryError::Mdns(format!("register: {e}")))?;

        tracing::info!("mDNS service registered: {instance_name}");
        Ok(())
    }

    pub(crate) fn browse(&self) -> Result<mpsc::Receiver<ServiceEvent>, DiscoveryError> {
        let daemon = self
            .daemon
            .as_ref()
            .ok_or_else(|| DiscoveryError::Mdns("daemon not available".into()))?;

        let flume_rx = daemon
            .browse(MDNS_SERVICE_TYPE)
            .map_err(|e| DiscoveryError::Mdns(format!("browse: {e}")))?;

        let (tx, rx) = mpsc::channel(64);

        // flume 0.11.1 does not have recv_async; bridge via spawn_blocking
        tokio::task::spawn_blocking(move || {
            while let Ok(event) = flume_rx.recv() {
                if tx.blocking_send(event).is_err() {
                    break;
                }
            }
        });

        Ok(rx)
    }
}
