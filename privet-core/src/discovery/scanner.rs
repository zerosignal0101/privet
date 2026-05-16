use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;

use crate::error::DiscoveryError;

/// Scan a subnet for devices with an open privet port.
pub struct SubnetScanner {
    port: u16,
    timeout: Duration,
}

impl SubnetScanner {
    pub fn new(port: u16, timeout: Duration) -> Self {
        Self { port, timeout }
    }

    /// Scan a CIDR range (e.g., "10.20.1.0/24") for open privet ports.
    /// Returns list of addresses that accepted a TCP connection.
    pub async fn scan(&self, cidr: &str) -> Result<Vec<SocketAddr>, DiscoveryError> {
        let net: ipnet::IpNet = cidr
            .parse()
            .map_err(|e| DiscoveryError::Scan(format!("invalid CIDR: {e}")))?;

        let mut found = Vec::new();

        for ip in net.hosts() {
            let addr = SocketAddr::new(ip, self.port);
            if let Ok(Ok(_)) = tokio::time::timeout(
                self.timeout,
                TcpStream::connect(addr),
            )
            .await
            {
                found.push(addr);
            }
        }

        Ok(found)
    }
}
