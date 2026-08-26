
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;

use crate::netinfo::NetworkFingerprint;
use crate::peer::{CandidateAddress, PeerRecord};

#[derive(Debug, Clone)]
pub struct KnownAddressRecord {
    pub addr: IpAddr,
    pub quic_port: u16,
    pub tcp_port: u16,
    pub subnet_cidr: String,
    pub last_seen_ms: u64,
    pub success_count: u32,
    pub fail_count: u32,
}

#[derive(Debug, Clone)]
pub enum ConnectOutcome {
    Ok { used_addr: IpAddr },
    Fail,
}

#[async_trait]
pub trait PeerConnector: Send + Sync {
    async fn try_connect(&self, addr: IpAddr, quic_port: u16, tcp_port: u16) -> ConnectOutcome;
}

pub fn select_candidates(
    rec: &PeerRecord,
    current_net: &NetworkFingerprint,
) -> Vec<CandidateAddress> {
    let mut same_subnet: Vec<&CandidateAddress> = rec
        .candidates
        .iter()
        .filter(|c| shares_subnet(c.ip, current_net))
        .collect();
    let mut other: Vec<&CandidateAddress> = rec
        .candidates
        .iter()
        .filter(|c| !shares_subnet(c.ip, current_net))
        .collect();
    same_subnet.sort_by_key(|b| std::cmp::Reverse(b.last_seen_ms));
    other.sort_by_key(|b| std::cmp::Reverse(b.last_seen_ms));
    same_subnet.into_iter().chain(other).cloned().collect()
}

pub fn shares_subnet(ip: IpAddr, net: &NetworkFingerprint) -> bool {
    let IpAddr::V4(v4) = ip else {
        return false;
    };
    let ip_bits = u32::from(v4);
    net.subnets.iter().any(|s| {
        let prefix = s.prefix.min(32);
        let mask = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        match s.addr {
            IpAddr::V4(n) => (u32::from(n) & mask) == (ip_bits & mask),
            _ => false,
        }
    })
}

pub async fn probe_recent<C: PeerConnector>(
    connector: &C,
    addrs: &[KnownAddressRecord],
    timeout: Duration,
    _concurrency: usize,
) -> Option<ConnectOutcome> {
    for a in addrs {
        let task = tokio::time::timeout(
            timeout,
            connector.try_connect(a.addr, a.quic_port, a.tcp_port),
        );
        match task.await {
            Ok(ConnectOutcome::Ok { used_addr }) => {
                return Some(ConnectOutcome::Ok { used_addr });
            }
            _ => continue,
        }
    }
    None
}
