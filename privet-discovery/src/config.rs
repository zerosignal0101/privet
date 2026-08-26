//! 发现配置

#![cfg_attr(test, allow(unused_imports))]

use std::time::Duration;

use crate::constants::*;

/// 可发现性模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverabilityMode {
    /// 始终广播 + 响应 Probe（默认）。
    Always,
    /// 限时窗口内广播，期满静默。
    Window,
    /// 不广播不响应公开 Probe；仅直连 + 接受已信任入站。
    TrustedOnly,
}

#[derive(Debug, Clone, Copy)]
pub struct KnownDevicesConfig {
    pub recent_n: usize,
    pub probe_concurrency: usize,
    pub probe_timeout: Duration,
    pub evict_consecutive_fails: u32,
    pub auto_record: bool,
    pub probe_known: bool,
}

impl Default for KnownDevicesConfig {
    fn default() -> Self {
        Self {
            recent_n: RECENT_N,
            probe_concurrency: PROBE_CONCURRENCY,
            probe_timeout: PROBE_TIMEOUT,
            evict_consecutive_fails: EVICT_FAILS,
            auto_record: true,
            probe_known: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub mode: DiscoverabilityMode,
    pub window_secs: u64,
    pub beacon_interval: Duration,
    pub probe_interval: Duration,
    pub stale_timeout: Duration,
    pub lost_timeout: Duration,
    pub udp_port: u16,
    pub interfaces: Vec<String>,
    pub active_scan: bool,
    pub known: KnownDevicesConfig,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            mode: DiscoverabilityMode::Always,
            window_secs: 600,
            beacon_interval: BEACON_INTERVAL,
            probe_interval: crate::constants::PROBE_INTERVAL,
            stale_timeout: PEER_STALE_TIMEOUT,
            lost_timeout: PEER_LOST_TIMEOUT,
            udp_port: PRIVET_DISCOVERY_PORT,
            interfaces: Vec::new(),
            active_scan: true,
            known: KnownDevicesConfig::default(),
        }
    }
}
