//! mDNS 通告 + 浏览。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::beacon::BeaconView;
use crate::error::{DiscoveryError, Result};

pub const SERVICE_TYPE: &str = "_privet._udp.local.";

/// TXT 映射。
pub fn to_txt(v: &BeaconView) -> Vec<(String, String)> {
    let mut t = vec![
        ("proto_version".to_string(), v.proto_version.to_string()),
        ("platform".to_string(), v.platform.clone()),
        ("capabilities".to_string(), v.capabilities.join(",")),
        ("device_fingerprint".to_string(), v.device_fingerprint.clone()),
        ("tcp_port".to_string(), v.tcp_port.to_string()),
    ];
    t.retain(|(_, val)| !val.is_empty());
    t
}

/// 从已解析 mDNS 服务还原 BeaconView（cap 列表/端口）。
pub fn from_service(
    device_name: &str,
    txt: &HashMap<String, String>,
    _addrs: &[IpAddr],
    port: u16,
) -> Option<BeaconView> {
    let device_fingerprint = txt.get("device_fingerprint")?.clone();
    Some(BeaconView {
        device_name: device_name.to_string(),
        platform: txt.get("platform").cloned().unwrap_or_default(),
        proto_version: txt.get("proto_version").and_then(|s| s.parse().ok()).unwrap_or(1),
        capabilities: txt
            .get("capabilities")
            .map(|s| s.split(',').map(str::to_string).collect())
            .unwrap_or_default(),
        device_fingerprint,
        quic_port: port,
        tcp_port: txt.get("tcp").and_then(|s| s.parse().ok()).unwrap_or(0),
        nonce: vec![],
        ts_ms: 0,
    })
}

/// 规范化实例名：替换非法字符为 `-`，截断 63 字节。
pub fn normalize_instance_name(device_name: &str, max_bytes: usize) -> String {
    let cleaned: String = device_name
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '?' | '*' | '"' | '<' | '>' | '|' => '-',
            _ => c,
        })
        .collect();
    let mut out = cleaned.into_bytes();
    out.truncate(max_bytes);
    String::from_utf8(out).unwrap_or_else(|_| "privet".to_string())
}

/// mDNS 通告器。
pub struct MdnsAnnouncer {
    daemon: Arc<ServiceDaemon>,
}

impl MdnsAnnouncer {
    pub fn new(view: &BeaconView, addrs: Vec<IpAddr>) -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(|e| DiscoveryError::Mdns(e.to_string()))?;
        let instance = normalize_instance_name(&view.device_name, 63);
        let host = format!("{}.local.", instance);
        let props = to_txt(view);
        let ip_str = addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &host,
            if ip_str.is_empty() {
                "0.0.0.0"
            } else {
                &ip_str
            },
            view.quic_port,
            &props[..],
        )
        .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;
        daemon
            .register(info)
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;
        Ok(Self {
            daemon: Arc::new(daemon),
        })
    }
    pub fn shutdown(&self) -> Result<()> {
        self.daemon
            .shutdown()
            .map(|_| ())
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))
    }
}

/// mDNS 浏览器：发现服务 -> 经 channel 推 (BeaconView, Vec\<IpAddr\>)。
pub struct MdnsBrowser {
    daemon: Arc<ServiceDaemon>,
}

impl MdnsBrowser {
    pub fn start(tx: tokio::sync::mpsc::Sender<(BeaconView, Vec<IpAddr>)>) -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(|e| DiscoveryError::Mdns(e.to_string()))?;
        let receiver = daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;
        let daemon_arc = Arc::new(daemon);
        let daemon_clone = daemon_arc.clone();
        tokio::spawn(async move {
            loop {
                let event = match receiver.recv_async().await {
                    Ok(e) => e,
                    Err(_) => break,
                };
                if let ServiceEvent::ServiceResolved(resolved) = event {
                    let mut txt: HashMap<String, String> = HashMap::new();
                    for prop in resolved.txt_properties.iter() {
                        let val = prop.val_str().to_string();
                        txt.insert(prop.key().to_string(), val);
                    }
                    // Convert ScopedIp addresses to IpAddr
                    let addrs: Vec<IpAddr> = resolved
                        .addresses
                        .iter()
                        .filter_map(|scoped| match scoped {
                            mdns_sd::ScopedIp::V4(v4) => Some(IpAddr::V4(*v4.addr())),
                            mdns_sd::ScopedIp::V6(v6) => Some(IpAddr::V6(*v6.addr())),
                            _ => None,
                        })
                        .collect();
                    if let Some(view) =
                        from_service(&resolved.fullname, &txt, &addrs, resolved.port)
                    {
                        let _ = tx.send((view, addrs)).await;
                    }
                }
            }
            let _ = daemon_clone;
        });
        Ok(Self { daemon: daemon_arc })
    }
    pub fn shutdown(&self) -> Result<()> {
        self.daemon
            .shutdown()
            .map(|_| ())
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::BeaconView;

    #[test]
    fn txt_roundtrip() {
        let v = BeaconView {
            device_name: "alice".into(),
            platform: "linux".into(),
            proto_version: 1,
            capabilities: vec!["quic".into(), "tcp".into()],
            device_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
            quic_port: 47808,
            tcp_port: 47810,
            nonce: vec![],
            ts_ms: 0,
        };
        let txt = to_txt(&v);
        assert_eq!(txt.iter().find(|(k, _)| k == "proto_version").unwrap().1, "1");
        assert_eq!(txt.iter().find(|(k, _)| k == "platform").unwrap().1, "linux");
        assert_eq!(txt.iter().find(|(k, _)| k == "device_fingerprint").unwrap().1, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        assert_eq!(txt.iter().find(|(k, _)| k == "tcp_port").unwrap().1, "47810");
        assert_eq!(txt.iter().find(|(k, _)| k == "capabilities").unwrap().1, "quic,tcp");
    }

    #[test]
    fn normalize_instance_name_truncates_and_replaces_illegal() {
        let n = normalize_instance_name("a/b:c?d", 8);
        assert!(n.len() <= 8);
        assert!(!n.contains('/'));
    }
}
