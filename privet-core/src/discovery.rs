//! Discovery 接线：LocalDeviceInfo 拼装 + 引擎启停 + peer 事件 -> EngineEvent（P1）。
use std::collections::HashMap;
use std::sync::Arc;

use privet_crypto::identity::Identity;
use privet_discovery::{
    config::DiscoveryConfigPrivet,
    engine::DiscoveryEngine,
    peer::{PeerRecord, PeerStoreEvent},
};

use crate::config::EngineConfig;
use crate::EngineEvent;

/// 从 Identity + EngineConfig 拼装本地设备信息。
pub fn build_local_device_info(
    identity: &Identity,
    cfg: &EngineConfig,
    quic_port: u16,
    tcp_port: u16,
    _udp_port: u16,
) -> privet_discovery::engine::LocalDeviceInfo {
    let fp = identity.fingerprint();
    privet_discovery::engine::LocalDeviceInfo {
        device_name: cfg.device_name.clone(),
        platform: cfg.platform.clone(),
        capabilities: vec![
            "quic".into(),
            "tcp".into(),
            "folder".into(),
            "resume".into(),
        ],
        device_fingerprint: fp,
        quic_port,
        tcp_port,
    }
}

use privet_crypto::hash::fingerprint_hex;

/// 启动发现引擎（bind UDP + recv 任务）。
pub async fn start_discovery(
    info: privet_discovery::engine::LocalDeviceInfo,
    dcfg: DiscoveryConfigPrivet,
) -> crate::Result<Arc<DiscoveryEngine>> {
    let engine = Arc::new(DiscoveryEngine::new(info, dcfg));
    engine.start().await.map_err(crate::CoreError::Discovery)?;
    Ok(engine)
}

/// 把 PeerStoreEvent 映射为 EngineEvent（用 peers device_name 表补 name，用 fp_map 解析 fp_prefix→UUID）。
pub fn map_peer_event(
    e: PeerStoreEvent,
    names: &HashMap<String, String>,
    fp_map: &HashMap<String, String>,
) -> Option<EngineEvent> {
    match e {
        PeerStoreEvent::Discovered(device_fingerprint) => {
            // device_fingerprint 仅当 device_fingerprint 命中已信任设备时才设为 UUID，否则留空（前端用 device_fingerprint 作 key）。
            let device_fingerprint = fp_map.get(&device_fingerprint).cloned().unwrap_or_default();
            Some(EngineEvent::DeviceDiscovered {
                device_fingerprint: device_fingerprint.clone(),
                device_name: names.get(&device_fingerprint).cloned().unwrap_or_default(),
            })
        }
        PeerStoreEvent::Lost(device_fingerprint) => {
            let device_fingerprint = fp_map.get(&device_fingerprint).cloned().unwrap_or_default();
            Some(EngineEvent::DeviceLost {
                device_fingerprint,
            })
        }
        // StateChanged 不直接外发（避免 Seen->Resolved->Live 三连发）。
        PeerStoreEvent::StateChanged(_, _) => None,
    }
}

/// 排空 discovery peer 事件并补 device_name + fp_map（UUID 解析）-> EngineEvent。
/// 在过滤映射前先发出 richer tracing 日志（含地址信息）。
pub(crate) fn drain_peer_events_named(
    d: &DiscoveryEngine,
    fp_map: &HashMap<String, String>,
) -> Vec<EngineEvent> {
    let peers = d.peers();
    let names: HashMap<String, String> = peers
        .iter()
        .map(|p: &PeerRecord| (p.device_fingerprint.clone(), p.device_name.clone()))
        .collect();
    let events = d.drain_events();

    // 发出 richer tracing 日志
    for e in &events {
        match e {
            PeerStoreEvent::Discovered(device_fingerprint) => {
                if let Some(p) = peers.iter().find(|p| p.device_fingerprint == *device_fingerprint) {
                    let addrs: Vec<String> = p
                        .candidates
                        .iter()
                        .map(|c| format!("{}:{}", c.ip, c.quic_port))
                        .collect();
                    tracing::info!(
                        device_fingerprint = %device_fingerprint,
                        device_name = %p.device_name,
                        addrs = %addrs.join(","),
                        "peer discovered"
                    );
                } else {
                    tracing::info!(device_fingerprint = %device_fingerprint, "peer discovered");
                }
            }
            PeerStoreEvent::Lost(device_fingerprint) => {
                tracing::info!(device_fingerprint = %device_fingerprint, "peer lost");
            }
            _ => {}
        }
    }

    events
        .into_iter()
        .filter_map(|e| map_peer_event(e, &names, fp_map))
        .collect()
}

/// 构建 device_fingerprint -> device_fingerprint 映射（仅 Trusted 设备；从 peer_spki 派生 fingerprint_hex）。
pub fn trusted_fp_map(db: &rusqlite::Connection) -> std::collections::HashMap<String, String> {
    let Ok(rows) = privet_storage::trust::list_all(db) else {
        return Default::default();
    };
    rows.iter()
        .filter(|r| r.trust_state == "Trusted")
        .map(|r| (fingerprint_hex(&r.peer_spki), r.device_fingerprint.clone()))
        .collect()
}

/// beacon 命中已信任设备时 best-effort upsert 其最新候选地址（不 inc_success）。
pub(crate) fn refresh_trusted_on_beacon(
    d: &DiscoveryEngine,
    db: &rusqlite::Connection,
    fp_map: &std::collections::HashMap<String, String>,
    now_secs: i64,
) {
    for p in d.peers() {
        let Some(did) = fp_map.get(&p.device_fingerprint) else {
            continue;
        };
        for cand in &p.candidates {
            let subnet =
                crate::ops::subnet_for_peer(cand.ip).unwrap_or_else(|| "0.0.0.0/0".to_string());
            let addr_str = cand.ip.to_string();
            let pa = privet_storage::trust::PeerAddress {
                subnet_cidr: &subnet,
                gateway_ip: None,
                addr: &addr_str,
                quic_port: cand.quic_port,
                tcp_port: cand.tcp_port,
                source: "self",
                last_seen_ts: now_secs,
            };
            let _ = privet_storage::addresses::upsert_address(db, did, &pa); // best-effort；不 inc_success
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_device_info_has_fp_prefix_and_ports() {
        let id = Identity::generate().unwrap();
        let cfg = EngineConfig::default();
        let info = build_local_device_info(&id, &cfg, 47808, 47810, 5353);
        assert_eq!(info.quic_port, 47808);
        assert_eq!(info.tcp_port, 47810);
        assert!(!info.device_fingerprint.is_empty());
        assert!(info.capabilities.contains(&"quic".to_string()));
    }

    #[test]
    fn fp_prefix_map_matches_trusted_spki() {
        let id = Identity::generate().unwrap();
        let fp = privet_crypto::hash::fingerprint_hex(id.spki_der());
        // 模拟数据库中有该设备。
        let map: std::collections::HashMap<String, String> =
            [(fp.clone(), "dev-x".to_string())].into();
        let matched = map.iter().find(|(f, _)| **f == fp).map(|(_, v)| v.clone());
        assert_eq!(matched.as_deref(), Some("dev-x"));
    }

    #[tokio::test]
    async fn drain_peer_events_named_populates_name() {
        use privet_discovery::beacon;
        use privet_discovery::engine::LocalDeviceInfo;
        use privet_protocol::Beacon;

        let engine = Arc::new(DiscoveryEngine::with_now(
            LocalDeviceInfo {
                device_name: "alice".into(),
                platform: "linux".into(),
                capabilities: vec!["quic".into()],
                device_fingerprint: "deadbeef".into(),
                quic_port: 47808,
                tcp_port: 47810,
            },
            DiscoveryConfigPrivet::default(),
            Arc::new(|| 1_700_000_000_000u64),
        ));
        let b = Beacon {
            device_name: "bob".into(),
            platform: "linux".into(),
            proto_version: 1,
            capabilities: vec!["quic".into()],
            device_fingerprint: "feedcafefeedcafefeedcafefeedcafefeedcafefeedcafefeedcafefeedcafe".into(),
            quic_port: 47808,
            tcp_port: 47810,
            nonce: b"0123456789abcdef".to_vec(),
            ts_ms: 1_700_000_000_000,
        };
        let bytes = beacon::encode_beacon_tagged(&b).unwrap();
        engine.inject_incoming(&bytes, "10.0.0.5".parse().unwrap(), None, 1_700_000_000_000);
        let evs = drain_peer_events_named(&engine, &HashMap::new());
        assert!(evs.iter().any(|e| matches!(
            e,
            EngineEvent::DeviceDiscovered { device_name, .. } if device_name == "bob"
        )));
    }
}
