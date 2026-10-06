
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerState {
    Absent,
    Seen,
    Resolved,
    Live,
    Stale,
    Lost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    BeaconRecv,
    AddrResolved,
    ConnectOk,
    ConnectFail,
    StaleTimeout,
    LostTimeout,
    GoodbyeBeacon,
    ExplicitRemove,
    KnownAddrConnectOk,
    KnownAddrConnectFail,
}

pub fn transition(state: PeerState, event: PeerEvent) -> Option<PeerState> {
    use PeerEvent::*;
    use PeerState::*;
    Some(match (state, event) {
        (Absent, BeaconRecv) => Seen,
        (Absent, KnownAddrConnectOk) => Live,
        (Seen, AddrResolved) => Resolved,
        (Resolved, ConnectOk) => Live,
        (Resolved, ConnectFail) => Resolved,
        (Live, StaleTimeout) => Stale,
        (Live, GoodbyeBeacon) => Absent,
        (Live, ExplicitRemove) => Absent,
        (Stale, BeaconRecv) => Live,
        (Stale, KnownAddrConnectOk) => Live,
        (Stale, LostTimeout) => Lost,
        (Lost, BeaconRecv) => Live,
        (Lost, KnownAddrConnectOk) => Live,
        (Lost, ExplicitRemove) => Absent,
        _ => return None,
    })
}

// Peer records and candidate addresses.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::beacon::BeaconView;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateAddress {
    pub ip: IpAddr,
    pub quic_port: u16,
    pub tcp_port: u16,
    pub heard_iface: Option<IpAddr>,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub device_fingerprint: String,
    pub state: PeerState,
    pub candidates: Vec<CandidateAddress>,
    pub device_name: String,
    pub last_beacon_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerStoreEvent {
    Discovered(String),
    StateChanged(String, PeerState),
    Lost(String),
}

pub struct PeerStore {
    peers: HashMap<String, PeerRecord>,
    events: Vec<PeerStoreEvent>,
    /// This device's own fingerprint. `handle_beacon` is the single funnel every
    /// inbound discovery path goes through — the UDP beacon path
    /// (`udp::handle_incoming_datagram`) and the mDNS path
    /// (`DiscoveryEngine::on_mdns_resolved`) both call it — so this is the one
    /// place that can drop a peer that is really us.
    own_fingerprint: Option<String>,
}

impl PeerStore {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            events: Vec::new(),
            own_fingerprint: None,
        }
    }

    /// A store that refuses to record `own_fp` as a peer.
    pub fn with_own_fingerprint(own_fp: String) -> Self {
        Self {
            own_fingerprint: Some(own_fp),
            ..Self::new()
        }
    }

    /// True when `fingerprint` is this device's own.
    ///
    /// A directed or global broadcast sent from this host is looped back by the
    /// kernel to sockets bound to `0.0.0.0`, so the daemon receives its own
    /// beacon with its own source address. Likewise `MdnsAnnouncer` registers
    /// `_privet._udp.local.` on the same host that `MdnsBrowser` browses, so the
    /// browser resolves the daemon's own service. Neither case is a peer.
    pub fn is_self(&self, fingerprint: &str) -> bool {
        self.own_fingerprint
            .as_deref()
            .is_some_and(|own| own == fingerprint)
    }

    pub fn handle_beacon(
        &mut self,
        v: &BeaconView,
        src: IpAddr,
        heard_iface: Option<IpAddr>,
        now_ms: u64,
    ) {
        if self.is_self(&v.device_fingerprint) {
            return;
        }
        let cand = CandidateAddress {
            ip: src,
            quic_port: v.quic_port,
            tcp_port: v.tcp_port,
            heard_iface,
            last_seen_ms: now_ms,
        };
        match self.peers.get_mut(&v.device_fingerprint) {
            Some(rec) => {
                rec.device_name = v.device_name.clone();
                rec.last_beacon_ms = now_ms;
                if let Some(c) = rec.candidates.iter_mut().find(|c| c.ip == src) {
                    c.last_seen_ms = now_ms;
                    c.quic_port = v.quic_port;
                    c.tcp_port = v.tcp_port;
                } else {
                    rec.candidates.push(cand);
                }
                let prev = rec.state;
                if let Some(ns) = transition(prev, PeerEvent::BeaconRecv) {
                    rec.state = ns;
                    if ns != prev {
                        self.events
                            .push(PeerStoreEvent::StateChanged(rec.device_fingerprint.clone(), ns));
                    }
                }
            }
            None => {
                let rec = PeerRecord {
                    device_fingerprint: v.device_fingerprint.clone(),
                    state: PeerState::Seen,
                    candidates: vec![cand],
                    device_name: v.device_name.clone(),
                    last_beacon_ms: now_ms,
                };
                self.events
                    .push(PeerStoreEvent::Discovered(rec.device_fingerprint.clone()));
                self.peers.insert(v.device_fingerprint.clone(), rec);
            }
        }
    }

    pub fn handle_goodbye(&mut self, fingerprint: &str) {
        if self.is_self(fingerprint) {
            return;
        }
        if let Some(rec) = self.peers.get_mut(fingerprint) {
            let prev = rec.state;
            if let Some(ns) = transition(prev, PeerEvent::GoodbyeBeacon) {
                rec.state = ns;
                self.events
                    .push(PeerStoreEvent::StateChanged(rec.device_fingerprint.clone(), ns));
            }
        }
    }

    pub fn transition(&mut self, fingerprint: &str, event: PeerEvent) {
        if let Some(rec) = self.peers.get_mut(fingerprint) {
            let prev = rec.state;
            if let Some(ns) = transition(prev, event) {
                rec.state = ns;
                if ns != prev {
                    self.events
                        .push(PeerStoreEvent::StateChanged(rec.device_fingerprint.clone(), ns));
                }
                if ns == PeerState::Lost {
                    self.events
                        .push(PeerStoreEvent::Lost(rec.device_fingerprint.clone()));
                }
            }
        }
    }

    pub fn sweep(&mut self, now_ms: u64, stale: std::time::Duration, lost: std::time::Duration) {
        let stale_ms = stale.as_millis() as u64;
        let lost_ms = lost.as_millis() as u64;
        let fps: Vec<String> = self.peers.keys().cloned().collect();
        for fp in fps {
            let rec = match self.peers.get(&fp) {
                Some(r) => r,
                None => continue,
            };
            let state = rec.state;
            if state == PeerState::Absent || state == PeerState::Lost {
                continue;
            }
            let last = rec.last_beacon_ms;
            if now_ms < last {
                continue;
            }
            let age = now_ms - last;
            if state == PeerState::Live && age > stale_ms {
                self.transition(&fp, PeerEvent::StaleTimeout);
            }
            if let Some(r) = self.peers.get(&fp) {
                if r.state == PeerState::Stale && age > lost_ms {
                    self.transition(&fp, PeerEvent::LostTimeout);
                }
            }
        }
    }

    pub fn get(&self, fingerprint: &str) -> Option<&PeerRecord> {
        self.peers.get(fingerprint)
    }
    pub fn snapshot(&self) -> Vec<&PeerRecord> {
        self.peers.values().collect()
    }
    pub fn drain_events(&mut self) -> Vec<PeerStoreEvent> {
        std::mem::take(&mut self.events)
    }
}

impl Default for PeerStore {
    fn default() -> Self {
        Self::new()
    }
}
