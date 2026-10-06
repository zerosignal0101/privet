
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use tokio::sync::watch;

use privet_protocol::{Beacon, Goodbye, Probe};

use crate::config::{DiscoverabilityMode, DiscoveryConfigPrivet};
use crate::peer::{PeerEvent, PeerRecord, PeerStore, PeerStoreEvent};
use crate::udp::{handle_incoming_datagram, NonceCache, Outgoing, RateLimiter, UdpBeacon};

#[derive(Debug, Clone)]
pub struct LocalDeviceInfo {
    pub device_name: String,
    pub platform: String,
    pub capabilities: Vec<String>,
    pub device_fingerprint: String, // 8 hex（crypto fingerprint_hex）
    pub quic_port: u16,
    pub tcp_port: u16,
}

pub struct DiscoveryEngine {
    info: LocalDeviceInfo,
    config: DiscoveryConfigPrivet,
    store: Arc<Mutex<PeerStore>>,
    nonce: Arc<Mutex<NonceCache>>,
    rl: Arc<Mutex<RateLimiter>>,
    mode: Mutex<DiscoverabilityMode>,
    now_fn: Arc<dyn Fn() -> u64 + Send + Sync>,
    outgoing: Mutex<Option<Arc<dyn Outgoing>>>,
    cancel: watch::Sender<bool>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    start_ms: Mutex<u64>,
    nonce_ctr: AtomicU64,
    mdns: Mutex<Option<MdnsHandles>>,
    local_addrs: Mutex<Vec<IpAddr>>,
}

pub(crate) struct MdnsHandles {
    pub announcer: Option<crate::mdns::MdnsAnnouncer>,
    pub browser: Option<crate::mdns::MdnsBrowser>,
}

impl DiscoveryEngine {
    pub fn new(info: LocalDeviceInfo, config: DiscoveryConfigPrivet) -> Self {
        Self::with_now(
            info,
            config,
            Arc::new(|| {
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64
            }),
        )
    }
    pub fn with_now(
        info: LocalDeviceInfo,
        config: DiscoveryConfigPrivet,
        now_fn: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        let (cancel, _) = watch::channel(false);
        let own_fp = info.device_fingerprint.clone();
        Self {
            info,
            mode: Mutex::new(config.mode),
            config,
            store: Arc::new(Mutex::new(PeerStore::with_own_fingerprint(own_fp))),
            nonce: Arc::new(Mutex::new(NonceCache::new())),
            rl: Arc::new(Mutex::new(RateLimiter::new())),
            now_fn,
            outgoing: Mutex::new(None),
            cancel,
            tasks: Mutex::new(Vec::new()),
            start_ms: Mutex::new(0),
            nonce_ctr: AtomicU64::new(0),
            mdns: Mutex::new(None),
            local_addrs: Mutex::new(Vec::new()),
        }
    }
    pub fn now_ms(&self) -> u64 {
        (self.now_fn)()
    }
    pub fn set_outgoing(&self, o: Arc<dyn Outgoing>) {
        *self.outgoing.lock().unwrap() = Some(o);
    }
    fn mode(&self) -> DiscoverabilityMode {
        *self.mode.lock().unwrap()
    }

    pub fn inject_incoming(
        &self,
        bytes: &[u8],
        src: IpAddr,
        heard_iface: Option<IpAddr>,
        now_ms: u64,
    ) {
        let mut store = self.store.lock().unwrap();
        let mut nonce = self.nonce.lock().unwrap();
        let mut rl = self.rl.lock().unwrap();
        handle_incoming_datagram(
            &mut store,
            bytes,
            src,
            heard_iface,
            now_ms,
            &mut nonce,
            &mut rl,
        );
    }

    pub async fn handle_inbound(&self, bytes: &[u8], src: std::net::SocketAddr, now_ms: u64) {
        self.inject_incoming(bytes, src.ip(), None, now_ms);
        if crate::beacon::message_tag(bytes) == Some(2) {
            let ifaces = crate::netinfo::enumerate_interfaces();
            if crate::netinfo::is_local_ip(src.ip(), &ifaces) {
                return;
            }
            let allowed = self.should_reply_to_probe(src.ip(), now_ms);
            tracing::info!(
                peer = %src.ip(),
                port = src.port(),
                allowed,
                "handle_inbound: received Probe"
            );
            if allowed {
                self.reply_to_probe(src).await;
                tracing::info!(
                    peer = %src.ip(),
                    "handle_inbound: replied to Probe with beacon"
                );
            }
        }
    }

    pub fn peers(&self) -> Vec<PeerRecord> {
        self.store
            .lock()
            .unwrap()
            .snapshot()
            .into_iter()
            .cloned()
            .collect()
    }

    pub fn force_transition(&self, device_fingerprint: &str, event: PeerEvent) {
        self.store.lock().unwrap().transition(device_fingerprint, event);
    }

    pub fn set_mode(&self, mode: DiscoverabilityMode) {
        *self.mode.lock().unwrap() = mode;
    }

    pub fn make_beacon(&self, now_ms: u64, nonce: Vec<u8>) -> Beacon {
        Beacon {
            device_name: self.info.device_name.clone(),
            platform: self.info.platform.clone(),
            proto_version: 1,
            capabilities: self.info.capabilities.clone(),
            device_fingerprint: self.info.device_fingerprint.clone(),
            quic_port: self.info.quic_port as u32,
            tcp_port: self.info.tcp_port as u32,
            nonce,
            ts_ms: now_ms,
        }
    }

    pub fn drain_events(&self) -> Vec<PeerStoreEvent> {
        self.store.lock().unwrap().drain_events()
    }

    fn fresh_nonce(&self) -> Vec<u8> {
        let now = self.now_ms().to_le_bytes();
        let ctr = self.nonce_ctr.fetch_add(1, Ordering::Relaxed).to_le_bytes();
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(&now);
        v.extend_from_slice(&ctr);
        v
    }
    async fn send_beacon_to(&self, b: &Beacon, dst: std::net::SocketAddr) {
        let out = self.outgoing.lock().unwrap().clone();
        if let Some(o) = out {
            if let Ok(bytes) = crate::beacon::encode_beacon_tagged(b) {
                let _ = o.send_to(&bytes, dst).await;
            }
        }
    }
    async fn send_goodbye_to(&self, g: &Goodbye, dst: std::net::SocketAddr) {
        let out = self.outgoing.lock().unwrap().clone();
        if let Some(o) = out {
            if let Ok(bytes) = crate::beacon::encode_goodbye_tagged(g) {
                let _ = o.send_to(&bytes, dst).await;
            }
        }
    }
    pub async fn reply_to_probe(&self, src: std::net::SocketAddr) {
        let b = self.make_beacon(self.now_ms(), self.fresh_nonce());
        self.send_beacon_to(
            &b,
            std::net::SocketAddr::new(src.ip(), crate::constants::PRIVET_DISCOVERY_PORT),
        )
        .await;
    }

    fn should_reply_to_probe(&self, src: IpAddr, now_ms: u64) -> bool {
        self.should_announce(now_ms)
            && crate::netinfo::probe_src_is_local_subnet(
                src,
                &crate::netinfo::enumerate_interfaces(),
            )
    }

    pub fn set_start_ms_for_test(&self, ms: u64) {
        *self.start_ms.lock().unwrap() = ms;
    }
    pub fn window_deadline(&self) -> Option<u64> {
        if self.mode() != DiscoverabilityMode::Window {
            return None;
        }
        let start = *self.start_ms.lock().unwrap();
        Some(start + self.config.window_secs.saturating_mul(1000))
    }
    pub fn should_announce(&self, now_ms: u64) -> bool {
        match self.mode() {
            DiscoverabilityMode::Always => true,
            DiscoverabilityMode::Window => self.window_deadline().is_some_and(|d| now_ms < d),
            DiscoverabilityMode::TrustedOnly => false,
        }
    }
    pub fn broadcast_targets(&self) -> Vec<std::net::SocketAddr> {
        let port = self.config.udp_port;
        let mut out: Vec<std::net::SocketAddr> = Vec::new();
        for (addr, prefix, bcast, _) in crate::netinfo::enumerate_interfaces() {
            // IPv6 has no directed broadcast: `directed_broadcast` returns the
            // address unchanged for V6, which would put the interface's *own*
            // unicast address into the beacon target list — a beacon sent
            // straight back to ourselves. Only IPv4 can be broadcast.
            if !addr.is_ipv4() {
                continue;
            }
            let b = bcast.unwrap_or_else(|| crate::netinfo::directed_broadcast(addr, prefix));
            let sa = std::net::SocketAddr::new(b, port);
            if !out.contains(&sa) {
                out.push(sa);
            }
        }
        use std::net::Ipv4Addr;
        let lan = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), port);
        if !out.contains(&lan) {
            out.push(lan);
        }
        out
    }
    pub(crate) fn local_beacon_view(&self) -> crate::beacon::BeaconView {
        crate::beacon::BeaconView {
            device_name: self.info.device_name.clone(),
            platform: self.info.platform.clone(),
            proto_version: 1,
            capabilities: self.info.capabilities.clone(),
            device_fingerprint: self.info.device_fingerprint.clone(),
            quic_port: self.info.quic_port,
            tcp_port: self.info.tcp_port,
            nonce: vec![],
            ts_ms: 0,
        }
    }

    pub fn spawn_beacon_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let mut cancel_rx = self.cancel.subscribe();
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let now = this.now_ms();
                if this.should_announce(now) {
                    let b = this.make_beacon(now, this.fresh_nonce());
                    for dst in this.broadcast_targets() {
                        this.send_beacon_to(&b, dst).await;
                    }
                }
                tokio::select! {
                    biased;
                    _ = cancel_rx.changed() => break,
                    _ = tokio::time::sleep(this.config.beacon_interval) => {}
                }
            }
        })
    }
    pub fn spawn_sweep_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let mut cancel_rx = self.cancel.subscribe();
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                this.sweep_now(this.now_ms());
                tokio::select! {
                    biased;
                    _ = cancel_rx.changed() => break,
                    _ = tokio::time::sleep(crate::constants::SWEEP_INTERVAL) => {}
                }
            }
        })
    }
    pub fn spawn_probe_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let mut cancel_rx = self.cancel.subscribe();
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let now = this.now_ms();
                if this.config.active_scan && this.should_announce(now) {
                    this.send_probe_to_all().await;
                }
                tokio::select! {
                    biased;
                    _ = cancel_rx.changed() => break,
                    _ = tokio::time::sleep(this.config.probe_interval) => {}
                }
            }
        })
    }
    fn sweep_now(&self, now_ms: u64) {
        self.store.lock().unwrap().sweep(
            now_ms,
            self.config.stale_timeout,
            self.config.lost_timeout,
        );
    }
    pub fn cancel(&self) {
        let _ = self.cancel.send(true);
    }

    pub fn on_mdns_resolved(
        &self,
        view: crate::beacon::BeaconView,
        addrs: Vec<IpAddr>,
        now_ms: u64,
    ) {
        let local = self.local_addrs.lock().unwrap().clone();
        let mut store = self.store.lock().unwrap();
        for addr in addrs {
            if local.contains(&addr) {
                continue;
            }
            store.handle_beacon(&view, addr, None, now_ms);
        }
    }
    pub fn spawn_mdns_task(self: Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        let local_addrs: Vec<IpAddr> = crate::netinfo::enumerate_interfaces()
            .into_iter()
            .map(|(a, _, _, _)| a)
            .collect();
        *self.local_addrs.lock().unwrap() = local_addrs.clone();
        let announcer =
            crate::mdns::MdnsAnnouncer::new(&self.local_beacon_view(), local_addrs).ok();
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let browser = crate::mdns::MdnsBrowser::start(tx).ok();
        if announcer.is_none() && browser.is_none() {
            tracing::warn!("mdns init failed (no multicast?); falling back to udp beacon");
            return None;
        }
        *self.mdns.lock().unwrap() = Some(MdnsHandles { announcer, browser });
        let mut cancel_rx = self.cancel.subscribe();
        let this = self.clone();
        let h = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel_rx.changed() => break,
                    r = rx.recv() => match r {
                        Some((view, addrs)) => this.on_mdns_resolved(view, addrs, this.now_ms()),
                        None => break,
                    }
                }
            }
        });
        Some(h)
    }

    pub async fn start(self: &Arc<Self>) -> crate::Result<()> {
        let udp = UdpBeacon::bind_listening(self.config.udp_port).await?;
        self.set_outgoing(udp.sink.clone());
        *self.start_ms.lock().unwrap() = self.now_ms();
        let this = self.clone();
        let mut cancel_rx = self.cancel.subscribe();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    biased;
                    _ = cancel_rx.changed() => break,
                    res = udp.recv(&mut buf) => match res {
                        Ok((n, src)) => {
                            this.handle_inbound(&buf[..n], src, this.now_ms()).await;
                        }
                        Err(_) => break,
                    },
                }
            }
        });
        self.tasks.lock().unwrap().push(handle);
        let bh = self.clone().spawn_beacon_task();
        self.tasks.lock().unwrap().push(bh);
        let sh = self.clone().spawn_sweep_task();
        self.tasks.lock().unwrap().push(sh);
        let ph = self.clone().spawn_probe_task();
        self.tasks.lock().unwrap().push(ph);
        // mDNS（best-effort）
        if let Some(mh) = self.clone().spawn_mdns_task() {
            self.tasks.lock().unwrap().push(mh);
        }
        self.clone().send_probe_to_all().await;
        Ok(())
    }

    async fn send_probe_to_all(&self) {
        if !self.config.active_scan {
            return;
        }
        let p = Probe {
            nonce: self.fresh_nonce(),
            ts_ms: self.now_ms(),
        };
        let Ok(bytes) = crate::beacon::encode_probe_tagged(&p) else {
            return;
        };
        let out = self.outgoing.lock().unwrap().clone();
        if let Some(o) = out {
            for dst in self.broadcast_targets() {
                let _ = o.send_to(&bytes, dst).await;
            }
        }
    }
    pub async fn send_probe_to(&self, dst: std::net::SocketAddr) {
        let p = Probe {
            nonce: self.fresh_nonce(),
            ts_ms: self.now_ms(),
        };
        let Ok(bytes) = crate::beacon::encode_probe_tagged(&p) else {
            return;
        };
        let out = self.outgoing.lock().unwrap().clone();
        if let Some(o) = out {
            let _ = o.send_to(&bytes, dst).await;
        }
    }
    pub async fn refresh(&self) -> crate::Result<()> {
        self.send_probe_to_all().await;
        Ok(())
    }

    pub async fn stop(&self) -> crate::Result<()> {
        let g = Goodbye {
            device_fingerprint: self.info.device_fingerprint.clone(),
        };
        for dst in self.broadcast_targets() {
            self.send_goodbye_to(&g, dst).await;
        }
        let _ = self.cancel.send(true);
        let tasks: Vec<_> = self.tasks.lock().unwrap().drain(..).collect();
        for h in tasks {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), h).await;
        }
        if let Some(m) = self.mdns.lock().unwrap().take() {
            if let Some(a) = m.announcer {
                let _ = a.shutdown();
            }
            if let Some(b) = m.browser {
                let _ = b.shutdown();
            }
        }
        Ok(())
    }
}
