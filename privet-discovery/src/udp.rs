//! UDP beacon 路径：核心 handle + I/O + 速率限制 + nonce 去重 + Outgoing trait。

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

use privet_protocol::{Beacon, Probe};

use crate::beacon::{validate_beacon, BeaconView};
use crate::constants::{
    NONCE_CACHE_SIZE, RATE_LIMIT_MAX_PER_WINDOW, RATE_LIMIT_WINDOW,
};
use crate::error::Result;
use crate::peer::PeerStore;

/// nonce 去重缓存（最近 NONCE_CACHE_SIZE 条）。
pub struct NonceCache {
    seen: VecDeque<Vec<u8>>,
}

impl NonceCache {
    pub fn new() -> Self {
        Self {
            seen: VecDeque::with_capacity(NONCE_CACHE_SIZE),
        }
    }
    /// 返回 true=新 nonce（未见）；false=重复。
    pub fn check_and_insert(&mut self, nonce: &[u8]) -> bool {
        if self.seen.iter().any(|n| n == nonce) {
            return false;
        }
        if self.seen.len() >= NONCE_CACHE_SIZE {
            self.seen.pop_front();
        }
        self.seen.push_back(nonce.to_vec());
        true
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

/// 每源 IP 速率限制（窗口内上限）。
pub struct RateLimiter {
    window: std::time::Instant,
    counts: std::collections::HashMap<IpAddr, usize>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            window: std::time::Instant::now(),
            counts: Default::default(),
        }
    }
    /// 返回 true=允许；false=超限丢弃。
    pub fn allow(&mut self, src: IpAddr) -> bool {
        if self.window.elapsed() > RATE_LIMIT_WINDOW {
            self.window = std::time::Instant::now();
            self.counts.clear();
        }
        let c = self.counts.entry(src).or_insert(0);
        if *c >= RATE_LIMIT_MAX_PER_WINDOW {
            return false;
        }
        *c += 1;
        true
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// 核心：处理入站 UDP 数据报（beacon/probe/goodbye）。纯逻辑，注入框架直接调。
/// `heard_iface`=收到该 beacon 的本机接口（None=未知）。
pub fn handle_incoming_datagram(
    store: &mut PeerStore,
    bytes: &[u8],
    src: IpAddr,
    heard_iface: Option<IpAddr>,
    now_ms: u64,
    nonce_cache: &mut NonceCache,
    rate_limiter: &mut RateLimiter,
) {
    if !rate_limiter.allow(src) {
        return; // 洪泛丢弃
    }
    // 消息类型标签首字节鉴别
    let tag = bytes.first().copied();
    match tag {
        Some(1) => {
            // Beacon
            let b = match crate::beacon::decode_beacon_tagged(bytes) {
                Ok(b) => b,
                Err(_) => return,
            };
            if validate_beacon(&b, now_ms).is_err() {
                return;
            }
            if !nonce_cache.check_and_insert(&b.nonce) {
                return; // 重放丢弃
            }
            store.handle_beacon(&BeaconView::from_beacon(&b), src, heard_iface, now_ms);
        }
        Some(2) => {
            // Probe — 防重放；上层应回 beacon
            if let Ok(p) = crate::beacon::decode_probe_tagged(bytes) {
                let _ = nonce_cache.check_and_insert(&p.nonce);
            }
        }
        Some(3) => {
            // Goodbye (graceful shutdown)
            if let Ok(g) = crate::beacon::decode_goodbye_tagged(bytes) {
                store.handle_goodbye(&g.device_fingerprint);
            }
        }
        _ => {} // 未知标签静默丢弃
    }
}

/// 对外广播 sink（生产=UDP，测试=收集）。
#[async_trait::async_trait]
pub trait Outgoing: Send + Sync {
    async fn send_to(&self, data: &[u8], dst: std::net::SocketAddr) -> Result<()>;
}

/// 生产 sink：UDP socket 广播。
pub struct UdpSink {
    sock: UdpSocket,
}

impl UdpSink {
    pub async fn bind(iface_ip: IpAddr) -> Result<Self> {
        let sock = UdpSocket::bind(std::net::SocketAddr::new(iface_ip, 0)).await?;
        let _ = sock.set_broadcast(true);
        Ok(Self { sock })
    }
}

#[async_trait::async_trait]
impl Outgoing for UdpSink {
    async fn send_to(&self, data: &[u8], dst: std::net::SocketAddr) -> Result<()> {
        self.sock.send_to(data, dst).await?;
        Ok(())
    }
}

/// UDP beacon I/O 持有者。
pub struct UdpBeacon {
    pub listen: UdpSocket,
    pub sink: Arc<dyn Outgoing>,
}

impl UdpBeacon {
    pub async fn bind_listening(port: u16) -> Result<Self> {
        let listen = UdpSocket::bind(("0.0.0.0", port)).await?;
        // 发送用 0.0.0.0 绑定（按接口定向广播由调用方指定 dst）。
        let sink = UdpSink::bind("0.0.0.0".parse().unwrap()).await?;
        Ok(Self {
            listen,
            sink: Arc::new(sink),
        })
    }

    pub async fn send_beacon(&self, b: &Beacon, dst: std::net::SocketAddr) -> Result<()> {
        let bytes = crate::beacon::encode_beacon_tagged(b)?;
        self.sink.send_to(&bytes, dst).await
    }
    pub async fn send_probe(&self, p: &Probe, dst: std::net::SocketAddr) -> Result<()> {
        let bytes = crate::beacon::encode_probe_tagged(p)?;
        self.sink.send_to(&bytes, dst).await
    }
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr)> {
        Ok(self.listen.recv_from(buf).await?)
    }
}
