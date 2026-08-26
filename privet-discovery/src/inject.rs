//! 注入框架：无真实组播即可测。

use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

use async_trait::async_trait;

use crate::peer::PeerStore;
use crate::udp::{handle_incoming_datagram, NonceCache, Outgoing, RateLimiter};

/// 测试 sink：收集对外数据报（dst, data）。
pub struct CapturedSink {
    inner: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
}

impl CapturedSink {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
        }
    }
    pub fn captured(&self) -> Vec<(Vec<u8>, SocketAddr)> {
        self.inner.lock().unwrap().clone()
    }
}

impl Default for CapturedSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Outgoing for CapturedSink {
    async fn send_to(&self, data: &[u8], dst: SocketAddr) -> crate::Result<()> {
        self.inner.lock().unwrap().push((data.to_vec(), dst));
        Ok(())
    }
}

/// 直接喂核心（无 socket）：`inject_beacon(raw_bytes)`。
pub fn inject_beacon(
    store: &mut PeerStore,
    nonce: &mut NonceCache,
    rl: &mut RateLimiter,
    bytes: &[u8],
    src: IpAddr,
    heard_iface: Option<IpAddr>,
    now_ms: u64,
) {
    handle_incoming_datagram(store, bytes, src, heard_iface, now_ms, nonce, rl);
}

/// `inject_probe(raw)`（等价于把 probe 数据报喂入核心；核心当前对 probe 仅防重放，响应在 Engine）。
pub fn inject_probe(
    _store: &mut PeerStore,
    nonce: &mut NonceCache,
    rl: &mut RateLimiter,
    bytes: &[u8],
    src: IpAddr,
    _now_ms: u64,
) {
    if !rl.allow(src) {
        return;
    }
    if let Ok(p) = crate::beacon::decode_probe_tagged(bytes) {
        let _ = nonce.check_and_insert(&p.nonce);
    }
    // probe 不更新 PeerStore（无对端信息）；Engine 收到 probe 时回发自身 beacon（Task 11）。
}
