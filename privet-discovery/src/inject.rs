
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

use async_trait::async_trait;

use crate::peer::PeerStore;
use crate::udp::{handle_incoming_datagram, NonceCache, Outgoing, RateLimiter};

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
}
