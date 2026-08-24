//! 可注入 I/O：PairingChannel（控制帧收发）+ PairingClock（时钟）+ 测试夹具。
use async_trait::async_trait;
use privet_protocol::ControlFrame;
use tokio::sync::mpsc;

use crate::code::Now;
use crate::PairingError;

/// 配对时钟（继承 code::Now）。
pub trait PairingClock: Now {}
impl<T: Now> PairingClock for T {}

/// 控制流通道：收发 ControlFrame（PairingInit/Confirm/Result/ResultAck 封装于内）。
#[async_trait]
pub trait PairingChannel: Send {
    async fn send(&mut self, frame: ControlFrame) -> Result<(), PairingError>;
    async fn recv(&mut self) -> Result<ControlFrame, PairingError>;
}

/// 进程内回环通道对（A<->B 双向 mpsc）。
pub struct LoopbackChannel {
    tx: mpsc::Sender<ControlFrame>,
    rx: mpsc::Receiver<ControlFrame>,
}

impl LoopbackChannel {
    /// 返回 (A, B)：A.send 进 B.recv，B.send 进 A.recv。
    pub fn pair(cap: usize) -> (Self, Self) {
        let (atx, brx) = mpsc::channel(cap);
        let (btx, arx) = mpsc::channel(cap);
        (Self { tx: atx, rx: arx }, Self { tx: btx, rx: brx })
    }
}

#[async_trait]
impl PairingChannel for LoopbackChannel {
    async fn send(&mut self, frame: ControlFrame) -> Result<(), PairingError> {
        self.tx
            .send(frame)
            .await
            .map_err(|_| PairingError::TransportFailed("channel closed".into()))
    }
    async fn recv(&mut self) -> Result<ControlFrame, PairingError> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| PairingError::TransportFailed("channel closed".into()))
    }
}

/// 丢前 `n` 帧的通道包装（测重发/丢失）。
pub struct LossyChannel {
    inner: Box<dyn PairingChannel>,
    drop_remaining: usize,
}

impl LossyChannel {
    pub fn drop_first(inner: Box<dyn PairingChannel>, n: usize) -> Self {
        Self {
            inner,
            drop_remaining: n,
        }
    }
}

#[async_trait]
impl PairingChannel for LossyChannel {
    async fn send(&mut self, frame: ControlFrame) -> Result<(), PairingError> {
        self.inner.send(frame).await
    }
    async fn recv(&mut self) -> Result<ControlFrame, PairingError> {
        loop {
            let f = self.inner.recv().await?;
            if self.drop_remaining > 0 {
                self.drop_remaining -= 1;
                continue;
            }
            return Ok(f);
        }
    }
}

/// 可设时钟（测试过期/超时）。
pub struct MutableClock(std::sync::atomic::AtomicU64);
impl MutableClock {
    pub fn new() -> Self {
        Self(0.into())
    }
    pub fn set(&self, ms: u64) {
        self.0.store(ms, std::sync::atomic::Ordering::SeqCst);
    }
}
impl Default for MutableClock {
    fn default() -> Self {
        Self::new()
    }
}
impl Now for MutableClock {
    fn now_ms(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}
