//! 可注入 I/O：ControlChannel（控制帧）+ DataChannel（数据帧+raw）+ 测试夹具。
//! 镜像 privet-security::channel 的注入范式；引擎核心只消费这两个 trait。

use async_trait::async_trait;
use bytes::BytesMut;
use privet_protocol::{ControlFrame, DataFrame};
use tokio::sync::mpsc;

use crate::error::{Result, TransferError};

/// 控制流通道：收发 ControlFrame（control 交错、cancel 响应）。
#[async_trait]
pub trait ControlChannel: Send {
    async fn send(&mut self, frame: ControlFrame) -> Result<()>;
    async fn recv(&mut self) -> Result<ControlFrame>;
}

/// 数据流通道：收发 DataFrame(+raw)。raw 为 ChunkHeader 后随的块字节。
#[async_trait]
pub trait DataChannel: Send {
    async fn send(&mut self, frame: DataFrame, raw: Option<&[u8]>) -> Result<()>;
    async fn recv(&mut self) -> Result<(DataFrame, Option<BytesMut>)>;
}

fn closed_err() -> TransferError {
    TransferError::Transport("channel closed".into())
}

// ===== Loopback =====

pub struct LoopbackControlChannel {
    tx: mpsc::Sender<ControlFrame>,
    rx: mpsc::Receiver<ControlFrame>,
}
impl LoopbackControlChannel {
    pub fn pair(cap: usize) -> (Self, Self) {
        let (atx, brx) = mpsc::channel(cap);
        let (btx, arx) = mpsc::channel(cap);
        (Self { tx: atx, rx: arx }, Self { tx: btx, rx: brx })
    }
    /// 取出底层 tx（测试用：从外部发帧给另一端）。
    pub fn sender(&self) -> mpsc::Sender<ControlFrame> {
        self.tx.clone()
    }
}
#[async_trait]
impl ControlChannel for LoopbackControlChannel {
    async fn send(&mut self, frame: ControlFrame) -> Result<()> {
        self.tx.send(frame).await.map_err(|_| closed_err())
    }
    async fn recv(&mut self) -> Result<ControlFrame> {
        self.rx.recv().await.ok_or_else(closed_err)
    }
}

/// 数据帧 + raw 一起传送的载荷。
struct DataItem {
    frame: DataFrame,
    raw: Option<Vec<u8>>,
}
pub struct LoopbackDataChannel {
    tx: mpsc::Sender<DataItem>,
    rx: mpsc::Receiver<DataItem>,
}
impl LoopbackDataChannel {
    pub fn pair(cap: usize) -> (Self, Self) {
        let (atx, brx) = mpsc::channel(cap);
        let (btx, arx) = mpsc::channel(cap);
        (Self { tx: atx, rx: arx }, Self { tx: btx, rx: brx })
    }
}
#[async_trait]
impl DataChannel for LoopbackDataChannel {
    async fn send(&mut self, frame: DataFrame, raw: Option<&[u8]>) -> Result<()> {
        self.tx
            .send(DataItem {
                frame,
                raw: raw.map(|r| r.to_vec()),
            })
            .await
            .map_err(|_| closed_err())
    }
    async fn recv(&mut self) -> Result<(DataFrame, Option<BytesMut>)> {
        let item = self.rx.recv().await.ok_or_else(closed_err)?;
        Ok((
            item.frame,
            item.raw.map(|v| {
                let mut b = BytesMut::with_capacity(v.len());
                b.extend_from_slice(&v);
                b
            }),
        ))
    }
}

// ===== Lossy（recv 侧丢前 N 帧）=====

pub struct LossyControlChannel {
    inner: Box<dyn ControlChannel>,
    drop_remaining: usize,
}
impl LossyControlChannel {
    pub fn drop_first(inner: Box<dyn ControlChannel>, n: usize) -> Self {
        Self {
            inner,
            drop_remaining: n,
        }
    }
}
#[async_trait]
impl ControlChannel for LossyControlChannel {
    async fn send(&mut self, frame: ControlFrame) -> Result<()> {
        self.inner.send(frame).await
    }
    async fn recv(&mut self) -> Result<ControlFrame> {
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

pub struct LossyDataChannel {
    inner: Box<dyn DataChannel>,
    drop_remaining: usize,
}
impl LossyDataChannel {
    pub fn drop_first(inner: Box<dyn DataChannel>, n: usize) -> Self {
        Self {
            inner,
            drop_remaining: n,
        }
    }
}
#[async_trait]
impl DataChannel for LossyDataChannel {
    async fn send(&mut self, frame: DataFrame, raw: Option<&[u8]>) -> Result<()> {
        self.inner.send(frame, raw).await
    }
    async fn recv(&mut self) -> Result<(DataFrame, Option<BytesMut>)> {
        loop {
            let item = self.inner.recv().await?;
            if self.drop_remaining > 0 {
                self.drop_remaining -= 1;
                continue;
            }
            return Ok(item);
        }
    }
}

// ===== Throttle（recv 侧插入延迟，模拟慢链路使 500ms 空闲不触发）=====

/// 慢链路模拟：对 `recv()` 插入固定延迟，使接收方 500ms 空闲 flush 永不触发。
/// 配合 CHUNK_ACK_INTERVAL（已降到 16 < INFLIGHT_TOTAL_CAP 32）+ 周期 flush 可防死锁；
/// 旧版 64（> 32）时复现 ack 死锁 -> ChunkCorrupt。
pub struct ThrottledDataChannel {
    inner: Box<dyn DataChannel>,
    delay: std::time::Duration,
}
impl ThrottledDataChannel {
    pub fn new(inner: Box<dyn DataChannel>, delay: std::time::Duration) -> Self {
        Self { inner, delay }
    }
}
#[async_trait]
impl DataChannel for ThrottledDataChannel {
    async fn send(&mut self, frame: DataFrame, raw: Option<&[u8]>) -> Result<()> {
        self.inner.send(frame, raw).await
    }
    async fn recv(&mut self) -> Result<(DataFrame, Option<BytesMut>)> {
        tokio::time::sleep(self.delay).await;
        self.inner.recv().await
    }
}

// ===== Reorder（缓冲前 N 帧后倒序释放）=====

pub struct ReorderDataChannel {
    inner: Box<dyn DataChannel>,
    buffer: Vec<(DataFrame, Option<BytesMut>)>,
    hold: usize,
    drained: bool,
}
impl ReorderDataChannel {
    pub fn buffer_and_reverse(inner: Box<dyn DataChannel>, hold: usize) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
            hold,
            drained: false,
        }
    }
}
#[async_trait]
impl DataChannel for ReorderDataChannel {
    async fn send(&mut self, frame: DataFrame, raw: Option<&[u8]>) -> Result<()> {
        self.inner.send(frame, raw).await
    }
    async fn recv(&mut self) -> Result<(DataFrame, Option<BytesMut>)> {
        if self.drained {
            return self.inner.recv().await;
        }
        if self.buffer.is_empty() {
            while self.buffer.len() < self.hold {
                self.buffer.push(self.inner.recv().await?);
            }
        }
        let item = self.buffer.pop().unwrap();
        if self.buffer.is_empty() {
            self.drained = true;
        }
        Ok(item)
    }
}

// ===== Latch（前 K 帧持有到第 K+1 帧到达后按序释放，测 manifest-late）=====

pub struct LatchControlChannel {
    inner: Box<dyn ControlChannel>,
    held: Vec<ControlFrame>,
    latch: usize,
    released: bool,
}
impl LatchControlChannel {
    pub fn hold_first(inner: Box<dyn ControlChannel>, latch: usize) -> Self {
        Self {
            inner,
            held: Vec::new(),
            latch,
            released: false,
        }
    }
}
#[async_trait]
impl ControlChannel for LatchControlChannel {
    async fn send(&mut self, frame: ControlFrame) -> Result<()> {
        self.inner.send(frame).await
    }
    async fn recv(&mut self) -> Result<ControlFrame> {
        if self.released {
            if !self.held.is_empty() {
                return Ok(self.held.remove(0));
            }
            return self.inner.recv().await;
        }
        while self.held.len() < self.latch {
            self.held.push(self.inner.recv().await?);
        }
        let trigger = self.inner.recv().await?;
        self.released = true;
        self.held.push(trigger);
        Ok(self.held.remove(0))
    }
}
