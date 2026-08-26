//! 配对适配器：PairingChannel over Stream + SystemPairingClock。

use async_trait::async_trait;
use privet_protocol::ControlFrame;
use privet_security::channel::PairingChannel;
use privet_security::code::Now;
use privet_security::PairingError;
use privet_transport::frame_io::{recv_control, send_control};
use privet_transport::Stream;

/// 控制流包装为 PairingChannel（send/recv ControlFrame；TransportError -> PairingError）。
pub struct StreamPairingChannel {
    inner: Box<dyn Stream>,
}

impl StreamPairingChannel {
    pub fn new(inner: Box<dyn Stream>) -> Self {
        Self { inner }
    }
    /// 取回底层流（配对完成后移交传送阶段复用）。
    pub fn into_inner(self) -> Box<dyn Stream> {
        self.inner
    }
}

#[async_trait]
impl PairingChannel for StreamPairingChannel {
    async fn send(&mut self, frame: ControlFrame) -> Result<(), PairingError> {
        send_control(self.inner.as_mut(), &frame)
            .await
            .map_err(|e| PairingError::TransportFailed(e.to_string()))
    }
    async fn recv(&mut self) -> Result<ControlFrame, PairingError> {
        recv_control(self.inner.as_mut())
            .await
            .map_err(|e| PairingError::TransportFailed(e.to_string()))
    }
}

/// 系统时钟实现 PairingClock（now_ms 毫秒）。
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemPairingClock;
impl Now for SystemPairingClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}
// PairingClock 有 blanket impl `<T: Now> PairingClock for T`，无需显式 impl。

// ===== 配对编排（Task B10）=====
use privet_crypto::identity::Identity;
use privet_crypto::pake::Spake2Backend;
use privet_security::channel::PairingClock;
use privet_security::commit::{wait_for_ack, PendingProof, ProofStore};
use privet_security::constants::PAIRING_ACK_TIMEOUT_SECS;
use privet_security::session::{run_initiator, run_responder, PairingOutcome, SessionInputs};
use privet_security::trust::TrustStore;
use std::time::Duration;

/// I 侧编排：跑 run_initiator，进 Pending（持久化 proof），再 wait_for_ack。
pub async fn run_pairing_initiator(
    local: &Identity,
    inputs: &SessionInputs,
    channel: &mut dyn privet_security::channel::PairingChannel,
    clock: &dyn PairingClock,
    trust: &dyn TrustStore,
    proof_store: &dyn ProofStore,
    pake: &Spake2Backend,
) -> crate::Result<PairingOutcome> {
    // run_initiator 内部持久化 proof + wait_for_ack 自动清 proof
    Ok(run_initiator(local, inputs, channel, clock, trust, pake, proof_store).await?)
}

/// R 侧编排（幂等去重）。
pub async fn run_pairing_responder(
    local: &Identity,
    inputs: &SessionInputs,
    channel: &mut dyn privet_security::channel::PairingChannel,
    clock: &dyn PairingClock,
    trust: &dyn TrustStore,
    pake: &Spake2Backend,
) -> crate::Result<PairingOutcome> {
    Ok(run_responder(local, inputs, channel, clock, trust, pake).await?)
}

/// 崩溃恢复：从持久化 proof 重发 + 等 ack。
pub async fn resume_pending_pairing(
    channel: &mut dyn privet_security::channel::PairingChannel,
    clock: &dyn PairingClock,
    trust: &dyn TrustStore,
    proof: &PendingProof,
    proof_store: &dyn ProofStore,
) -> crate::Result<PairingOutcome> {
    Ok(wait_for_ack(
        channel,
        clock,
        trust,
        proof,
        proof_store,
        Duration::from_secs(PAIRING_ACK_TIMEOUT_SECS),
    )
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bytes::BytesMut;
    use privet_protocol::{control_frame::Payload, control_message, Cancel, ControlMessage};

    struct LoopbackStream {
        buf: Vec<u8>,
        pos: usize,
    }
    #[async_trait]
    impl Stream for LoopbackStream {
        async fn send_all(&mut self, buf: &[u8]) -> Result<(), privet_transport::TransportError> {
            self.buf.extend_from_slice(buf);
            Ok(())
        }
        async fn recv_exact(
            &mut self,
            n: usize,
        ) -> Result<BytesMut, privet_transport::TransportError> {
            if self.buf.len() - self.pos < n {
                return Err(privet_transport::TransportError::Closed("eof".into()));
            }
            let mut out = BytesMut::zeroed(n);
            out.copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            Ok(out)
        }
        async fn reset(self: Box<Self>, _c: u32) {}
    }

    #[tokio::test]
    async fn pairing_channel_roundtrip_and_into_inner() {
        let s = Box::new(LoopbackStream {
            buf: Vec::new(),
            pos: 0,
        });
        let mut ch = StreamPairingChannel::new(s);
        let f = ControlFrame {
            payload: Some(Payload::Control(ControlMessage {
                msg: Some(control_message::Msg::Cancel(Cancel {
                    transfer_id: "t".into(),
                    reason: "x".into(),
                })),
            })),
        };
        ch.send(f.clone()).await.unwrap();
        let got = ch.recv().await.unwrap();
        assert_eq!(got.payload, f.payload);
        let _stream: Box<dyn Stream> = ch.into_inner();
    }
}
