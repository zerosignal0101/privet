//! 传输控制面：transfer_id -> 命令通道 + offer 裁决 + 接受策略。
//! 不可阻塞 I/O（纯内存同步 + tokio 通道），无密钥/无文件。
//! 定义在 privet-transfer 层（低于 privet-core），core 重导出。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};

/// 传输控制命令（ControlMessage 的本地等价注入）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferCommand {
    Cancel,
    Pause,
    Resume,
}

/// 活跃传输注册表：transfer_id -> 命令通道。
/// Engine::cancel_transfer / pause_transfer / resume_transfer 经此注入命令。
pub struct TransferRegistry {
    cmds: Mutex<HashMap<String, mpsc::Sender<TransferCommand>>>,
}

impl TransferRegistry {
    pub fn new() -> Self {
        Self {
            cmds: Mutex::new(HashMap::new()),
        }
    }

    /// 注册一个 tid，返回命令接收端。已存在 tid 覆盖旧 sender（旧接收端关闭）。
    pub fn register(&self, tid: &str) -> mpsc::Receiver<TransferCommand> {
        let (tx, rx) = mpsc::channel(8);
        self.cmds
            .lock()
            .expect("reg lock")
            .insert(tid.to_string(), tx);
        rx
    }

    /// 向 tid 发命令。返回 false = 未注册/已结束（命令丢弃）。
    pub fn send(&self, tid: &str, cmd: TransferCommand) -> bool {
        let g = self.cmds.lock().expect("reg lock");
        if let Some(tx) = g.get(tid) {
            tx.try_send(cmd).is_ok()
        } else {
            false
        }
    }

    /// 注销（transfer 终态时调用）。
    pub fn unregister(&self, tid: &str) {
        self.cmds.lock().expect("reg lock").remove(tid);
    }
}

impl Default for TransferRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// 接受裁决结果：true=接收，false=拒绝。
pub type AcceptDecision = bool;

/// offer 裁决器：transfer_id -> oneshot。
/// receiver 收 offer 后 await；daemon 的 AcceptTransfer IPC 经此 resolve。
pub struct OfferResolver {
    pending: Mutex<HashMap<String, oneshot::Sender<AcceptDecision>>>,
}

impl OfferResolver {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// 登记一个待决 offer，返回裁决接收端。同 tid 重复覆盖旧 sender。
    pub fn await_decision(&self, tid: &str) -> oneshot::Receiver<AcceptDecision> {
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .expect("res lock")
            .insert(tid.to_string(), tx);
        tracing::debug!(transfer_id = %tid, "offer resolver: awaiting decision");
        rx
    }

    /// resolve 一个待决 offer。返回 false = 无此 tid / 已 resolve。
    pub fn resolve(&self, tid: &str, decision: AcceptDecision) -> bool {
        if let Some(tx) = self.pending.lock().expect("res lock").remove(tid) {
            let _ = tx.send(decision);
            tracing::debug!(transfer_id = %tid, accept = decision, "offer resolver: resolved");
            true
        } else {
            tracing::warn!(
                transfer_id = %tid,
                "offer resolver: resolve with no pending decision (resolve-before-register race)"
            );
            false
        }
    }

    /// 清理（transfer 结束/取消时调用，防泄漏）。
    pub fn cancel(&self, tid: &str) {
        tracing::debug!(transfer_id = %tid, "offer resolver: cancelled");
        self.pending.lock().expect("res lock").remove(tid);
    }
}

impl Default for OfferResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// 接受策略：CLI 嵌入 = AutoAccept；守护进程 = Resolver（GUI 经 IPC AcceptTransfer 决定）。
#[derive(Clone)]
pub enum AcceptPolicy {
    /// 一律接收（CLI 嵌入 receive 的 v1 行为；等价 --accept-all-trusted）。
    AutoAccept,
    /// 逐传输由外部裁决（守护进程：GUI 经 AcceptTransfer IPC 决定）。
    Resolver(Arc<OfferResolver>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_before_register_returns_false() {
        let r = OfferResolver::new();
        assert!(
            !r.resolve("t1", true),
            "resolve before await_decision must be false"
        );
        let _rx = r.await_decision("t2");
        assert!(
            r.resolve("t2", true),
            "resolve after await_decision must succeed"
        );
    }

    #[tokio::test]
    async fn await_decision_times_out_when_never_resolved() {
        let r = OfferResolver::new();
        let rx = r.await_decision("t3");
        let got = tokio::time::timeout(std::time::Duration::from_millis(100), rx).await;
        assert!(got.is_err(), "unresolved decision must time out");
    }
}
