
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferCommand {
    Cancel,
    Pause,
    Resume,
}

pub struct TransferRegistry {
    cmds: Mutex<HashMap<String, mpsc::Sender<TransferCommand>>>,
}

impl TransferRegistry {
    pub fn new() -> Self {
        Self {
            cmds: Mutex::new(HashMap::new()),
        }
    }

    pub fn register(&self, tid: &str) -> mpsc::Receiver<TransferCommand> {
        let (tx, rx) = mpsc::channel(8);
        self.cmds
            .lock()
            .expect("reg lock")
            .insert(tid.to_string(), tx);
        rx
    }

    pub fn send(&self, tid: &str, cmd: TransferCommand) -> bool {
        let g = self.cmds.lock().expect("reg lock");
        if let Some(tx) = g.get(tid) {
            tx.try_send(cmd).is_ok()
        } else {
            false
        }
    }

    pub fn unregister(&self, tid: &str) {
        self.cmds.lock().expect("reg lock").remove(tid);
    }

    pub fn active_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.cmds.lock().expect("reg lock").keys().cloned().collect();
        ids.sort();
        ids
    }
}

impl Default for TransferRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub type AcceptDecision = bool;

pub struct OfferResolver {
    pending: Mutex<HashMap<String, oneshot::Sender<AcceptDecision>>>,
}

impl OfferResolver {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn await_decision(&self, tid: &str) -> oneshot::Receiver<AcceptDecision> {
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .expect("res lock")
            .insert(tid.to_string(), tx);
        tracing::debug!(transfer_id = %tid, "offer resolver: awaiting decision");
        rx
    }

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

#[derive(Clone)]
pub enum AcceptPolicy {
    AutoAccept,
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
