//! 传送生命周期状态机。

/// Paused 原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PausedReason {
    User,
    DiskFull,
    PermissionBlocked,
    ReconnectExhausted,
}

/// Failed 属性（对齐 TransferFailed{retryable,part_kept}）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferFailed {
    pub error_code: &'static str,
    pub error_message: String,
    pub retryable: bool,
    pub part_kept: bool,
}

/// 传送状态。瞬时态 Reconnecting 不作持久态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferState {
    Preparing,
    Offered,
    Scheduled,
    Transferring,
    SendingDone,
    Verified { ok: bool },
    Completed,
    VerifyFailed,
    Cancelled,
    Paused { reason: PausedReason },
    Reconnecting,
    Failed(TransferFailed),
}

impl TransferState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed(_))
    }

    /// 检查状态迁移是否合法。返回 Ok(to) 或 Err 说明。
    pub fn transition(
        from: &TransferState,
        to: TransferState,
    ) -> Result<TransferState, &'static str> {
        use TransferState::*;
        let legal = matches!(
            (from, &to),
            (Preparing, Offered)
                | (Offered, Scheduled)
                | (Scheduled, Transferring)
                | (Transferring, SendingDone)
                | (SendingDone, Verified { .. })
                | (Verified { ok: true }, Completed)
                | (Transferring, Paused { .. })
                | (Paused { .. }, Transferring)
                | (Reconnecting, Transferring)
                | (Transferring, Reconnecting)
                | (_, Cancelled)
                | (_, Failed(_))
        );
        if legal {
            Ok(to)
        } else {
            Err("illegal transition")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_states() {
        assert!(TransferState::Completed.is_terminal());
        assert!(TransferState::Cancelled.is_terminal());
        assert!(TransferState::Failed(TransferFailed {
            error_code: "aborted",
            error_message: "x".into(),
            retryable: false,
            part_kept: true,
        })
        .is_terminal());
        assert!(!TransferState::Transferring.is_terminal());
        assert!(!TransferState::Paused {
            reason: PausedReason::User,
        }
        .is_terminal());
    }
}
