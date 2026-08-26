//! 运行时可变配置（AcceptPolicy 运行时切换）。
//!
//! 守护进程启动时把 `ServeOptions` 的初值 seed 进 `RuntimeSettings`；之后 acceptor
//! **每连接**从 `RuntimeSettings` 读取当前生效值，而非用启动时的固定克隆。这样
//! IPC `SetConfig` 即可立即改变入站行为（accept_all_trusted / on_collision / save_dir）。
//!
//! 向后兼容：`effective_accept_policy = flag ? AutoAccept : base`。所有现有调用点
//! （accept_all_trusted=true+AutoAccept / daemon false+Resolver / ops_pair false+AutoAccept）
//! 行为不变。
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use privet_transfer::CollisionPolicy;

use crate::AcceptPolicy;

/// 运行时可变配置：acceptor 每连接读取的“当前值”。
///
/// 非 runtime 键（端口/超时/块大小/device_name/discoverable/history_limit）不经此结构--
/// 它们绑定 socket / 注入运行任务，仅持久化到 config 文件，重启生效。
pub struct RuntimeSettings {
    /// true=受信对端自动接收（AutoAccept）；false=用 base（daemon 通常 Resolver）。
    accept_all_trusted: AtomicBool,
    /// 启动种子策略（daemon=Resolver，CLI 嵌入=AutoAccept）。flag=false 时生效。
    base_accept_policy: Mutex<AcceptPolicy>,
    /// 下一次入站接收的冲突策略。
    on_collision: Mutex<CollisionPolicy>,
    /// 下一次入站接收的落地目录。
    save_dir: Mutex<PathBuf>,
}

impl RuntimeSettings {
    pub fn new(
        accept_all_trusted: bool,
        base_accept_policy: AcceptPolicy,
        on_collision: CollisionPolicy,
        save_dir: PathBuf,
    ) -> Self {
        Self {
            accept_all_trusted: AtomicBool::new(accept_all_trusted),
            base_accept_policy: Mutex::new(base_accept_policy),
            on_collision: Mutex::new(on_collision),
            save_dir: Mutex::new(save_dir),
        }
    }

    /// 当前生效的接受策略（acceptor 每连接调用）。
    pub fn effective_accept_policy(&self) -> AcceptPolicy {
        if self.accept_all_trusted.load(Ordering::SeqCst) {
            AcceptPolicy::AutoAccept
        } else {
            self.base_accept_policy
                .lock()
                .expect("base_accept_policy lock")
                .clone()
        }
    }

    pub fn accept_all_trusted(&self) -> bool {
        self.accept_all_trusted.load(Ordering::SeqCst)
    }

    pub fn set_accept_all_trusted(&self, v: bool) {
        self.accept_all_trusted.store(v, Ordering::SeqCst);
    }

    /// serve 启动种子（base_accept_policy）。daemon=Resolver，CLI 嵌入=AutoAccept。
    pub fn set_base_accept_policy(&self, v: AcceptPolicy) {
        *self
            .base_accept_policy
            .lock()
            .expect("base_accept_policy lock") = v;
    }

    pub fn on_collision(&self) -> CollisionPolicy {
        *self.on_collision.lock().expect("on_collision lock")
    }

    pub fn set_on_collision(&self, v: CollisionPolicy) {
        *self.on_collision.lock().expect("on_collision lock") = v;
    }

    pub fn save_dir(&self) -> PathBuf {
        self.save_dir.lock().expect("save_dir lock").clone()
    }

    pub fn set_save_dir(&self, v: PathBuf) {
        *self.save_dir.lock().expect("save_dir lock") = v;
    }

    /// 按 ConfigFile 键名应用一个 runtime 值（供 IPC SetConfig 复用）。
    /// 仅接受 runtime 键；非 runtime 键返回 Err（调用方应仅持久化、标记 restart_required）。
    pub fn apply_key(&self, key: &str, value: &str) -> crate::Result<()> {
        match key {
            "accept_all_trusted" => {
                let v: bool = value
                    .parse()
                    .map_err(|_| crate::CoreError::Internal(format!("invalid bool: {value}")))?;
                self.set_accept_all_trusted(v);
                Ok(())
            }
            "on_collision" | "collision" => {
                let v = match value {
                    "skip" => CollisionPolicy::Skip,
                    "overwrite" => CollisionPolicy::Overwrite,
                    "rename" => CollisionPolicy::Rename,
                    _ => {
                        return Err(crate::CoreError::Internal(format!(
                            "invalid collision: {value}"
                        )))
                    }
                };
                self.set_on_collision(v);
                Ok(())
            }
            "save_dir" => {
                self.set_save_dir(PathBuf::from(value));
                Ok(())
            }
            _ => Err(crate::CoreError::Internal(format!(
                "not a runtime key: {key}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OfferResolver;

    fn resolver() -> AcceptPolicy {
        AcceptPolicy::Resolver(std::sync::Arc::new(OfferResolver::new()))
    }

    #[test]
    fn flag_true_overrides_base_to_autoaccept() {
        let rt = RuntimeSettings::new(
            false,
            resolver(),
            CollisionPolicy::Rename,
            PathBuf::from("."),
        );
        assert!(matches!(
            rt.effective_accept_policy(),
            AcceptPolicy::Resolver(_)
        ));
        rt.set_accept_all_trusted(true);
        assert!(matches!(
            rt.effective_accept_policy(),
            AcceptPolicy::AutoAccept
        ));
    }

    #[test]
    fn flag_false_keeps_base_autoaccept() {
        // ops_pair 风格：base=AutoAccept, flag=false -> 仍 AutoAccept（向后兼容）。
        let rt = RuntimeSettings::new(
            false,
            AcceptPolicy::AutoAccept,
            CollisionPolicy::Rename,
            PathBuf::from("."),
        );
        assert!(matches!(
            rt.effective_accept_policy(),
            AcceptPolicy::AutoAccept
        ));
    }

    #[test]
    fn apply_key_sets_runtime_values() {
        let rt = RuntimeSettings::new(
            false,
            resolver(),
            CollisionPolicy::Rename,
            PathBuf::from("."),
        );
        rt.apply_key("accept_all_trusted", "true").unwrap();
        assert!(rt.accept_all_trusted());
        assert!(matches!(
            rt.effective_accept_policy(),
            AcceptPolicy::AutoAccept
        ));

        rt.apply_key("on_collision", "skip").unwrap();
        assert_eq!(rt.on_collision(), CollisionPolicy::Skip);

        rt.apply_key("save_dir", "/tmp/x").unwrap();
        assert_eq!(rt.save_dir(), PathBuf::from("/tmp/x"));

        // 非 runtime 键拒绝。
        assert!(rt.apply_key("quic_port", "50000").is_err());
        assert!(rt.apply_key("bogus", "x").is_err());
    }

    #[test]
    fn apply_key_rejects_invalid_values() {
        let rt = RuntimeSettings::new(
            false,
            AcceptPolicy::AutoAccept,
            CollisionPolicy::Rename,
            PathBuf::from("."),
        );
        assert!(rt.apply_key("accept_all_trusted", "maybe").is_err());
        assert!(rt.apply_key("on_collision", "bogus").is_err());
    }
}
