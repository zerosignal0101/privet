//! Thread-safe settings that the daemon may change while listeners are running.
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use privet_transfer::CollisionPolicy;

use crate::AcceptPolicy;

/// Runtime receive policy shared by both transport accept loops.
pub struct RuntimeSettings {
    accept_all_trusted: AtomicBool,
    base_accept_policy: Mutex<AcceptPolicy>,
    on_collision: Mutex<CollisionPolicy>,
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
