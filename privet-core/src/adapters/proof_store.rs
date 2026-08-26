//! PendingProof 持久化复用 StorageTrustStore（同一 SQLite 句柄）；实现见 trust_store.rs。
pub use crate::adapters::trust_store::StorageTrustStore;
