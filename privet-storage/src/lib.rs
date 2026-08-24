//! privet-storage：信任库/地址簿/历史/续传元数据持久化。
//!
//! 两套机制：(A) SQLite 单库 + WAL + 迁移；(B) 自包含 sidecar `.part.meta`。

pub mod constants;
pub mod error;
pub mod path_guard;
pub mod sidecar;
pub mod resume;
pub mod staging;
pub mod schema_v1;
pub mod db;
pub mod migration;
pub mod trust;
pub mod addresses;
pub mod history;

pub use constants::*;
pub use error::StorageError;

// prost-build 0.13 生成扁平类型（无嵌套 `pub mod privet { pub mod storage { pub mod v1 } }`），直接 include。
include!(concat!(env!("OUT_DIR"), "/privet.storage.v1.rs"));
