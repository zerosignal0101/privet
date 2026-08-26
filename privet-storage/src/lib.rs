//! SQLite persistence, transfer history, staging, and resume sidecars.

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

include!(concat!(env!("OUT_DIR"), "/privet.storage.v1.rs"));
