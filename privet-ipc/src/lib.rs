//! Versioned local IPC contract and asynchronous client for Privet frontends.
//!
//! This crate deliberately has no dependency on `privet-core`. CLI and GUI clients should depend
//! on this crate (or bindings generated from its schema), never on the embedded engine.

pub mod client;
pub mod codec;
pub mod endpoint;
pub mod error;
pub mod protocol;

pub use client::IpcClient;
pub use endpoint::{default_endpoint, LocalEndpoint, LocalListener, LocalStream};
pub use error::{IpcError, Result};
pub use protocol::*;
