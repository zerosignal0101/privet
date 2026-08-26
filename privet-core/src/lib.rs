//! Daemon-side orchestration for Privet discovery, pairing, and transfers.
//!
//! Frontends must use the daemon IPC contract described in `SPEC.md`; direct engine embedding is
//! reserved for the daemon and integration tests.

#![allow(rustdoc::invalid_html_tags)]

pub mod constants;
pub mod error;
pub mod config;
pub mod events;
pub mod adapters;
pub mod pairing;
pub mod peers;
pub mod identity_tls;
pub mod auth;
pub mod connection;
pub mod reconnect;
pub mod transfer_control;
pub mod transfer;

pub mod ops;
pub mod discovery;

pub mod runtime;
pub mod engine;

pub use config::EngineConfig;
pub use error::{CoreError, Result};
pub use events::EngineEvent;
pub use transfer_control::{
    AcceptDecision, AcceptPolicy, OfferResolver, TransferCommand, TransferRegistry,
};
pub use runtime::RuntimeSettings;
pub use engine::Engine;
