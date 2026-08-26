//! privet-core：Engine 集成层。把 discovery+transport+security+transfer+storage 缝接成可运行引擎，
//! 暴露 async API + 事件通道。前端唯一入口。真实 I/O 接线在此完成。
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
