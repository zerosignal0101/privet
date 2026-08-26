//! privet-transfer：传输引擎。可靠文件/文件夹传输 + BLAKE3 三级完整性 + 断点续传 + 取消/暂停/重连。
//! 引擎核心消费可注入 trait（ControlChannel/DataChannel/Clock/TransferEventSink/PartStore/ChunkReader）；
//! 真实 QUIC/TCP 接线推迟到 privet-core。

#![allow(rustdoc::invalid_html_tags)]

pub mod constants;
pub mod error;
pub mod config;
pub mod clock;
pub mod control;
pub mod integrity;
pub mod state;
pub mod events;
pub mod prepare;
pub mod fileset;
pub mod channel;
pub mod transport_adapter;
pub mod inflight;
pub mod sender;

pub mod bitmask;
pub mod manifest_store;
pub mod part_store;
pub mod receiver;

pub mod resume;

pub use constants::*;
pub use error::{Result, TransferError};
pub use config::{CollisionPolicy, TransferEngineConfig};
pub use control::{AcceptDecision, AcceptPolicy, OfferResolver, TransferCommand, TransferRegistry};
pub use state::{PausedReason, TransferFailed, TransferState};
pub use prepare::{prepare_dir, prepare_dir_streaming, prepare_single_file, PreparedSet};
pub use channel::{ControlChannel, DataChannel};
pub use transport_adapter::{StreamControlChannel, StreamDataChannel};
