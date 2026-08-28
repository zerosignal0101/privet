//! File-set preparation, integrity verification, transfer state, and resume behavior.

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
pub use part_store::FsPartStore;
pub use sender::{run_sender, ChunkReader, MappedChunkReader, SenderInputs, SharedCommandReceiver};
pub use receiver::{run_receiver, ReceiveHistory, ReceivedFileRecord, ReceiverInputs};
