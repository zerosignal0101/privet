//! LAN peer discovery and candidate-address tracking.

pub mod constants;
pub mod error;
pub mod beacon;
pub mod config;
pub mod netinfo;
pub mod peer;
pub mod udp;
pub mod mdns;
pub mod engine;
pub mod direct;
pub mod inject;

pub use constants::*;
pub use error::{DiscoveryError, Result};
