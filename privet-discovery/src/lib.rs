//! privet-discovery：mDNS + UDP beacon，对等体列表与生命周期。无传输逻辑。

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
