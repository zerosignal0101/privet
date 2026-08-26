//! Pairing policy, transcript binding, pinned-key authorization, and trust commit behavior.
#![allow(rustdoc::invalid_html_tags)]

pub mod constants;
pub mod error;
pub mod config;
pub mod code;
pub mod transcript;
pub mod trust;
pub mod cert;
pub mod channel;
pub mod session;
pub mod commit;
pub mod conn_auth;
pub mod events;

pub use config::PairingConfig;
pub use constants::*;
pub use error::{PairingError, Result};
