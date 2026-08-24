//! privet-security：身份钉扎、配对码、SPAKE2+ 握手、提交时序、撤销/失败关闭。
//! 可注入测试：不依赖 transport/storage。core 负责接真实 I/O。
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
