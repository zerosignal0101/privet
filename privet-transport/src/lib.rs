//! QUIC and TLS-over-TCP transports behind a shared stream interface.

#![allow(rustdoc::invalid_html_tags)]

pub mod config;
pub mod constants;
pub mod error;
pub mod transport;
pub mod tls;
pub mod quic;
pub mod tcp;
pub mod frame_io;
pub mod fallback;

pub use constants::*;
pub use error::{Result, TransportError};
pub use transport::*;
pub use quic::QuicTransport;
pub use tcp::TcpTransport;
pub use frame_io::{recv_control, recv_data, send_control, send_data};
pub use fallback::connect_with_fallback;
