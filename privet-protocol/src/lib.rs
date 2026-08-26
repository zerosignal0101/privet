//! Versioned wire messages, framing, layout, and path validation.

pub mod constants;
pub mod error;
pub mod varint;
pub mod framing;
pub mod layout;
pub mod path;

include!(concat!(env!("OUT_DIR"), "/privet.v1.rs"));
