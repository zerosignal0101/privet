//! privet-protocol：报文 schema、版本、帧编解码。无 I/O。

pub mod constants;
pub mod error;
pub mod varint;
pub mod framing;
pub mod layout;

// prost-build 0.13 生成扁平类型（无嵌套 `pub mod privet { pub mod v1 }`），直接 include。
include!(concat!(env!("OUT_DIR"), "/privet.v1.rs"));
