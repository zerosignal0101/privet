//! Engine 传输控制面重导出。
//! 定义在 privet-transfer（层级低于 core），本文件仅 pub use。
pub use privet_transfer::{
    AcceptDecision, AcceptPolicy, OfferResolver, TransferCommand, TransferRegistry,
};
