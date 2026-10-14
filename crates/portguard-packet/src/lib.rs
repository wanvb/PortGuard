//! 数据包采集与解析。
//!
//! 职责边界（规范 3.2）：本 crate **只负责把字节变成 [`PacketInfo`]**，
//! 绝不在这里决定「封停谁」。判定逻辑全部在 `portguard-core::engine`。
//!
//! 数据流：
//!
//! ```text
//! raw socket → parser → PacketInfo → portguard-core 规则引擎
//! ```

pub mod adapter;
#[cfg(windows)]
pub mod capture;
pub mod parser;

#[cfg(not(windows))]
pub mod capture;

pub use adapter::{enumerate, AdapterInfo};
pub use capture::CaptureHandle;
pub use parser::{parse_ethernet_or_ip, parse_ipv4, ParsedPacket};
