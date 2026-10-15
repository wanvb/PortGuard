//! PortGuard 核心域。
//!
//! 本 crate 是纯业务逻辑层：**不得出现任何 Win32 / WinSock 调用**，
//! 因此可以在任意机器上 `cargo test`，无需管理员权限、无需真实网卡。
//!
//! 模块划分：
//!
//! | 模块 | 职责 |
//! |------|------|
//! | [`model`] | 领域数据结构 |
//! | [`config`] | 配置模型与 TOML 读写 |
//! | [`notes`] | 端口 / 名单规则的备注（纯展示） |
//! | [`iprange`] | IP 规则解析与匹配 |
//! | [`tracker`] | 滑动窗口连接跟踪 |
//! | [`ban`] | 封停状态机 |
//! | [`engine`] | 规则引擎（判定顺序的唯一权威实现）|
//! | [`logging`] | 日志模型与内存缓冲 |
//! | [`api`] | 表现层契约与只读视图 |
//! | [`error`] / [`time`] | 通用支撑 |

#![deny(clippy::unwrap_used, clippy::expect_used)]
// 测试代码允许 unwrap/expect（规范 27 明确豁免）。
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod api;
pub mod ban;
pub mod config;
pub mod engine;
pub mod error;
pub mod iprange;
pub mod logging;
pub mod model;
pub mod notes;
pub mod observe;
pub mod time;
pub mod tracker;

/// 程序版本号，取自 Cargo 包版本。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use error::{AppError, Result};
