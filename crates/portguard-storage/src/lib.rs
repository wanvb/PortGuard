//! portguard-storage：本地持久化层。
//!
//! 职责边界：
//! - `paths`        —— 相对 exe 的目录布局（绿色部署）
//! - `config_store` —— `config.toml` 读写、首次生成模板、损坏备份
//! - `bans`         —— `state/bans.json` 原子读写
//! - `logger`       —— 内存环形缓冲 + 后台线程落盘
//!
//! 本层不含任何网络与防火墙逻辑，便于纯单元测试。

// 非测试代码禁止 unwrap/expect（规范 26：失败必须显式处理）。
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod bans;
pub mod config_store;
pub mod logger;
pub mod paths;

pub use bans::BanStore;
pub use config_store::{ConfigStore, LoadOutcome};
pub use logger::Logger;
pub use paths::AppPaths;
