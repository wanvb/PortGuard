//! portguard-web：内嵌 Web 控制面板。
//!
//! 结构：
//! - `assets`  —— 编译期内嵌的前端资源（`include_str!`，单文件部署）
//! - `router`  —— 纯函数路由：方法 + 路径 + 请求体 → 响应
//! - `server`  —— tiny_http 服务循环与安全校验（Host / Origin / 体积）
//!
//! 本层只通过 `portguard_core::api::PortGuardApi` 与业务交互，
//! 不认识抓包与防火墙的内部结构（对应规范的 UI / Core 解耦）。

// 非测试代码禁止 unwrap/expect（规范 26：失败必须显式处理）。
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod assets;
pub mod router;
pub mod server;

#[cfg(test)]
pub(crate) mod testapi;

#[cfg(test)]
mod e2e;

pub use router::{PanelMeta, Reply};
pub use server::WebServer;

/// 面板默认监听地址。
///
/// 与 `PanelConfig::default()` 同源，避免两处字面量各写一份后悄悄分叉。
pub const DEFAULT_BIND: &str = portguard_core::config::DEFAULT_PANEL_BIND;
