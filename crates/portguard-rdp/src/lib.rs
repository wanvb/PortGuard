//! portguard-rdp：远程桌面接入保护。
//!
//! 职责：
//! - `session` —— WTS 会话枚举、客户端计算机名查询、会话断开（薄封装）
//! - `policy`  —— 判定与巡查逻辑（纯逻辑，可完整单元测试）
//!
//! 与抓包/防火墙无关：本模块只处理「谁在通过远程桌面登录」这一件事，
//! 断开动作不生成防火墙规则，因此不与 `portguard-firewall` 的规则管理冲突。

// 非测试代码禁止 unwrap/expect（规范 26：失败必须显式处理）。
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod policy;
pub mod session;

pub use policy::{evaluate, run_once, sweep, validate, RdpDecision, SweepReport};
pub use session::{SessionInfo, SessionState};
