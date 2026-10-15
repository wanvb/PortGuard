//! portguard-win：Windows 平台适配层。
//!
//! 只放「必须与 Windows API 打交道」的能力，且全部限定在系统集成范围内：
//!
//! - `admin`           —— 管理员权限检查（抓包与防火墙的前提）
//! - `single_instance` —— 命名互斥体单实例守卫
//! - `timezone`        —— 本地时区偏移（日志时间戳）
//! - `locale`          —— 系统界面语言探测（面板「跟随系统」语言）
//! - `browser`         —— 打开控制面板地址
//! - `service`         —— Windows 系统服务：注册 / 卸载 / 服务分发（开机自启）
//! - `tray`            —— 系统托盘图标与菜单
//! - `console`         —— 控制台退出信号接管、窗口隐藏与错误对话框
//!
//! 本层不包含抓包（`portguard-packet`）与防火墙（`portguard-firewall`），
//! 避免职责重叠。

// 非测试代码禁止 unwrap/expect（规范 26：失败必须显式处理）。
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod admin;
pub mod browser;
pub mod console;
pub mod locale;
pub mod service;
pub mod single_instance;
pub mod timezone;
pub mod tray;
pub mod wide;
pub mod winerr;

pub use admin::is_elevated;
pub use browser::{open_url, panel_url};
pub use console::{
    enable_utf8_output, exit_requested, hide_own_console_window, install_exit_handler,
    request_exit, show_error,
};
pub use locale::system_language;
pub use service::Service;
pub use single_instance::SingleInstance;
pub use tray::{Tray, TrayAction, WM_TRAYICON};

/// 托盘图标（32x32 32bpp ICO）。
///
/// 由 `tools/gen_tray_icon.py` 生成后编译进二进制，
/// 部署时不需要附带任何图标文件。
pub const TRAY_ICON: &[u8] = include_bytes!("../assets/tray.ico");
