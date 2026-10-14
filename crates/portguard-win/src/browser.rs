//! 用系统默认浏览器打开面板地址。
//!
//! 走 `ShellExecuteW` 而不是 `cmd /c start`：
//! - 不经过命令解释器，URL 中的 `&`、`%`、空格不会被当成 shell 语法（规范 25）；
//! - 不需要窗口闪烁。

use crate::wide::to_wide;
use portguard_core::error::{AppError, Result};
use windows::core::PCWSTR;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// `ShellExecuteW` 返回值 <= 32 表示失败（Win32 文档定义的阈值）。
const SHELL_EXECUTE_MIN_OK: isize = 32;

/// 打开 URL。仅接受 `http://` 与 `https://`，其余一律拒绝。
pub fn open_url(url: &str) -> Result<()> {
    let url = url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(AppError::Other(format!(
            "拒绝打开非 HTTP 地址：{}",
            url
        )));
    }

    let op = to_wide("open");
    let target = to_wide(url);

    unsafe {
        let h = ShellExecuteW(
            None,
            PCWSTR(op.as_ptr()),
            PCWSTR(target.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
        // 返回值是 HINSTANCE 形式的伪句柄，需要按数值判断成败。
        if h.0 <= SHELL_EXECUTE_MIN_OK {
            return Err(AppError::Other(format!(
                "调用系统浏览器失败（代码 {}）：{}",
                h.0, url
            )));
        }
    }
    Ok(())
}

/// 拼接面板地址。
pub fn panel_url(bind: &str) -> String {
    // 面板只监听回环，`0.0.0.0` 无法直接访问，统一改写为 127.0.0.1。
    let host_port = bind.replace("0.0.0.0", "127.0.0.1").replace("[::]", "127.0.0.1");
    format!("http://{}", host_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 拒绝非http地址() {
        assert!(open_url("file:///C:/Windows/System32/calc.exe").is_err());
        assert!(open_url("C:\\Windows\\System32\\calc.exe").is_err());
        assert!(open_url("javascript:alert(1)").is_err());
        assert!(open_url("").is_err());
    }

    #[test]
    fn 面板地址拼接正确() {
        assert_eq!(panel_url("127.0.0.1:58080"), "http://127.0.0.1:58080");
        // 通配监听地址必须改写，否则浏览器打不开
        assert_eq!(panel_url("0.0.0.0:58080"), "http://127.0.0.1:58080");
    }
}
