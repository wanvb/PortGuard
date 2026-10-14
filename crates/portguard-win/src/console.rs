//! 控制台退出信号接管。
//!
//! 默认情况下 Ctrl+C 会让进程直接终止，析构函数不执行 —— 那样托盘图标会残留在
//! 通知区域、防火墙规则也可能来不及清理。这里把退出信号转换成标志位，
//! 让主循环自己走完整的收尾流程。

use std::sync::atomic::{AtomicBool, Ordering};

use portguard_core::error::{AppError, Result};
use windows::Win32::Foundation::BOOL;
use windows::Win32::System::Console::{SetConsoleCtrlHandler, SetConsoleOutputCP};

/// UTF-8 代码页，让中文提示在 cmd 里正常显示。
const CP_UTF8: u32 = 65001;

/// 退出请求标志。控制台处理器是裸函数指针，无法携带上下文，
/// 因此只能通过进程级全局传递。
static EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);

/// 控制台控制事件处理器。
///
/// 返回 `TRUE` 表示事件已被处理，系统不再执行默认动作（直接终止进程）。
unsafe extern "system" fn handler(_ctrl_type: u32) -> BOOL {
    EXIT_REQUESTED.store(true, Ordering::SeqCst);
    BOOL(1)
}

/// 注册退出处理器：Ctrl+C / 关闭窗口 / 注销 / 关机时置位标志，交由主循环收尾。
///
/// 重复调用对同一函数指针幂等。
pub fn install_exit_handler() -> Result<()> {
    unsafe { SetConsoleCtrlHandler(Some(handler), true) }.map_err(|e| AppError::WindowsApi {
        api: "SetConsoleCtrlHandler",
        code: e.code().0 as u32,
    })
}

/// 是否已被外部要求退出。
pub fn exit_requested() -> bool {
    EXIT_REQUESTED.load(Ordering::SeqCst)
}

/// 把控制台输出代码页切到 UTF-8。
///
/// 中文 Windows 控制台默认是 GBK，直接打印 UTF-8 字节会变成乱码。
/// 没有控制台（例如被计划任务拉起）时该调用失败，属于正常情况，忽略即可。
pub fn enable_utf8_output() {
    unsafe {
        let _ = SetConsoleOutputCP(CP_UTF8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 注册退出处理器可用() {
        assert!(install_exit_handler().is_ok());
    }

    #[test]
    fn 退出标志存取一致() {
        let before = exit_requested();
        EXIT_REQUESTED.store(true, Ordering::SeqCst);
        assert!(exit_requested());
        EXIT_REQUESTED.store(before, Ordering::SeqCst);
    }
}
