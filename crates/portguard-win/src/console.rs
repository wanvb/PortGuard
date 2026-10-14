//! 控制台接入与退出信号接管。
//!
//! 两件事：
//!
//! 1. **退出信号转标志位**：默认情况下 Ctrl+C 会让进程直接终止，析构函数不执行
//!    —— 那样托盘图标会残留在通知区域、防火墙规则也可能来不及清理。
//!    这里把退出信号转换成标志位，让主循环自己走完整的收尾流程。
//! 2. **隐藏控制台窗口**：程序是「托盘 + 网页面板」形态，不需要常驻的黑窗口。
//!    隐藏后任务栏只剩托盘图标，但仍能从托盘右键控制；终端输出同时无影无踪，
//!    因此启动期的致命错误必须改走对话框（见 [`show_error`]）。

use std::sync::atomic::{AtomicBool, Ordering};

use crate::wide::to_wide;
use portguard_core::error::{AppError, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{BOOL, HWND};
use windows::Win32::System::Console::{
    GetConsoleProcessList, GetConsoleWindow, SetConsoleCtrlHandler, SetConsoleOutputCP,
};
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, ShowWindow, MB_ICONERROR, MB_OK, MB_SETFOREGROUND, SW_HIDE,
};

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

/// 隐藏本进程独占的控制台窗口，让它不再占据任务栏。
///
/// 返回 `true` 表示窗口已隐藏：此后终端里看不到任何输出（日志照常落盘、
/// 面板照常可看），启动期的错误提示必须改走 [`show_error`]。
///
/// 是否「独占」由 `GetConsoleProcessList` 判定：从 cmd / PowerShell 里启动时，
/// 控制台上还挂着 cmd.exe 本身，此时隐藏会连带把用户自己的窗口一起藏掉，
/// 所以只有确认挂载进程数为 1 才动手（那种情形把输出留在用户终端里更合适）。
pub fn hide_own_console_window() -> bool {
    unsafe {
        let hwnd = GetConsoleWindow();
        let mut pids = [0u32; 16];
        let attached = GetConsoleProcessList(&mut pids);
        if !should_hide(hwnd != HWND::default(), attached) {
            return false;
        }
        // `ShowWindow` 的返回值是「此前的可见状态」，不能当作成功标志，
        // 隐藏动作本身没有可失败的路径，调用完即视为已处理。
        let _ = ShowWindow(hwnd, SW_HIDE);
        true
    }
}

/// 隐藏判定：**有窗口**且**控制台上只挂着一个进程（即本进程）**。
///
/// 取不到窗口（无控制台）或挂载进程数不为 1（从 cmd 启动、或查询失败返回 0）时
/// 一律不动手 —— 宁可留一个黑窗口，也不能把用户自己的 cmd 窗口藏掉。
fn should_hide(has_window: bool, attached_processes: u32) -> bool {
    has_window && attached_processes == 1
}

/// 弹出一个置顶的错误对话框。
///
/// 控制台窗口隐藏后，启动阶段的致命错误在终端里是看不见的，
/// 不弹框就会表现为「双击了但没反应」（规范 26.1：失败不得静默）。
pub fn show_error(title: &str, text: &str) {
    let caption = to_wide(title);
    let message = to_wide(text);
    unsafe {
        MessageBoxW(
            HWND::default(),
            PCWSTR(message.as_ptr()),
            PCWSTR(caption.as_ptr()),
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND,
        );
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

    #[test]
    fn 只在独占控制台时才隐藏窗口() {
        // 独占：双击启动，控制台上只有本进程
        assert!(should_hide(true, 1));
        // 从 cmd 启动：控制台上还挂着 cmd.exe，藏了会连用户的窗口一起藏
        assert!(!should_hide(true, 2));
        // 无控制台（计划任务 / 服务模式）
        assert!(!should_hide(false, 0));
        // 查询失败返回 0，按「不确定就不动手」处理
        assert!(!should_hide(true, 0));
    }
}
