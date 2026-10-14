//! 系统托盘图标与右键菜单。
//!
//! 实现要点（对齐规范 13「控制台 + 系统托盘」的进程形态）：
//!
//! - 托盘需要一个**接收消息的窗口**。这里用 `WS_POPUP` + `WS_EX_TOOLWINDOW`
//!   创建永不显示的隐藏窗口，它不会出现在任务栏与 Alt+Tab 中；
//! - **不使用回调闭包**：`WNDPROC` 是裸函数指针，跨线程传递闭包会引入
//!   `Send` 与生命周期问题。改为「窗口过程只把动作压进线程局部队列，
//!   主线程通过 `pump()` 取出」，控制流始终留在主线程；
//! - 中断式消息泵（`PeekMessageW` + 超时休眠），让主线程在等消息的同时
//!   仍能周期性做后台工作。
//!
//! `Tray` 必须在创建它的线程上使用 —— 窗口消息只会投递到那个线程的消息队列。

use crate::wide::{to_wide, write_wide_fixed};
use crate::winerr::win_err;
use portguard_core::error::{AppError, Result};
use std::cell::RefCell;
use std::marker::PhantomData;
use std::time::Duration;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NOTIFYICONDATAW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, GetCursorPos, LoadIconW, LoadImageW, PeekMessageW, PostMessageW,
    RegisterClassW, SetForegroundWindow, TrackPopupMenu, TranslateMessage, HICON, HMENU,
    IDI_APPLICATION, IMAGE_ICON, LR_DEFAULTSIZE, LR_LOADFROMFILE, MF_SEPARATOR, MF_STRING, MSG,
    PM_REMOVE, TPM_RETURNCMD, TPM_RIGHTBUTTON, WNDCLASSW, WNDCLASS_STYLES, WM_APP, WM_CONTEXTMENU,
    WM_DESTROY, WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP, WS_EX_TOOLWINDOW, WS_POPUP,
};

/// 托盘图标的自定义消息号（`WM_APP` 之后的首个值）。
pub const WM_TRAYICON: u32 = WM_APP + 1;

/// 隐藏窗口的类名。
const WINDOW_CLASS: &str = "PortGuardTrayWindow";
/// 托盘图标在同一窗口内的编号。
const ICON_ID: u32 = 1;

const ID_OPEN_PANEL: u16 = 1001;
const ID_TOGGLE_PROTECT: u16 = 1002;
const ID_EXIT: u16 = 1003;

/// 用户从托盘菜单触发的动作。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayAction {
    /// 打开 Web 控制面板。
    OpenPanel,
    /// 暂停 / 恢复保护。
    ToggleProtection,
    /// 退出程序。
    Exit,
}

/// 菜单渲染所需的运行状态。
struct TrayCtx {
    tooltip: String,
    protect_enabled: bool,
    ban_count: usize,
}

thread_local! {
    /// 菜单与提示文本的状态（窗口过程无参数可传，只能放线程局部）。
    static CTX: RefCell<TrayCtx> = const {
        RefCell::new(TrayCtx { tooltip: String::new(), protect_enabled: true, ban_count: 0 })
    };
    /// 窗口过程压入、主线程取走的动作队列。
    static ACTIONS: RefCell<Vec<TrayAction>> = const { RefCell::new(Vec::new()) };
}

/// 系统托盘图标。
pub struct Tray {
    hwnd: HWND,
    data: NOTIFYICONDATAW,
    /// 图标是否成功加入通知区域（无桌面环境时会失败）。
    icon_added: bool,
    /// 图标文件临时路径，退出时清理。
    icon_temp: Option<std::path::PathBuf>,
    /// 禁止跨线程移动：窗口消息只投递到创建它的线程。
    _not_send: PhantomData<*const ()>,
}

impl Tray {
    /// 创建托盘图标。
    ///
    /// - `tooltip`：鼠标悬停提示；
    /// - `icon`：`Some(ico 字节)` 时使用自带图标，`None` 时回退到系统默认图标。
    ///
    /// `NOTIFYICONDATAW` 字段多且需按 C 头文件顺序逐项赋值，故豁免 clippy 的建议。
    #[allow(clippy::field_reassign_with_default)]
    pub fn create(tooltip: &str, icon: Option<&[u8]>) -> Result<Tray> {
        let (hwnd, hicon, icon_temp) = unsafe {
            let hwnd = create_hidden_window()?;
            let (hicon, temp) = load_icon(icon);
            (hwnd, hicon, temp)
        };

        CTX.with(|c| {
            if let Ok(mut c) = c.try_borrow_mut() {
                c.tooltip = tooltip.to_string();
            }
        });

        let mut data = NOTIFYICONDATAW::default();
        data.cbSize = core::mem::size_of::<NOTIFYICONDATAW>() as u32;
        data.hWnd = hwnd;
        data.uID = ICON_ID;
        data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        data.uCallbackMessage = WM_TRAYICON;
        data.hIcon = hicon;
        write_wide_fixed(&mut data.szTip, tooltip);

        // 桌面环境不可用（服务、无登录会话）时图标加不进去，
        // 但控制台与 Web 面板仍然可用，因此不视为致命错误。
        let icon_added = unsafe { Shell_NotifyIconW(NIM_ADD, &data).as_bool() };

        Ok(Tray {
            hwnd,
            data,
            icon_added,
            icon_temp,
            _not_send: PhantomData,
        })
    }

    /// 图标是否已出现在通知区域。
    pub fn icon_visible(&self) -> bool {
        self.icon_added
    }

    /// 更新悬停提示。
    pub fn set_tooltip(&mut self, text: &str) {
        CTX.with(|c| {
            if let Ok(mut c) = c.try_borrow_mut() {
                c.tooltip = text.to_string();
            }
        });
        write_wide_fixed(&mut self.data.szTip, text);
        self.data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        if self.icon_added {
            unsafe {
                let _ = Shell_NotifyIconW(NIM_MODIFY, &self.data);
            }
        }
    }

    /// 更新菜单里的状态文本。
    pub fn set_menu_state(&self, protect_enabled: bool, ban_count: usize) {
        CTX.with(|c| {
            if let Ok(mut c) = c.try_borrow_mut() {
                c.protect_enabled = protect_enabled;
                c.ban_count = ban_count;
            }
        });
    }

    /// 弹出气泡提示（用于如实上报防火墙写入失败等关键事件）。
    pub fn balloon(&mut self, title: &str, text: &str) {
        if !self.icon_added {
            return;
        }
        write_wide_fixed(&mut self.data.szInfoTitle, title);
        write_wide_fixed(&mut self.data.szInfo, text);
        self.data.dwInfoFlags = Default::default();
        self.data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_INFO;
        unsafe {
            let _ = Shell_NotifyIconW(NIM_MODIFY, &self.data);
        }
        // 恢复为普通标志，避免后续修改提示文本时重复弹气泡。
        self.data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    }

    /// 处理已到达的窗口消息，返回用户触发的动作。
    ///
    /// `timeout_ms`：无消息时最多休眠多久。主线程据此周期性处理后台工作。
    pub fn pump(&self, timeout_ms: u32) -> Vec<TrayAction> {
        unsafe {
            let mut msg = MSG::default();
            // 取尽队列中的消息，避免连续点击时动作被拆到多次 pump 里。
            while PeekMessageW(&mut msg, HWND::default(), 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        let actions = drain_actions();
        if actions.is_empty() && timeout_ms > 0 {
            // 没有消息时让出 CPU；这也是主线程"心跳"的节拍来源。
            std::thread::sleep(Duration::from_millis(timeout_ms as u64));
            return drain_actions();
        }
        actions
    }

    /// 隐藏窗口句柄（供测试与调试）。
    pub fn hwnd(&self) -> HWND {
        self.hwnd
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        unsafe {
            if self.icon_added {
                let _ = Shell_NotifyIconW(NIM_DELETE, &self.data);
            }
            let _ = DestroyWindow(self.hwnd);
            // 图标临时文件是运行时产物，退出时清理，避免堆积在 %TEMP%。
            if let Some(p) = &self.icon_temp {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}

/// 取出并清空动作队列。
fn drain_actions() -> Vec<TrayAction> {
    ACTIONS.with(|a| match a.try_borrow_mut() {
        Ok(mut a) => std::mem::take(&mut *a),
        Err(_) => Vec::new(),
    })
}

fn push_action(action: TrayAction) {
    ACTIONS.with(|a| {
        if let Ok(mut a) = a.try_borrow_mut() {
            a.push(action);
        }
    });
}

/// 创建接收托盘消息的隐藏窗口。
unsafe fn create_hidden_window() -> Result<HWND> {
    let hmodule = GetModuleHandleW(PCWSTR::null())
        .map_err(|e| win_err("GetModuleHandleW", &e))?;
    let hinstance = HINSTANCE(hmodule.0);

    let class_name = to_wide(WINDOW_CLASS);
    let wc = WNDCLASSW {
        style: WNDCLASS_STYLES(0),
        lpfnWndProc: Some(wndproc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: Default::default(),
        hCursor: Default::default(),
        hbrBackground: Default::default(),
        lpszMenuName: PCWSTR::null(),
        lpszClassName: PCWSTR(class_name.as_ptr()),
    };

    // 类已注册时返回 0，这在同一进程内重复创建托盘时属于正常情况。
    RegisterClassW(&wc);

    let window_title = to_wide("PortGuard");
    let hwnd = CreateWindowExW(
        WS_EX_TOOLWINDOW,
        PCWSTR(class_name.as_ptr()),
        PCWSTR(window_title.as_ptr()),
        WS_POPUP,
        0,
        0,
        0,
        0,
        HWND::default(),
        HMENU::default(),
        hinstance,
        None,
    );

    if hwnd.0 == 0 {
        return Err(AppError::Other(
            "创建托盘消息窗口失败（无法接收托盘事件）".to_string(),
        ));
    }
    Ok(hwnd)
}

/// 载入托盘图标：优先用自带图标，失败时回退到系统默认图标。
///
/// 自带图标以字节内嵌在 exe 中（单文件部署），但 `LoadImageW` 只认文件，
/// 因此运行时写一份到 `%TEMP%`，退出时删除。
unsafe fn load_icon(icon: Option<&[u8]>) -> (HICON, Option<std::path::PathBuf>) {
    if let Some(bytes) = icon {
        let path = std::env::temp_dir().join(format!("portguard-tray-{}.ico", std::process::id()));
        if std::fs::write(&path, bytes).is_ok() {
            let wpath = to_wide(&path.to_string_lossy());
            if let Ok(handle) = LoadImageW(
                HINSTANCE::default(),
                PCWSTR(wpath.as_ptr()),
                IMAGE_ICON,
                0,
                0,
                LR_LOADFROMFILE | LR_DEFAULTSIZE,
            ) {
                if handle.0 != 0 {
                    return (
                        HICON(handle.0),
                        Some(path),
                    );
                }
            }
            let _ = std::fs::remove_file(&path);
        }
    }

    let fallback = LoadIconW(HINSTANCE::default(), IDI_APPLICATION).unwrap_or_else(|_| HICON::default());
    (fallback, None)
}

/// 弹出右键菜单并处理选择结果。
unsafe fn show_menu(hwnd: HWND) {
    let (protect_enabled, ban_count) = CTX.with(|c| match c.try_borrow() {
        Ok(c) => (c.protect_enabled, c.ban_count),
        Err(_) => (true, 0),
    });

    let menu = match CreatePopupMenu() {
        Ok(m) => m,
        Err(_) => return,
    };

    let open_text = to_wide(format!("打开控制面板（已封停 {} 个 IP）", ban_count).as_str());
    let toggle_text = to_wide(if protect_enabled {
        "暂停保护"
    } else {
        "恢复保护"
    });
    let exit_text = to_wide("退出 PortGuard");

    let _ = AppendMenuW(menu, MF_STRING, ID_OPEN_PANEL as usize, PCWSTR(open_text.as_ptr()));
    let _ = AppendMenuW(
        menu,
        MF_STRING,
        ID_TOGGLE_PROTECT as usize,
        PCWSTR(toggle_text.as_ptr()),
    );
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    let _ = AppendMenuW(menu, MF_STRING, ID_EXIT as usize, PCWSTR(exit_text.as_ptr()));

    let mut pt = POINT::default();
    let _ = GetCursorPos(&mut pt);

    // 必须先置前台，否则菜单在点击别处时不会自动消失。
    let _ = SetForegroundWindow(hwnd);

    let chosen = TrackPopupMenu(
        menu,
        TPM_RIGHTBUTTON | TPM_RETURNCMD,
        pt.x,
        pt.y,
        0,
        hwnd,
        None,
    );
    let _ = DestroyMenu(menu);
    // 微软文档要求的收尾消息，用于修正菜单残影。
    let _ = PostMessageW(hwnd, WM_NULL, WPARAM(0), LPARAM(0));

    match chosen.0 as u16 {
        ID_OPEN_PANEL => push_action(TrayAction::OpenPanel),
        ID_TOGGLE_PROTECT => push_action(TrayAction::ToggleProtection),
        ID_EXIT => push_action(TrayAction::Exit),
        _ => {}
    }
}

/// 隐藏窗口的消息过程。
unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_TRAYICON => {
            // 传统（非 version 4）语义：lParam 的低位是鼠标消息。
            let event = (lparam.0 as u32) & 0xFFFF;
            if event == WM_RBUTTONUP || event == WM_LBUTTONUP || event == WM_CONTEXTMENU {
                show_menu(hwnd);
            }
            LRESULT(0)
        }
        WM_DESTROY => LRESULT(0),
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 托盘创建需要窗口类注册能力，测试进程同样具备；
    /// 但没有桌面（如无头 CI）时图标加不进去，因此只断言不崩溃。
    #[test]
    fn 可创建托盘窗口() {
        let mut tray = Tray::create("PortGuard 测试", None).unwrap();
        assert!(tray.hwnd().0 != 0);
        tray.set_tooltip("PortGuard 测试 2");
        tray.set_menu_state(false, 7);
        tray.balloon("测试", "内容");
        // 无消息时 pump 只在超时后返回空列表
        assert!(tray.pump(0).is_empty());
    }

    #[test]
    fn 状态更新不泄漏到其他测试() {
        let tray = Tray::create("PortGuard 测试", None).unwrap();
        tray.set_menu_state(true, 3);
        let got = CTX.with(|c| c.borrow().ban_count);
        assert_eq!(got, 3);
        drop(tray);
    }

    #[test]
    fn 动作队列可压入与取空() {
        // 直接验证队列语义，不依赖真实鼠标事件
        push_action(TrayAction::OpenPanel);
        push_action(TrayAction::Exit);
        let actions = drain_actions();
        assert_eq!(actions, vec![TrayAction::OpenPanel, TrayAction::Exit]);
        assert!(drain_actions().is_empty());
    }

    #[test]
    fn 菜单常量不与系统消息冲突() {
        // 经 black_box 阻止常量折叠，否则该断言会被编译器直接优化掉
        let msg_id = std::hint::black_box(WM_TRAYICON);
        assert!(msg_id > WM_APP, "托盘消息 ID 必须落在 WM_APP 之后");
        let ids = [ID_OPEN_PANEL, ID_TOGGLE_PROTECT, ID_EXIT];
        let mut sorted: Vec<u16> = ids.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "菜单项 ID 不可重复");
    }

    /// 内嵌图标若被替换成坏文件，托盘会静默退回系统默认图标；
    /// 这里直接从字节层面校验 ICO 头，让问题在构建期就暴露。
    #[test]
    fn 内嵌图标是合法ico() {
        let data = crate::TRAY_ICON;
        assert!(data.len() > 64, "图标文件过小：{}", data.len());
        assert_eq!(&data[0..4], &[0, 0, 1, 0], "ICONDIR 头不合法");
        assert_eq!(data[4], 1, "图标数量应为 1");
        assert_eq!(data[6], 32, "图标宽应为 32");
        assert_eq!(data[7], 32, "图标高应为 32");
        assert_eq!(data[12], 32, "位深应为 32");
        // 声明的图像长度必须与实际剩余字节一致，否则 LoadImageW 会读取越界
        let declared = u32::from_le_bytes([data[14], data[15], data[16], data[17]]) as usize;
        assert_eq!(declared, data.len() - 22, "图像长度字段与实际不符");
    }
}
