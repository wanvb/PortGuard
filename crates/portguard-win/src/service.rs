//! 开机自启动（Windows 系统服务）。
//!
//! 选型说明：不用「启动」文件夹快捷方式（需要用户登录才生效，而本程序要在
//! 无人值守的服务器上开机即防护），也不用注册表 `Run`（同样要求登录），
//! 更不用计划任务（旧实现，任务计划程序里的项与程序本身没有隶属关系，
//! 无法用 `sc query` / 服务管理器统一查看）。改用真正的 Windows 服务：
//!
//! - `SERVICE_AUTO_START`：开机由服务控制管理器（SCM）拉起，无需登录；
//! - 账号留空 = LocalSystem，天然具备管理员权限；
//! - `sc query PortGuard` / `services.msc` 中可直接查看与停止，符合规范 14 的可审计要求。
//!
//! 服务进程与 SCM 之间有一次必须完成的握手：进程启动后要尽快调用
//! [`StartServiceCtrlDispatcherW`] 并上报 `SERVICE_RUNNING`，否则 SCM 会在 30 秒后
//! 报「1053 服务没有及时响应启动或控制请求」并杀掉进程。因此主程序必须**在**
//! 读配置、抢单实例之前进入服务分发（见 `portguard-app` 的 `main`）。
//!
//! 与 netsh 一样，**绝不经过 shell**：注册与卸载走 `advapi32` 的服务 API，
//! 只在清理旧版计划任务时使用 `Command::new("schtasks").args([...])`。

use std::path::Path;
use std::sync::atomic::{AtomicI32, AtomicIsize, AtomicU32, Ordering};
use std::sync::Mutex;

use crate::wide::to_wide;
use crate::winerr::win_err;
use portguard_core::error::Result;
use windows::core::{Error as WinError, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_EXISTS,
    ERROR_SERVICE_MARKED_FOR_DELETE,
};
use windows::Win32::Security::SC_HANDLE;
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
    CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW, ENUM_SERVICE_TYPE,
    SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_ACCEPT_SHUTDOWN,
    SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
    SERVICE_DESCRIPTIONW, SERVICE_ERROR, SERVICE_ERROR_NORMAL,
    SERVICE_NO_CHANGE, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_START_TYPE, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE,
    SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};
use windows::Win32::System::Threading::GetCurrentProcessId;

/// 服务名（`sc` 命令行与事件日志里使用的短名）。
pub const NAME: &str = "PortGuard";

/// 服务显示名（服务管理器里面向用户的名称）。
pub const DISPLAY_NAME: &str = "PortGuard 恶意连接防护";

/// 服务描述。
pub const DESCRIPTION: &str =
    "识别恶意连接并自动封停（内嵌 Web 控制面板，默认 http://127.0.0.1:58080）";

/// 旧版实现留下的计划任务名，仅用于清理。
///
/// 不清理的话，开机时计划任务与服务会各拉一个实例，单实例守卫虽能挡住第二个，
/// 但用户会在「任务计划程序」里看到一个无法解释的残留项。
const LEGACY_TASK_NAME: &str = "PortGuard";

/// 服务启动参数：复用既有的 `--service` 开关（不建托盘、不开浏览器）。
const SERVICE_ARG: &str = "--service";

/// `CREATE_NO_WINDOW`：避免闪出控制台窗口。
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 删除服务所需的访问权限。
///
/// 即 `winnt.h` 里的标准权限 `DELETE`；`windows` crate 只把 `SERVICE_*` 单独导出，
/// 没有这个通用权限常量，因此按文档原值写出。
const DELETE_ACCESS: u32 = 0x0001_0000;

/// 要在服务线程里执行的主体。
///
/// `SERVICE_TABLE_ENTRYW` 只接受裸函数指针，无法携带上下文，
/// 因此只能通过进程级全局把闭包交给 [`service_main`]。
static BODY: Mutex<Option<Box<dyn FnOnce() -> i32 + Send>>> = Mutex::new(None);

/// 服务状态句柄（`SERVICE_STATUS_HANDLE` 的原始值，0 表示尚未注册）。
static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);

/// 最近一次上报的运行状态与已接受的控制码，供 `SERVICE_CONTROL_INTERROGATE` 原样回读。
///
/// 回读时必须带上真实的 `dwControlsAccepted`：回成全 0 会让 SCM 认为本服务
/// 不再接受停止请求。
static CURRENT_STATE: AtomicU32 = AtomicU32::new(SERVICE_STOPPED.0);
static CURRENT_ACCEPTED: AtomicU32 = AtomicU32::new(0);

/// 服务主体的退出码。
static EXIT_CODE: AtomicI32 = AtomicI32::new(0);

/// 服务注册 / 卸载 / 分发。
#[derive(Debug)]
pub struct Service;

impl Service {
    /// 查询是否已注册本服务。
    ///
    /// 打不开服务控制管理器（例如非管理员）时返回 `false` —— 调用方据此展示
    /// 面板开关的初始状态，不需要区分「没装」与「看不到」。
    pub fn is_enabled() -> bool {
        Self::open().is_ok()
    }

    /// 注册为开机自启动服务（幂等）。
    ///
    /// `exe` 必须是当前可执行文件的绝对路径。**只注册不启动**：本项的含义是
    /// 「开机自动启动」，由 SCM 在下次开机时拉起；立即启动会与用户当前正在
    /// 运行的实例争抢单实例守卫，徒增困惑。
    pub fn install(exe: &Path) -> Result<()> {
        // 路径可能含空格，用引号包裹后整体作为 lpBinaryPathName 传入。
        let action = format!("\"{}\" {}", exe.display(), SERVICE_ARG);
        let w_action = to_wide(&action);
        let w_name = to_wide(NAME);
        let w_display = to_wide(DISPLAY_NAME);

        unsafe {
            let scm = ScHandle::open(SC_MANAGER_CREATE_SERVICE)?;
            let service = match CreateServiceW(
                scm.raw(),
                PCWSTR(w_name.as_ptr()),
                PCWSTR(w_display.as_ptr()),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                PCWSTR(w_action.as_ptr()),
                // 加载组 / 标签 / 依赖项 / 账号 / 口令全部留空：账号空 = LocalSystem
                None,
                None,
                None,
                None,
                None,
            ) {
                Ok(h) => ScHandle(h),
                // 已注册过：只把可执行路径改成当前路径（程序可能被挪到了别的目录），
                // 其余配置（自启动类型、账号）保持用户/系统的既有设置。
                Err(e) if win32_code(&e) == ERROR_SERVICE_EXISTS.0 => {
                    let h = OpenServiceW(scm.raw(), PCWSTR(w_name.as_ptr()), SERVICE_ALL_ACCESS)
                        .map_err(|e| win_err("OpenServiceW", &e))?;
                    let handle = ScHandle(h);
                    ChangeServiceConfigW(
                        handle.raw(),
                        ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
                        SERVICE_START_TYPE(SERVICE_NO_CHANGE),
                        SERVICE_ERROR(SERVICE_NO_CHANGE),
                        PCWSTR(w_action.as_ptr()),
                        None,
                        None,
                        None,
                        None,
                        None,
                        PCWSTR(w_display.as_ptr()),
                    )
                    .map_err(|e| win_err("ChangeServiceConfigW", &e))?;
                    handle
                }
                Err(e) => return Err(win_err("CreateServiceW", &e)),
            };

            // 描述是可选信息，写不进去不影响服务的可用性，不因此让安装失败。
            let mut desc = to_wide(DESCRIPTION);
            let info = SERVICE_DESCRIPTIONW {
                lpDescription: PWSTR(desc.as_mut_ptr()),
            };
            let _ = ChangeServiceConfig2W(
                service.raw(),
                SERVICE_CONFIG_DESCRIPTION,
                Some(&info as *const _ as *const core::ffi::c_void),
            );
        }

        remove_legacy_task();
        Ok(())
    }

    /// 卸载服务（幂等：没装、已标记删除都算成功）。
    ///
    /// 若服务正在运行且**不是本进程**，先请求停止再删除；若正由本进程提供服务
    /// （面板正是这个服务实例在响应），则只删除不停止 —— 停掉自己会让这次 HTTP
    /// 响应发不出去，而且用户取消的只是「开机自动启动」，并不等于要立刻停止防护。
    /// 该情形下服务项会在进程退出后由 SCM 自动清除。
    pub fn uninstall() -> Result<()> {
        let w_name = to_wide(NAME);
        unsafe {
            let scm = match OpenSCManagerW(None, None, SC_MANAGER_CONNECT) {
                Ok(h) => ScHandle(h),
                // 连服务控制管理器都打不开时，注册项必然也不在本进程掌控之下；
                // 按「没有服务可删」处理，保持幂等语义。
                Err(_) => {
                    remove_legacy_task();
                    return Ok(());
                }
            };
            let service = match OpenServiceW(
                scm.raw(),
                PCWSTR(w_name.as_ptr()),
                DELETE_ACCESS | SERVICE_STOP | SERVICE_QUERY_STATUS,
            ) {
                Ok(h) => ScHandle(h),
                Err(e) => {
                    let c = win32_code(&e);
                    if c == ERROR_SERVICE_DOES_NOT_EXIST.0 || c == ERROR_SERVICE_MARKED_FOR_DELETE.0 {
                        remove_legacy_task();
                        return Ok(());
                    }
                    return Err(win_err("OpenServiceW", &e));
                }
            };

            if running_in_other_process(service.raw()) {
                let mut status = SERVICE_STATUS::default();
                // 停止请求只是尽力而为：即使 SCM 没来得及停下进程，
                // DeleteService 也能把服务标记为删除，目标已经达成。
                let _ = ControlService(service.raw(), SERVICE_CONTROL_STOP, &mut status);
            }

            if let Err(e) = DeleteService(service.raw()) {
                if win32_code(&e) != ERROR_SERVICE_MARKED_FOR_DELETE.0 {
                    return Err(win_err("DeleteService", &e));
                }
            }
        }
        remove_legacy_task();
        Ok(())
    }

    /// 以服务身份运行 `body`，返回其退出码。
    ///
    /// 由 SCM 拉起时：进入服务分发循环，`body` 在服务线程上执行，
    /// `sc stop` / 关机时经控制处理器置退出标志，由 `body` 自己走完整收尾。
    ///
    /// 手工执行 `PortGuard.exe --service`（并未经过 SCM）时，
    /// `StartServiceCtrlDispatcherW` 会报 1063，此时原地执行 `body`，
    /// 保持该参数原有含义（不建托盘、不开浏览器）。
    pub fn run<F>(body: F) -> Result<i32>
    where
        F: FnOnce() -> i32 + Send + 'static,
    {
        if let Ok(mut slot) = BODY.lock() {
            *slot = Some(Box::new(body));
        }

        let mut name = to_wide(NAME);
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: PWSTR(name.as_mut_ptr()),
                lpServiceProc: Some(service_main),
            },
            // 表以「全空项」结尾，这是 SCM 约定的结束标记
            SERVICE_TABLE_ENTRYW {
                lpServiceName: PWSTR::null(),
                lpServiceProc: None,
            },
        ];

        match unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } {
            Ok(()) => Ok(EXIT_CODE.load(Ordering::SeqCst)),
            Err(e) if win32_code(&e) == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT.0 => {
                Ok(take_body().map(|f| f()).unwrap_or(1))
            }
            Err(e) => Err(win_err("StartServiceCtrlDispatcherW", &e)),
        }
    }

    /// 打开已注册的服务句柄，只要求查询权限。
    fn open() -> Result<ScHandle> {
        let w_name = to_wide(NAME);
        unsafe {
            let scm = ScHandle::open(SC_MANAGER_CONNECT)?;
            OpenServiceW(scm.raw(), PCWSTR(w_name.as_ptr()), SERVICE_QUERY_STATUS)
                .map(ScHandle)
                .map_err(|e| win_err("OpenServiceW", &e))
        }
    }
}

/// 取出待执行的主体（只能取一次）。
fn take_body() -> Option<Box<dyn FnOnce() -> i32 + Send>> {
    BODY.lock().ok().and_then(|mut slot| slot.take())
}

/// 服务主函数：由 SCM 在它自己创建的线程上调用。
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let w_name = to_wide(NAME);
    let handle = RegisterServiceCtrlHandlerExW(PCWSTR(w_name.as_ptr()), Some(control_handler), None);
    let handle = match handle {
        Ok(h) => h,
        // 注册处理器失败时 SCM 已经无法接受任何状态上报，
        // 这里只能直接返回，由 SCM 按「启动失败」处理。
        Err(_) => return,
    };
    STATUS_HANDLE.store(handle.0, Ordering::SeqCst);

    report(SERVICE_START_PENDING, 0, 0);
    report(
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        0,
    );

    let code = take_body().map(|f| f()).unwrap_or(1);

    EXIT_CODE.store(code, Ordering::SeqCst);
    report(SERVICE_STOPPED, 0, code as u32);
}

/// 服务控制处理器。
///
/// 与 Ctrl+C 处理器同构：只置退出标志，由主循环走完整收尾流程
/// （停面板、清防火墙规则、收尾日志），不在回调里做任何耗时操作（规范 11.1）。
unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            // 先上报「停止中」，否则 SCM 会以为服务对停止请求无响应。
            report(SERVICE_STOP_PENDING, 0, 0);
            crate::console::request_exit();
        }
        // 回读当前状态即可，不做任何动作。
        SERVICE_CONTROL_INTERROGATE => {
            let state = SERVICE_STATUS_CURRENT_STATE(CURRENT_STATE.load(Ordering::SeqCst));
            report(state, CURRENT_ACCEPTED.load(Ordering::SeqCst), 0);
        }
        _ => {}
    }
    0
}

/// 上报服务状态。
///
/// 句柄尚未注册（值为 0）时静默跳过：那些调用发生在注册失败之后，
/// 再调 `SetServiceStatus` 也只会继续失败。
fn report(state: SERVICE_STATUS_CURRENT_STATE, accepted: u32, exit_code: u32) {
    let raw = STATUS_HANDLE.load(Ordering::SeqCst);
    if raw == 0 {
        return;
    }
    CURRENT_STATE.store(state.0, Ordering::SeqCst);
    CURRENT_ACCEPTED.store(accepted, Ordering::SeqCst);
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        // 不声明等待时长：状态切换是瞬时的，声明反而会让 SCM 多等
        dwWaitHint: 0,
    };
    unsafe {
        let _ = SetServiceStatus(SERVICE_STATUS_HANDLE(raw), &status);
    }
}

/// 服务是否正在运行且由**别的**进程承载。
///
/// 查询失败时返回 `false`：宁可不停止，也不要在信息不足时去动一个可能正在
/// 保护本机的进程。
fn running_in_other_process(service: SC_HANDLE) -> bool {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0u32;
    let buf = unsafe {
        std::slice::from_raw_parts_mut(
            &mut status as *mut SERVICE_STATUS_PROCESS as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
        )
    };
    unsafe {
        if QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, Some(buf), &mut needed).is_err() {
            return false;
        }
        status.dwCurrentState == SERVICE_RUNNING
            && status.dwProcessId != 0
            && status.dwProcessId != GetCurrentProcessId()
    }
}

/// 取出 `windows` 错误里的 Win32 错误码。
///
/// `windows` crate 对 Win32 API 失败会返回 `HRESULT_FROM_WIN32(GetLastError())`，
/// 低 16 位即原始错误码（本项目用到的几个码都远小于 65536）。
fn win32_code(e: &WinError) -> u32 {
    (e.code().0 as u32) & 0xFFFF
}

/// 删除旧版实现留下的计划任务（存在才删，失败忽略）。
fn remove_legacy_task() {
    use std::os::windows::process::CommandExt;
    let _ = std::process::Command::new("schtasks")
        .args(["/Delete", "/TN", LEGACY_TASK_NAME, "/F"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

/// 服务控制管理器 / 服务句柄的 RAII 包装。
///
/// `SC_HANDLE` 是 `Copy` 且没有 `Drop`，不显式 `CloseServiceHandle` 就会泄漏；
/// 用守卫包一层，早退路径（各种 `?`）也不会漏关。
struct ScHandle(SC_HANDLE);

impl ScHandle {
    /// 打开服务控制管理器。
    fn open(access: u32) -> Result<ScHandle> {
        unsafe { OpenSCManagerW(None, None, access) }
            .map(ScHandle)
            .map_err(|e| win_err("OpenSCManagerW", &e))
    }

    fn raw(&self) -> SC_HANDLE {
        self.0
    }
}

impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 服务名符合可读性要求() {
        assert_eq!(NAME, "PortGuard");
        assert!(!NAME.contains('\\'), "服务名不带路径前缀，便于 sc 命令与运维查找");
        assert!(!NAME.contains(' '), "服务名带空格会让 sc 命令必须加引号");
    }

    #[test]
    fn 显示名与描述面向用户可读() {
        assert!(!DISPLAY_NAME.is_empty());
        assert!(!DESCRIPTION.is_empty());
        assert!(DISPLAY_NAME.contains("PortGuard"));
    }

    #[test]
    fn 查询未注册的服务不报错() {
        // 只验证「查询动作可用且不 panic」；结论取决于本机是否已注册。
        let _ = Service::is_enabled();
    }

    #[test]
    fn 错误码从错误信息中正确取出() {
        // HRESULT_FROM_WIN32(1060) = 0x8007_0424，即「指定的服务未安装」
        let e = WinError::from_hresult(windows::core::HRESULT(0x8007_0424u32 as i32));
        assert_eq!(win32_code(&e), 1060);
        assert_eq!(win32_code(&e), ERROR_SERVICE_DOES_NOT_EXIST.0);
    }
}
