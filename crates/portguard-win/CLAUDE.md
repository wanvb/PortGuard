# portguard-win 模块规范

## 职责
- 承载「必须与 Windows API 打交道」的系统集成能力，是平台适配层。
- 提供：管理员权限检查（`admin`）、命名互斥体单实例守卫（`single_instance`）、本地时区偏移（`timezone`）、系统浏览器打开面板（`browser`）、计划任务开机自启（`autostart`）、系统托盘图标与菜单（`tray`）、控制台退出信号接管（`console`）、UTF-16 字符串工具（`wide`）、Win32 错误转换（`winerr`）。
- 内嵌托盘图标资源（`TRAY_ICON`，`include_bytes!`），供单文件部署。
- 不做什么：不含抓包（`portguard-packet`）与防火墙（`portguard-firewall`），避免职责重叠；不持有业务状态，不做封停判定。

## 对外接口
- `is_elevated() -> bool`：用 `TokenElevation` 判断当前进程是否以管理员权限运行。
- `admin::describe() -> &'static str`：启动日志用的中文权限诊断文本。
- `Autostart`：`is_enabled() -> Result<bool>` 查询自启任务；`enable(&Path) -> Result<()>` 注册；`disable() -> Result<()>` 取消（幂等）。
- `Autostart::TASK_NAME: &str`：计划任务名 `"PortGuard"`。
- `open_url(&str) -> Result<()>`：仅接受 `http://` / `https://`，经 `ShellExecuteW` 打开。
- `panel_url(&str) -> String`：把 bind 串（含 `0.0.0.0` / `[::]`）改写为可访问的回环地址。
- `SingleInstance`：`acquire() -> Result<Option<SingleInstance>>`（`Ok(None)` 表示已有实例）、`name() -> &'static str`。
- `Tray`：`create(tooltip, Option<&[u8]>) -> Result<Tray>`、`set_tooltip`、`set_menu_state(protect_enabled, ban_count)`、`balloon(title, text)`、`pump(timeout_ms) -> Vec<TrayAction>`、`hwnd()`、`icon_visible()`。
- `TrayAction`：`OpenPanel` / `ToggleProtection` / `Exit`；`WM_TRAYICON: u32` 为自定义回调消息号。
- `install_exit_handler() -> Result<()>` / `exit_requested() -> bool` / `enable_utf8_output()`：Ctrl+C 转标志位与 UTF-8 代码页。
- `utc_offset_minutes() -> i32` / `refresh()` / `clear_override()`：本地时区偏移探测与运行期覆盖。
- `to_wide` / `write_wide_fixed` / `from_wide_fixed`：UTF-16 缓冲转换。
- `win_err(api, &WinError) -> AppError` / `code_of(&WinError) -> u32`：Win32 错误码保留。
- `lib::TRAY_ICON: &[u8]`：内嵌 ICO 字节。

## 关键约束
- **Win32 API 失败必须显式处理**：crate 声明 `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]`；句柄创建失败、调用返回错误码都走 `Result` / `AppError::WindowsApi`，不得静默吞掉（对应规范 26.1 / 27）。
- **windows crate feature 按需开启**：`Cargo.toml` 只在 `cfg(windows)` 下声明实际用到的 feature（`Win32_Foundation`、`Win32_Security`、`Win32_System_Threading`、`Win32_System_LibraryLoader`、`Win32_System_Time`、`Win32_UI_Shell`、`Win32_UI_WindowsAndMessaging`、`Win32_Graphics_Gdi`、`Win32_System_Console`），新增 API 才加对应 feature，勿整包开启（规范 40：不虚构 API，先核对 crate 定义）。
- **单实例语义**：`CreateMutexW` 名已存在时仍返回有效句柄，必须靠 `GetLastError() == ERROR_ALREADY_EXISTS` 区分；优先 `Global\` 命名空间，无权限时回退 `Local\`；互斥体随进程退出（含崩溃）自动释放，不用锁文件。
- **托盘语义**：接收消息的隐藏窗口用 `WS_POPUP + WS_EX_TOOLWINDOW`，不进任务栏与 Alt+Tab；窗口过程只把动作压入线程局部队列，控制流留在主线程（规范 11.1：窗口过程不做长时间操作）；`Tray` 非 `Send`，必须在创建它的线程上使用；无桌面环境时 `Shell_NotifyIconW` 失败不视为致命，`Drop` 时删除图标与临时 ico 文件。
- **退出路径**：Ctrl+C 只置标志位，由主循环走完整收尾，避免托盘残留与规则未清理。
- **不经 shell**：开浏览器走 `ShellExecuteW`，自启动走 `Command::new("schtasks")` + 参数数组，禁止 `cmd /c`（规范 25）。
- **时区探测不 panic**：取不到或超出 ±14 小时回退 `DEFAULT_UTC_OFFSET_MINUTES`，显示格式问题不得拖垮抓包线程。
- > 待办：规范 24 要求「重复启动时激活已有窗口」，本 crate 的 `SingleInstance` 仅做到「拒绝第二个实例」，无跨进程窗口激活能力（当前由主程序改为打开浏览器面板，属行为偏差）。

## 测试
- 位置：各源码文件内联 `#[cfg(test)] mod tests`（`admin.rs` / `autostart.rs` / `browser.rs` / `console.rs` / `single_instance.rs` / `timezone.rs` / `tray.rs` / `wide.rs` / `winerr.rs`）。
- 关键用例：`权限检查不崩溃且结论自洽`、`拒绝非http地址`、`面板地址拼接正确`、`首次获取成功` / `第二次获取失败` / `释放后可重新获取`、`偏移在真实时区范围内` / `可临时覆盖并清除`、`可创建托盘窗口` / `动作队列可压入与取空` / `内嵌图标是合法ico`、`定长写入超长时截断且仍以零结尾`、`错误码被完整保留` / `高位错误码不丢符号位`。
- 测试数量：27 个 `#[test]`（admin 1、autostart 2、browser 2、console 2、single_instance 4、timezone 3、tray 5、wide 6、winerr 2）。

## 依赖关系
- 依赖：`portguard-core`（`error::AppError/Result`、`time::DEFAULT_UTC_OFFSET_MINUTES`）；`windows`（`cfg(windows)`，含 Gdi/Shell/Console 等 feature）。
- 被依赖：`portguard-app`（权限检查、单实例、托盘、退出信号、时区、开浏览器、自启动）。
