# portguard-win 模块规范

## 职责
- 承载「必须与 Windows API 打交道」的系统集成能力，是平台适配层。
- 提供：管理员权限检查（`admin`）、命名互斥体单实例守卫（`single_instance`）、本地时区偏移（`timezone`）、服务器界面语言探测（`locale`）、系统浏览器打开面板（`browser`）、Windows 系统服务注册 / 卸载 / SCM 服务分发（`service`）、系统托盘图标与菜单（`tray`）、控制台退出信号接管 / 窗口隐藏 / 错误对话框（`console`）、UTF-16 字符串工具（`wide`）、Win32 错误转换（`winerr`）。
- 内嵌托盘图标资源（`TRAY_ICON`，`include_bytes!`），供单文件部署。
- 不做什么：不含抓包（`portguard-packet`）与防火墙（`portguard-firewall`），避免职责重叠；不持有业务状态，不做封停判定。

## 对外接口
- `is_elevated() -> bool`：用 `TokenElevation` 判断当前进程是否以管理员权限运行。
- `admin::describe() -> &'static str`：启动日志用的中文权限诊断文本。
- `Service`：`is_enabled() -> bool` 查询服务是否已注册；`install(&Path) -> Result<()>` 注册开机自启服务（已存在则更新路径）；`uninstall() -> Result<()>` 卸载（幂等）；`run(body: F) -> Result<i32>` 进入 SCM 分发并运行主体，返回进程退出码。
- `service::NAME / DISPLAY_NAME / DESCRIPTION`：服务名 `"PortGuard"`、中文显示名与服务描述。
- `open_url(&str) -> Result<()>`：仅接受 `http://` / `https://`，经 `ShellExecuteW` 打开。
- `panel_url(&str) -> String`：把 bind 串（含 `0.0.0.0` / `[::]`）改写为可访问的回环地址。
- `SingleInstance`：`acquire() -> Result<Option<SingleInstance>>`（`Ok(None)` 表示已有实例）、`name() -> &'static str`。
- `Tray`：`create(tooltip, Option<&[u8]>) -> Result<Tray>`、`set_tooltip`、`set_menu_state(protect_enabled, ban_count)`、`balloon(title, text)`、`pump(timeout_ms) -> Vec<TrayAction>`、`hwnd()`、`icon_visible()`。
- `TrayAction`：`OpenPanel` / `ToggleProtection` / `Exit`；`WM_TRAYICON: u32` 为自定义回调消息号。
- `install_exit_handler() -> Result<()>` / `exit_requested() -> bool` / `request_exit()` / `enable_utf8_output()`：Ctrl+C 与服务控制请求共用的退出标志位，以及 UTF-8 代码页。
- `hide_own_console_window() -> bool`：隐藏本进程独占的控制台窗口（返回是否已隐藏，决定后续告警走打印还是对话框）。
- `show_error(title, text)`：置顶错误对话框，用于控制台已隐藏时的启动期致命错误。
- `system_language() -> &'static str`：服务器界面语言（`"zh"` / `"en"`），供面板语言设置为「跟随系统」时使用；`locale::language_of(langid)` 是纯函数判据，`LANGUAGE_ZH` / `LANGUAGE_EN` 取自 `portguard_core::config`。
- `utc_offset_minutes() -> i32` / `refresh()` / `clear_override()`：本地时区偏移探测与运行期覆盖。
- `to_wide` / `write_wide_fixed` / `from_wide_fixed`：UTF-16 缓冲转换。
- `win_err(api, &WinError) -> AppError` / `code_of(&WinError) -> u32`：Win32 错误码保留。
- `lib::TRAY_ICON: &[u8]`：内嵌 ICO 字节。

## 关键约束
- **Win32 API 失败必须显式处理**：crate 声明 `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]`；句柄创建失败、调用返回错误码都走 `Result` / `AppError::WindowsApi`，不得静默吞掉（对应规范 26.1 / 27）。
- **windows crate feature 按需开启**：`Cargo.toml` 只在 `cfg(windows)` 下声明实际用到的 feature（`Win32_Foundation`、`Win32_Security`、`Win32_System_Threading`、`Win32_System_LibraryLoader`、`Win32_System_Time`、`Win32_System_Services`、`Win32_UI_Shell`、`Win32_UI_WindowsAndMessaging`、`Win32_Graphics_Gdi`、`Win32_System_Console`、`Win32_Globalization`），新增 API 才加对应 feature，勿整包开启（规范 40：不虚构 API，先核对 crate 定义）。隐藏控制台窗口用到的 `GetConsoleWindow` / `GetConsoleProcessList` 在 `Win32_System_Console`，`ShowWindow` / `MessageBoxW` 在 `Win32_UI_WindowsAndMessaging`，`GetUserDefaultUILanguage` / `GetSystemDefaultUILanguage` 在 `Win32_Globalization`，均已在列。
- **单实例语义**：`CreateMutexW` 名已存在时仍返回有效句柄，必须靠 `GetLastError() == ERROR_ALREADY_EXISTS` 区分；优先 `Global\` 命名空间，无权限时回退 `Local\`；互斥体随进程退出（含崩溃）自动释放，不用锁文件。
- **托盘语义**：接收消息的隐藏窗口用 `WS_POPUP + WS_EX_TOOLWINDOW`，不进任务栏与 Alt+Tab；窗口过程只把动作压入线程局部队列，控制流留在主线程（规范 11.1：窗口过程不做长时间操作）；`Tray` 非 `Send`，必须在创建它的线程上使用；无桌面环境时 `Shell_NotifyIconW` 失败不视为致命，`Drop` 时删除图标与临时 ico 文件。
- **开机自启只用系统服务，不用计划任务**：`CreateServiceW(SERVICE_AUTO_START, SERVICE_WIN32_OWN_PROCESS)`，账号传 `NULL`（LocalSystem）；勾选＝注册、取消＝卸载，**勾选后不立即启动**（下次开机由 SCM 拉起）。服务与 `services.msc` / `sc query` 同源，可统一查看；旧版可能残留的同名计划任务在注册 / 卸载时顺带清理，避免两个实例被同时拉起。
- **服务必须实现 SCM 握手**：进程被 SCM 拉起后须尽快进入 `StartServiceCtrlDispatcherW` 并上报 `SERVICE_RUNNING`，否则 30 秒后 SCM 会报 1053「服务没有及时响应启动或控制请求」并杀掉进程。因此主程序必须在读配置、抢单实例**之前**调用 `Service::run`（见 `portguard-app`）。
- **服务卸载不得停掉自己**：`uninstall` 先取 `QueryServiceStatusEx(SC_STATUS_PROCESS_INFO).dwProcessId`，等于本进程时直接 `DeleteService`（停自己会把这次请求的响应掐断）；其它情况才 `ControlService(SERVICE_CONTROL_STOP)`。`ERROR_SERVICE_DOES_NOT_EXIST` / `ERROR_SERVICE_MARKED_FOR_DELETE` 一律视为成功，保证幂等。
- **`SC_HANDLE` 必须显式关闭**：它是 `Copy` 且无 `Drop`，统一走 `ScHandle` 包装，在 `Drop` 里 `CloseServiceHandle`。
- **`SERVICE_TABLE_ENTRYW` 只接受裸函数指针**：服务主体以进程级 `static Mutex<Option<Box<dyn FnOnce() -> i32 + Send>>>` 传递；取不到 SCM 上下文（错误 1063，即手工执行 `--service`）时把闭包取回原地执行，保留手工运行语义。
- **退出路径**：Ctrl+C 与 `sc stop` / 关机事件都只置同一个标志位（`console::request_exit()`），由主循环走完整收尾，避免托盘残留与规则未清理。
- **控制台窗口隐藏只在「独占」时动手**：`GetConsoleWindow` 取不到窗口（服务模式 / 无控制台）或 `GetConsoleProcessList` 挂载进程数不为 1（从 cmd 启动时控制台上还挂着 cmd.exe，查询失败也返回 0）时一律不隐藏 —— 宁可留个黑窗口，也不能把用户自己的 cmd 窗口藏掉。这是 `should_hide` 纯函数的唯一判据，可单测。
- **隐藏后不假装成功**：窗口一旦隐藏，终端里看不到任何输出，启动期致命错误必须改走 `show_error` 对话框，否则表现为「双击没反应」（规范 26.1）。
- **不经 shell**：开浏览器走 `ShellExecuteW`；清理旧版计划任务用 `Command::new("schtasks")` + 参数数组（不经 `cmd /c`，且只在固定规则名上操作），服务本身全部走 SCM API（规范 25）。
- **时区探测不 panic**：取不到或超出 ±14 小时回退 `DEFAULT_UTC_OFFSET_MINUTES`，显示格式问题不得拖垮抓包线程。
- **语言探测只归类到中 / 英，探测不到按中文**：`locale::system_language()` 先问 `GetUserDefaultUILanguage`，取不到 0 时退到 `GetSystemDefaultUILanguage`，仍为 0 回 `LANGUAGE_ZH`；`language_of` 只看 LANGID 低 10 位的主语言（`0x04` 为中文，其余一律英文），因此 0x0804 / 0x0404（简繁）都算中文。结论用 `OnceLock` 缓存 —— 系统语言在一次运行内不会变，且该函数在启动期被调用一次。这里只做「给面板挑一份文案」这一件事，探测结果不得参与任何判定，也不代表抓包 / 防火墙的平台能力。
- > 待办：规范 24 要求「重复启动时激活已有窗口」，本 crate 的 `SingleInstance` 仅做到「拒绝第二个实例」，无跨进程窗口激活能力（当前由主程序改为打开浏览器面板，属行为偏差）。

## 测试
- 位置：各源码文件内联 `#[cfg(test)] mod tests`（`admin.rs` / `browser.rs` / `console.rs` / `locale.rs` / `service.rs` / `single_instance.rs` / `timezone.rs` / `tray.rs` / `wide.rs` / `winerr.rs`）。
- 关键用例：`权限检查不崩溃且结论自洽`、`拒绝非http地址`、`面板地址拼接正确`、`首次获取成功` / `第二次获取失败` / `释放后可重新获取`、`偏移在真实时区范围内` / `可临时覆盖并清除`、`可创建托盘窗口` / `动作队列可压入与取空` / `内嵌图标是合法ico`、`定长写入超长时截断且仍以零结尾`、`错误码被完整保留` / `高位错误码不丢符号位`、`只在独占控制台时才隐藏窗口`（纯函数 `should_hide`，不在测试里真去隐藏窗口 —— 那会把跑测试的终端一起藏掉）、`服务名符合可读性要求` / `显示名与描述面向用户可读` / `查询未注册的服务不报错`（只读查询，**不在测试里真去注册 / 删除服务**）、`错误码从错误信息中正确取出`、`语言标识按主语言归类`（0x0804 / 0x0404 → 中文，0x0409 / 0x0407 → 英文，0 → 取不到）、`系统语言探测结论自洽`（只断言结论落在 zh / en 内且与 `language_of` 一致，不假定跑测试的机器装的是哪种系统语言）。
- 测试数量：32 个 `#[test]`（admin 1、browser 2、console 3、locale 2、service 4、single_instance 4、timezone 3、tray 5、wide 6、winerr 2）。

## 依赖关系
- 依赖：`portguard-core`（`error::AppError/Result`、`time::DEFAULT_UTC_OFFSET_MINUTES`）；`windows`（`cfg(windows)`，含 Gdi/Shell/Console 等 feature）。
- 被依赖：`portguard-app`（权限检查、单实例、托盘、退出信号、时区、开浏览器、开机自启服务）。
