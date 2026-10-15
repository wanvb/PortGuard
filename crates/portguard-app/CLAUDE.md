# portguard-app 模块规范

## 职责
- 主程序（可执行文件 `PortGuard.exe`），形态为「系统托盘 + 内嵌 Web 控制面板」单 exe 部署（控制台窗口默认隐藏，`--console` 可保留）。
- 编排启动顺序、驱动主循环、执行退出收尾。
- `cli`：解析命令行开关；`runtime`：抓包判定 → 队列 → 执行线程的运行期业务回路；`controller`：`PortGuardApi` 实现，把状态翻译成面板视图、把操作翻译成后台动作与配置落盘。
- `build.rs`：仅对 MSVC 目标向 `PortGuard.exe` 注入内嵌应用程序清单（`/MANIFEST:EMBED` + `/MANIFESTUAC:level='requireAdministrator'`），使双击运行默认弹出 UAC 提权，无需用户手动右键「以管理员身份运行」。
- 不做什么：不直接实现抓包解析、防火墙规则或 Win32 细节，全部委托给对应 crate。

## 对外接口
- `cli::NAME` / `VERSION`：程序名与版本；`Options{service, panel, open_only, data_dir, auto_start, console}`；`Parsed::Run(Options)` / `Parsed::Print(String)`；`help_text()`、`parse<I>(args) -> Result<Parsed>`。
- `main::fail(message, console_hidden, code)`：启动期致命错误按「控制台可见性」选打印还是弹对话框。
- `runtime::RuntimeHandle`：`new(config, logger, firewall, paths)`、`read(f)`、`config()`、`started_at_ms()`、`data_dir()`、`enqueue(Action) -> bool`、`persist_bans()`、`start() -> Result<()>`、`stop()`、`select_adapter(ip) -> Result<()>`、`apply_config(cfg) -> Result<()>`、`logs(limit)`。
- `runtime::Action`：`Ban(BanRequest)` / `Unban(Ip)` / `SyncSystemRules`；`BanRequest{ip, reason, protocol, service_port, remote_port, attempt_count, permanent_override}`。
- `runtime::Inner`：共享运行状态（config / engine / bans / events / capture / local_ip / observer 等），同一把锁下保证快照一致；另提供 `capture_diagnostics`、`count_accept`、`reset_observer`。
- `runtime::OBSERVE_TOP_LIMIT`：面板「抓包观测」展示条数（12）。
- `controller::Controller`：`new(rt, paths, logger)`，实现 `PortGuardApi`（status / connections / bans / config / save_config / start / stop / ban_ip / unban_ip / 名单增删 / logs / events / adapters / select_adapter / set_protection / data_dir）；额外持有 `RwLock<GeoLookup>`（地理位置展示，`reload_geo` / `location_of` / `with_geo`）。
- `main`：`fn main()`（无参入口，`std::process::exit(run())`）；`fail()` 统一处理启动期致命错误的呈现方式。

## 关键约束
- **启动顺序固定**：参数 → **服务模式分发** → 隐藏控制台窗口 → 数据目录 → 配置 → 日志 → 旧配置迁移 → 单实例 → 权限提示 → 运行时（抓包 + 封停）→ 面板 → 托盘 → 自动选网卡 → 开始保护 → 主循环 → 收尾。
- **控制台窗口默认隐藏**（`cli.Options.console == false`）：`portguard_win::hide_own_console_window()` 只在控制台独占本进程时动手，从 cmd 启动或加 `--console` 时保留窗口。隐藏判定必须放在最前（越早越小概率看到黑窗口闪烁），且隐藏后启动期的致命错误一律走 `fail` 的对话框分支 —— 否则表现为「双击没反应」（规范 26.1）。托盘形态不变：右键菜单照旧提供打开面板 / 暂停保护 / 退出。
- **UAC 自提权必须靠内嵌清单**：`build.rs` 用 `cargo:rustc-link-arg-bins` 下发链接参数，不受环境变量 `RUSTFLAGS` 覆盖，因此 `build.bat` 的静态 CRT 分支（会设置 `RUSTFLAGS`）同样带上清单。**不得改用 `.cargo/config.toml` 的 `rustflags`** —— 它会被 `RUSTFLAGS` 整体覆盖，表现为某一类构建静默丢失提权清单。`/MANIFEST:EMBED` 保证清单写进 exe 的 `RT_MANIFEST` 资源，而不是生成同目录的外部 `.manifest` 文件（后者不会触发提权）。非 Windows / 非 MSVC 目标不注入。清单缺失时 `mt.exe -inputresource:PortGuard.exe;#1` 会报「指定的映像文件不包含资源区域」。
- **服务模式与提权清单不冲突**：`--service` 由 SCM 以 LocalSystem 拉起，服务管理器不读清单、不弹 UAC；降级路径（`portguard_win::admin` 判定非管理员 → 只告警不启动保护）继续保留，用于 UAC 被系统关闭（`EnableLUA=0`）等仍然拿不到提升令牌的场景。
- **启动期告警在隐藏控制台后改走托盘气泡**：非管理员、自动开始保护失败两条都写进 `notices`，托盘建好后逐个 `balloon`；服务模式（会话 0）没有托盘，只留日志与面板。
- **旧配置迁移必须落盘**：`Config::migrate()` 只改内存，主程序拿到非空结果后立即 `store.save`（写盘失败只告警不退出，迁移在本次运行仍然生效）。不落盘的话，第二个实例会拿文件里的旧端口去开面板，而运行中的实例已换到新端口，用户看到的就是「页面打不开」。
- **抓包线程只做锁内判定 + 入队**（规范 42 / 19）：`PacketSink::consume` 在锁内更新计数、`engine.evaluate`、必要时 `tx.send(Action::Ban)`，绝不调用防火墙或写文件；netsh 与落盘全部交给 `portguard-worker` 执行线程串行完成。
- **失败不得假装成功**（规范 26.1）：`apply_ban` 先 `firewall.block_ip` 成功后才更新内存状态，失败则移除 `pending` 并写 error 事件 + 日志；到期解封删除规则失败时保持内存不变，让用户看到真实差异。
- **封停后不删除跟踪行**：`apply_ban` 只更新 `bans`，跟踪表记录保留，`Inner::connection_rows` 依 `bans.is_banned` 把状态标为 `BANNED` / `PERMANENT`，用户仍能看到该 IP 打的是哪个端口、累计多少次；行本身按 5 分钟 TTL 与 10 分钟保留期自然回收。
- **保护端口全空必须告警**：`RuntimeHandle::new` 检测 `config.has_any_protected_port()`，全空时写一条 `warn` 事件（面板可见）与告警日志，避免「程序在跑但零保护」这种静默失效。
- **先观测再判定**：`PacketSink::consume` 在 `engine.evaluate` **之前**把包记入 `Inner::observer`，被判定层丢弃的包同样要留下记录，否则无法分辨「没抓到」与「被丢掉」。
- **阈值判定用累计连接次数**：判定不做滑动窗口，`count >= max_attempts` 即封停；计数唯一的归零路径是 `TRACK_RETENTION_MS`（10 分钟）空闲后 `expire_pass` 的 `engine.prune` 回收该条目。调小该值会让计数更快归零（更容易漏封），调大则让「隔很久来一次」的地址也可能被累计到阈值，改动需同步 `docs/behavior-spec.md` 2.6。
- **连接事件来源可自动回退**：`accept_pass`（随 5 秒 PRUNE 周期跑）在「受保护 TCP 端口无入站 SYN + 有本机发出的 SYN+ACK」同时成立时自动 `engine.set_count_accept(true)`，写 `warn` 事件与日志说明原因。该判定只做一次：配置里 `count_accept` 被显式改动（`apply_config` 检测到值变化）或启动时即为 `true`（**默认值**，此时根本没有回退的必要），都视为用户已决定，之后永不覆盖；只有自动切换的结果在换网卡时允许重新判定。因此自动回退只对「旧配置里写着 `false`」的机器有意义。重新开始抓包与切换网卡都要 `reset_observer`。
- **禁止直接调用 netsh**：所有防火墙操作经 `portguard-firewall` 的 `FirewallBackend` trait；`netsh` 仅由该 crate 内部执行，本 crate 不拼命令。
- **单实例**：`SingleInstance::acquire()` 返回 `Ok(None)` 时打开已有实例的面板后退出，不启动第二个监听器。
- **白名单硬校验**：`ban_ip` 与 `blacklist_add` 落库前查白名单；`whitelist_add` 后立即对已封停地址入队解封。
- **锁中毒不瘫**：`lock_inner` 用 `unwrap_or_else(|e| e.into_inner())` 继续使用内部数据；非测试代码 `deny(clippy::unwrap_used, clippy::expect_used)`。
- **端口顺延**：面板端口被占用时最多向后试 `PORT_FALLBACK_TRIES` 个端口，保证程序总能起来。
- **非管理员不启动保护**（规范 23）：非管理员时跳过自动开始保护并打印明确指引，而不是先启动再失败。
- **服务模式**（`--service`）：由 Windows 服务管理器（SCM）以 LocalSystem 在会话 0 拉起（服务项由 `portguard_win::Service` 注册），既不建托盘也不自动打开浏览器（`should_open_browser` 三条件之一）。
- **服务分发必须抢在读配置与单实例之前**：`main::run` 解析参数后发现 `opts.service` 立即调用 `portguard_win::Service::run(move || run_app(opts))`；主体逻辑抽在 `run_app(opts)` 里。一旦落在分发之后，「已有实例在运行」这条早退路径会让 SCM 空等到 30 秒超时，用户看到的是 1053「服务没有及时响应启动或控制请求」。单实例早退在服务模式下不再尝试开浏览器（会话 0 无桌面，只会失败刷日志）。
- **服务开关只改「是否注册」**：`Controller::set_protection` 的 `Autostart` 分支先 `Service::install` / `Service::uninstall`，成功后才写 `system.autostart` 并落盘；防火墙 / 服务操作失败一律向上返回错误，不得只改配置假装成功（规范 26.1）。勾选不立即启动服务，下次开机由 SCM 拉起。
- **备注与地理位置一样由 controller 在锁外填充**：`ConnectionView.port_note` / `ip_note` 与 `BanView.port_note` / `ip_note` 都是纯展示字段，`connections()` / `bans()` 先在锁内取快照，再按 `ProtectConfig::port_note` / `port_note_any` 与 `ListsConfig::rule_note` 查配置填充；`runtime` 侧只把这两个字段留空，判定路径不接触备注。
- **地理位置在运行期锁之外查询**（规范 22）：`connections()` / `bans()` 先在锁内取快照、释放锁，再用 `location_of` 逐行填充 `location`；抓包线程与判定路径完全不接触 `portguard-geo`。
- **地理位置库可在运行期重载**：`save_config` 检测到 `geo` 段变化时立即 `reload_geo`，避免「改了设置但没生效」的静默失效；`geo_candidates` 按「数据目录 → 程序目录」给出候选路径。

## 测试
- 位置：内联 `#[cfg(test)] mod tests`（`cli.rs` / `main.rs` / `controller.rs` / `runtime.rs`）。
- 关键用例：`默认选项符合预期` / `默认隐藏控制台窗口` / `未知参数给出中文提示`、`面板地址解析支持主机与端口`、`白名单地址拒绝手动封停` / `加入白名单会写入配置文件` / `备注随端口与名单落盘并在删除后清除` / `非法配置被拒绝且不覆盖已保存的文件` / `切换非法网卡地址被拒绝`、`单个实例只发放一次封停动作` / `白名单不产生封停动作` / `未选择网卡时启动会明确报错` / `事件流不会无限增长` / `封停后跟踪行保留并标记状态` / `保护端口为空时启动会写入告警事件` / `观测表记录被判定层丢弃的包` / `入站不可见时自动改用握手响应` / `入站可见时不做自动切换` / `用户显式设置后不再自动改写`。
- 测试数量：34 个 `#[test]`（cli 7、main 3、controller 12、runtime 12）；`main` 侧含 `自动打开浏览器受三条件约束`，controller 侧含 `地理位置库候选路径优先数据目录` / `数据库缺失时地理位置恒为未知` / `保存配置后地理位置库立即重载`。

## 依赖关系
- 依赖：`portguard-core`、`portguard-packet`、`portguard-firewall`、`portguard-storage`、`portguard-win`、`portguard-rdp`、`portguard-geo`、`portguard-web`，以及 `serde` / `serde_json` / `thiserror` / `windows`。
- 被依赖：无（workspace 顶层可执行 crate）。
