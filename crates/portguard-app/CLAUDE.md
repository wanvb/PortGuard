# portguard-app 模块规范

## 职责
- 主程序（可执行文件 `PortGuard.exe`），形态为「控制台 + 系统托盘 + 内嵌 Web 控制面板」单 exe 部署。
- 编排启动顺序、驱动主循环、执行退出收尾。
- `cli`：解析命令行开关；`runtime`：抓包判定 → 队列 → 执行线程的运行期业务回路；`controller`：`PortGuardApi` 实现，把状态翻译成面板视图、把操作翻译成后台动作与配置落盘。
- 不做什么：不直接实现抓包解析、防火墙规则或 Win32 细节，全部委托给对应 crate。

## 对外接口
- `cli::NAME` / `VERSION`：程序名与版本；`Options{service, panel, open_only, data_dir, auto_start}`；`Parsed::Run(Options)` / `Parsed::Print(String)`；`help_text()`、`parse<I>(args) -> Result<Parsed>`。
- `runtime::RuntimeHandle`：`new(config, logger, firewall, paths)`、`read(f)`、`config()`、`started_at_ms()`、`data_dir()`、`enqueue(Action) -> bool`、`persist_bans()`、`start() -> Result<()>`、`stop()`、`select_adapter(ip) -> Result<()>`、`apply_config(cfg) -> Result<()>`、`logs(limit)`。
- `runtime::Action`：`Ban(BanRequest)` / `Unban(Ip)` / `SyncSystemRules`；`BanRequest{ip, reason, protocol, service_port, remote_port, attempt_count, permanent_override}`。
- `runtime::Inner`：共享运行状态（config / engine / bans / events / capture / local_ip 等），同一把锁下保证快照一致。
- `controller::Controller`：`new(rt, paths, logger)`，实现 `PortGuardApi`（status / connections / bans / config / save_config / start / stop / ban_ip / unban_ip / 名单增删 / logs / events / adapters / select_adapter / set_protection / data_dir）。
- `main`：`fn main()`（无参入口，`std::process::exit(run())`）。

## 关键约束
- **启动顺序固定**：参数 → 数据目录 → 配置 → 日志 → 单实例 → 权限提示 → 运行时（抓包 + 封停）→ 面板 → 托盘 → 自动选网卡 → 开始保护 → 主循环 → 收尾。
- **抓包线程只做锁内判定 + 入队**（规范 42 / 19）：`PacketSink::consume` 在锁内更新计数、`engine.evaluate`、必要时 `tx.send(Action::Ban)`，绝不调用防火墙或写文件；netsh 与落盘全部交给 `portguard-worker` 执行线程串行完成。
- **失败不得假装成功**（规范 26.1）：`apply_ban` 先 `firewall.block_ip` 成功后才更新内存状态，失败则移除 `pending` 并写 error 事件 + 日志；到期解封删除规则失败时保持内存不变，让用户看到真实差异。
- **禁止直接调用 netsh**：所有防火墙操作经 `portguard-firewall` 的 `FirewallBackend` trait；`netsh` 仅由该 crate 内部执行，本 crate 不拼命令。
- **单实例**：`SingleInstance::acquire()` 返回 `Ok(None)` 时打开已有实例的面板后退出，不启动第二个监听器。
- **白名单硬校验**：`ban_ip` 与 `blacklist_add` 落库前查白名单；`whitelist_add` 后立即对已封停地址入队解封。
- **锁中毒不瘫**：`lock_inner` 用 `unwrap_or_else(|e| e.into_inner())` 继续使用内部数据；非测试代码 `deny(clippy::unwrap_used, clippy::expect_used)`。
- **端口顺延**：面板端口被占用时最多向后试 `PORT_FALLBACK_TRIES` 个端口，保证程序总能起来。
- > 待办：规范 23 要求「无管理员权限时不允许启动 raw socket 监听」，而 `main.rs` 在非管理员时仅记录错误与打印警告，仍会继续并按 `auto_start` 尝试开始保护（启动抓包将在运行期失败并记日志，属行为偏差）。

## 测试
- 位置：内联 `#[cfg(test)] mod tests`（`cli.rs` / `main.rs` / `controller.rs` / `runtime.rs`）。
- 关键用例：`默认选项符合预期` / `未知参数给出中文提示`、`面板地址解析支持主机与端口`、`白名单地址拒绝手动封停` / `加入白名单会写入配置文件` / `非法配置被拒绝且不覆盖已保存的文件` / `切换非法网卡地址被拒绝`、`单个实例只发放一次封停动作` / `白名单不产生封停动作` / `未选择网卡时启动会明确报错` / `事件流不会无限增长`。
- 测试数量：22 个 `#[test]`（cli 6、main 2、controller 8、runtime 6）。

## 依赖关系
- 依赖：`portguard-core`、`portguard-packet`、`portguard-firewall`、`portguard-storage`、`portguard-win`、`portguard-rdp`、`portguard-web`，以及 `serde` / `serde_json` / `thiserror` / `windows`。
- 被依赖：无（workspace 顶层可执行 crate）。
