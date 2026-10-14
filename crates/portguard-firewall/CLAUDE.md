# portguard-firewall 模块规范

## 职责
- 集中承载所有 Windows 防火墙操作：封停/解封 IP、端口封锁、ICMP 屏蔽、规则查询与孤儿规则清理。
- 对外只暴露 `FirewallBackend` 抽象，屏蔽底层实现差异（真实 `netsh advfirewall` / 内存 `MockFirewall`）。
- 负责启动时清理本程序残留的孤儿规则，绝不触碰系统或第三方规则。
- 不负责：抓包与判定（属 portguard-capture / portguard-core）、配置读写、UI。
- 所有防火墙动作必须经本 crate：UI 与核心业务一律不得出现 `Command::new("netsh")`。

## 对外接口
- `trait FirewallBackend`：`name` / `is_enabled` / `block_ip` / `delete_rule` / `rule_exists` / `list_own_rules` / `block_ports` / `set_block_icmp`。
- `enum RuleDirection`：`In` / `Out`；`as_netsh()` 转 `in` / `out`。
- `struct MockFirewall`：纯内存后端；`new`，测试断言用 `blocked_ips` / `rule_names` / `calls`。
- `struct NetshFirewall`（仅 Windows）：基于 `netsh advfirewall` 的真实后端。
- `fn default_backend() -> Arc<dyn FirewallBackend>`：Windows 用 `NetshFirewall`，其他平台退回 `MockFirewall`。
- `fn cleanup_orphans(backend, active_rule_names) -> Result<Vec<String>>`：清理不在活跃列表中的本程序封停规则。
- `fn is_our_rule(name) -> bool`：宽口径归属判定（前缀 `PortGuard-`）。
- 常量：`OWN_PREFIX`=`PortGuard-`、`OWN_SYSTEM_RULES`、`RISKY_PORTS`=`[135,137,138,139,445]`、`RULE_RISKY_TCP` / `RULE_RISKY_UDP` / `RULE_ICMP_V4` / `RULE_ICMP_V6`。

## 关键约束
- 规则命名前缀：本程序规则一律以 `PortGuard-` 开头（`OWN_PREFIX`）；封停规则用 `portguard_core::ban::RULE_PREFIX`=`PortGuard-Ban-`。前缀为写死常量，禁止拼接用户输入。
- 禁止按 `remoteip` 等条件删除规则：删除只能按精确规则名进行，且必须先通过归属校验，否则可能误删系统或第三方规则。
- 禁止删除非本程序规则：`delete_rule` / `block_ip` / `block_ports` 入口均先校验前缀，不合格直接返回 `AppError::Firewall`。
- 失败不得假装成功：`netsh` 非 0 退出码必须返回 `AppError::Firewall` 并携带 stdout/stderr；`block_ip` 建规则后需 `rule_exists` 复查，防「退出码 0 但规则未生效」的静默失败。
- `netsh` 参数严格构造、禁止命令注入：一律 `Command::new("netsh").args([...])`，绝不经过 shell；参数由强类型格式化（`Ip`、`u16`、常量前缀）生成，用户输入不进入命令行。
- 操作必须幂等：`block_ip` / `block_ports` 先删同名规则再添加；`delete_rule` 对不存在的规则视为成功（解封幂等）。
- 两种归属口径勿混用：`portguard_core::ban::is_own_rule` 仅认 `PortGuard-Ban-`（窄），`backend::is_our_rule` 认 `PortGuard-`（宽，含危险端口与 ICMP 规则）；`cleanup_orphans` 只清理窄口径的封停规则。
- `NetshFirewall` 仅 Windows 编译；`rule_exists` 用 netsh 退出码判断，不解析本地化文本（规避系统语言差异）。
> 待办：`netsh::collect_stale_rules` 的筛选条件 `OWN_SYSTEM_RULES.contains(..) || is_our_rule(..)` 后半项完全覆盖前半项，且当前无调用点，属冗余实现，与根 CLAUDE.md「避免冗余代码」相悖。

## 测试
- 位置：各源文件内 `#[cfg(test)] mod tests`（`lib.rs` / `mock.rs` / `netsh.rs`）。
- 关键用例：`清理孤儿规则不会误删在用规则`、`拒绝删除非本程序规则`、`封停与删除规则幂等`、`列表只返回本程序规则`、`网际控制报文屏蔽可开可关`、`规则名必须带本程序前缀才允许创建`、`空端口列表被拒绝`、`网际控制报文不支持端口规则`、`封停规则名生成稳定`。
- 测试数量：10 个 `#[test]`（`mock.rs` 5 + `netsh.rs` 4 + `lib.rs` 1）；`netsh.rs` 用例仅在 Windows 下编译执行。

## 依赖关系
- 依赖：`portguard-core`（`error::{AppError, Result}`、`model::{Ip, Protocol}`、`ban::{ban_rule_name, is_own_rule}`）。
- 被依赖：`portguard-app`（`runtime` 中调用 `cleanup_orphans` 与 `default_backend`）。
