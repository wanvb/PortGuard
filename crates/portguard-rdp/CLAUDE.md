# portguard-rdp 模块规范

## 职责
- 远程桌面接入保护：枚举 WTS 会话、查询客户端计算机名、按策略断开来路不明的 RDP 会话。
- `session` 只做 Win32 WTS 最薄封装；`policy` 承载全部判定逻辑，为纯逻辑、可完整单元测试。
- 与抓包/防火墙无关：断开动作不产生防火墙规则，不与 `portguard-firewall` 的规则管理冲突。
- 不负责：网络层封堵（属 portguard-firewall）、抓包与判定（属 portguard-capture）。

## 对外接口
- `fn evaluate(session, cfg: &RdpConfig, self_session_id: Option<u32>) -> RdpDecision`：对单个会话做判定。
- `enum RdpDecision`：`Allow(&str)` / `Block(&str)`；附 `is_block` / `reason`。
- `fn matches_client(list: &[String], client: &str) -> bool`：客户端名是否命中白名单。
- `fn sweep(cfg) -> Result<SweepReport>`：巡查全部会话并按策略断开，逐条记录结果。
- `fn validate(cfg) -> Vec<String>`：校验白名单写法。
- `fn run_once(cfg) -> Result<SweepReport>`：便捷入口，禁用时返回空报告，校验失败返回 `AppError::Config`。
- `struct SweepReport`：字段 `scanned` / `disconnected` / `failures`；附 `has_action`。
- `struct SessionInfo`：字段 `session_id` / `station` / `state` / `client_name` / `user_name`；附 `is_remote`。
- `enum SessionState`：`Active` / `Connected` / `Disconnected` / `Idle` / `Listen` / `Other(i32)`；附 `is_occupied` / `label`。
- `session` 函数：`enumerate` / `current_session_id` / `session_exists` / `disconnect(session_id, wait)`。

## 关键约束
- 不得在回调/判定线程做长操作：`disconnect` 固定以 `wait=false` 调用，避免在巡查路径上阻塞；WTS 调用仅薄封装，无重试与等待循环。
- 白名单语义：`client_whitelist` 为空 = 不限制（避免一次误配置锁死服务器）；命中（大小写不敏感，`*` 仅末尾表示前缀匹配）= 放行；未命中 = 断开；无法识别客户端名 = 断开。
- 本地控制台会话永不处理：控制台无客户端名（`is_remote` 为 false），断开它会把管理员锁在门外。
- 本程序所在会话永不处理：`evaluate` 以 `self_session_id` 跳过；`disconnect` 二次校验并拒绝断开自身会话。
- 失败必须逐条上报：`sweep` 遇断开失败记入 `SweepReport.failures`，不静默跳过；部分成功仍返回 `Ok` 报告供上层展示。
- 校验通配符：`*` 只允许出现在末尾，用 `strip_suffix` 判定而非按下标切片，避免中文规则名触发非字符边界 panic。
- 非测试代码禁止 `unwrap` / `expect`：`#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]`。
- `session` 依赖 `windows` crate（Cargo 中仅 `cfg(windows)`），但模块未做条件编译，故本 crate 实际仅在 Windows 可编译与测试。

## 测试
- 位置：`policy.rs`、`session.rs` 内 `#[cfg(test)] mod tests`。
- 关键用例：`未启用时全部放行`、`白名单命中的客户端放行`、`匹配不区分大小写`、`未命中的客户端被断开`、`本地控制台会话永不处理`、`本程序所在会话永不处理`、`白名单为空表示不限制`、`通配符前缀匹配`、`校验能发现中间通配符`、`本地控制台会话不算远程`、`拒绝断开自身会话`。
- 测试数量：19 个 `#[test]`（`policy.rs` 13 + `session.rs` 6）。

## 依赖关系
- 依赖：`portguard-core`（`config::RdpConfig`、`error::{AppError, Result}`）；`windows` crate（features `Win32_Foundation` / `Win32_System_RemoteDesktop` / `Win32_System_Threading`，仅 `cfg(windows)`）。
- 被依赖：`portguard-app`。
