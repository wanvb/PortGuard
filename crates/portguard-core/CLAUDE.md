# portguard-core 模块规范

## 职责
- 纯业务逻辑层：领域模型、配置模型与 TOML 读写、IP 规则解析、滑动窗口连接跟踪、封停状态机、规则引擎、日志内存缓冲、表现层契约。
- 不调用任何 Win32 / WinSock API，不做网络 I/O，无平台相关代码（规范 3.1）。
- 不决定「如何封停」：只产出判定结果（`Outcome`）与封停记录（`BanRecord`），实际防火墙操作由 `portguard-firewall` 承担。
- 不负责日志落盘：只提供 `LogLine` 与内存缓冲，写磁盘由 `portguard-storage` 的独立线程完成（规范 42）。
- 时间完全由调用方注入（Unix 纪元毫秒 `u64`），因此可在任意机器 `cargo test`，无需管理员权限、无需真实网卡。

## 对外接口
| 模块 | pub 类型 / 关键函数 | 说明 |
|------|------|------|
| `model` | `Ip`（= `Ipv4Addr`）、`Protocol`、`TrafficDirection`、`PortGroup`、`TcpFlags`、`PacketInfo`、`BanReason`、`BanRecord`、`Statistics` | 领域数据结构与 `Display`/`label`/`as_str` 辅助 |
| `config` | `Config`、`ProtectionRule`、`ProtectConfig`、`PanelConfig`、`NetworkConfig`、`BanConfig`、`ListsConfig`、`RdpConfig`、`SystemConfig`、`LoggingConfig`、`CURRENT_CONFIG_VERSION` | `Config::with_defaults/from_toml/to_toml/load/save/normalize/validate` |
| `iprange` | `IpRange`、`IpSet`、`parse_ipv4`、`u32_to_ip` | 支持单 IP / 区间 / 末段通配 / CIDR / 多段通配；`IpSet::from_rules` 任一条非法即整体失败 |
| `tracker` | `TrackKey`、`TrackEntry`、`ConnectionTracker` | `record` 返回当前窗口计数；`peek_count`、`prune`、`remove_ip`、`iter_entries` |
| `ban` | `RULE_PREFIX`、`ban_rule_name`、`is_own_rule`、`BanManager` | `make_record`、`ban`、`unban`、`take_expired`、`restore`、`snapshot` |
| `engine` | `RuleEngine`、`Outcome`、`EngineStats`、`ConnectionRow`、`FLAG_SYN` | `new`、`reload`、`set_local_ip`、`evaluate`、`connection_rows`、`prune`、`protected_port_count` |
| `logging` | `Level`、`LogLine`、`LogBuffer` | `push`、`tail`、`render` |
| `api` | `PortGuardApi`（trait）、`StatusView`、`ConnectionView`、`BanView`、`AdapterView`、`EventView`、`BanSource`、`ProtectionSwitch`、`protocol_label`、`reason_label` | 表现层唯一依赖面，全部方法必须快速返回 |
| `error` | `AppError`、`Result<T>` | 全项目统一错误类型 |
| `time` | `now_ms`、`format_ms`、`format_ms_with_offset`、`DEFAULT_UTC_OFFSET_MINUTES` | 纯整数民用历法换算，不引入 chrono |
| 顶层 | `VERSION`（取自 `CARGO_PKG_VERSION`） | — |

## 关键约束
- 禁止任何 Win32 / WinSock 调用（规范 3.1）；本 crate 依赖仅 `serde` / `toml` / `thiserror`，不含 `windows`。
- 生产代码禁止 `unwrap()` / `expect()`，统一 `Result<T, AppError>` 向上传播；`lib.rs` 以 `#![deny(clippy::unwrap_used, clippy::expect_used)]` 强制，测试经 `cfg_attr(test, allow(...))` 豁免（规范 27）。
- 判定顺序唯一权威实现在 `engine.rs`：白名单 → 黑名单 → 保护端口 → 次数阈值 → 封停（规范 5.1）。
- 白名单优先最高，任何路径（threshold / blacklist / manual / restore）都不得封停白名单 IP（规范 26.2）；`BanManager::ban` 命中白名单必须返回 `Err`，不得假装成功。
- 一切封停必须经 `BanManager`，UI 与引擎不得直接操作封停 Map（规范 7）。
- 防火墙规则归属靠 `RULE_PREFIX = "PortGuard-Ban-"` 前缀识别；`is_own_rule` 用于清理时精确筛选，绝不得按 IP 无条件删除系统或第三方规则（规范 8.4）。
- `Config::default()` 与 `Config::with_defaults()` 必须同源：`#[serde(default)]` 在局部配置或旧版升级缺失字段时走的即是此默认值，若给空端口会静默失去保护能力。
- IP 匹配比较阶段统一用 `u32`，禁止逐包做字符串切割（规范 21）；`IpSet::from_rules` 任一条非法即整体失败，避免静默丢规则。
- 时间不得用 `SystemTime` 直接参与逻辑，一律以调用方注入的 `now_ms` 表达，保证引擎与跟踪器可单测。

> 待办：`engine.rs` 中 `record_and_judge`、`record_and_judge_web` 与 UDP 分支内的「记录 + 判定」逻辑三份近乎重复（仅 `ProtectionRule` 与 `PortGroup` 不同），与根 CLAUDE.md「避免冗余代码」不符，宜抽为按 `(规则, 分组)` 参数化的单一实现。

## 测试
- 位置：各源文件内联 `#[cfg(test)] mod tests`。
- 分布：`ban.rs` 11、`config.rs` 9、`engine.rs` 22、`iprange.rs` 11、`logging.rs` 5、`time.rs` 5、`tracker.rs` 10。
- 合计 `#[test]`：73 个。
- 关键用例：
  - `ban`：白名单地址手动封停同样被拒绝、永久封停不会被临时封停降级、恢复时丢弃白名单记录并可用到期回收清理防火墙、规则名前缀可识别归属。
  - `config`：空文件解析为默认值、只写面板段时保护端口不丢失、注释与空行在规范化时被剔除。
  - `engine`：白名单优先于黑名单、超阈值触发封停、握手响应不算新连接、同端口同时属于两组时两组独立计数、非法白名单不会清空既有规则。
  - `iprange`：区间写反时自动纠正、多段通配、非尾部通配判定非法、规则集遇非法规则整体失败。
  - `tracker`：窗口滑出后旧事件不再计数、生命周期累计计数不受窗口影响、条目上限触发淘汰不会无限增长。
  - `time`：已知时间点换算正确、闰年二月正确处理、时区偏移可配置。

## 依赖关系
- 本 crate 依赖：`serde`、`toml`、`thiserror`（版本随工作区锁定，勿放宽）。
- 被依赖：`portguard-packet`、`portguard-firewall`、`portguard-storage`、`portguard-rdp`、`portguard-web`、`portguard-win`、`portguard-app`。
