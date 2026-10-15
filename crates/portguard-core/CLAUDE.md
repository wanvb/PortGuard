# portguard-core 模块规范

## 职责
- 纯业务逻辑层：领域模型、配置模型与 TOML 读写、IP 规则解析、累计连接计数、封停状态机、规则引擎、日志内存缓冲、表现层契约。
- 不调用任何 Win32 / WinSock API，不做网络 I/O，无平台相关代码（规范 3.1）。
- 不决定「如何封停」：只产出判定结果（`Outcome`）与封停记录（`BanRecord`），实际防火墙操作由 `portguard-firewall` 承担。
- 不负责日志落盘：只提供 `LogLine` 与内存缓冲，写磁盘由 `portguard-storage` 的独立线程完成（规范 42）。
- 时间完全由调用方注入（Unix 纪元毫秒 `u64`），因此可在任意机器 `cargo test`，无需管理员权限、无需真实网卡。

## 对外接口
| 模块 | pub 类型 / 关键函数 | 说明 |
|------|------|------|
| `model` | `Ip`（= `Ipv4Addr`）、`Protocol`、`TrafficDirection`、`PortGroup`、`TcpFlags`、`FlagClass`、`PacketInfo`、`BanReason`、`BanRecord`、`IgnoreCounters`、`Statistics` | 领域数据结构与 `Display`/`label`/`as_str` 辅助；`Statistics.ignored` 承载被丢弃数据包的分类计数；`TcpFlags::is_connection_request`（入站 SYN）与 `is_handshake_accepted`（出站 SYN+ACK）是两种连接事件来源 |
| `config` | `Config`、`ProtectionRule`、`ProtectConfig`、`PanelConfig`、`NetworkConfig`、`BanConfig`、`ListsConfig`、`RdpConfig`、`SystemConfig`、`LoggingConfig`、`GeoConfig`、`DEFAULT_GEO_DB`、`DEFAULT_PANEL_BIND`、`CURRENT_CONFIG_VERSION` | `Config::with_defaults/from_toml/to_toml/load/save/normalize/migrate/validate/has_any_protected_port`；`GeoConfig{enabled, db}` 默认开启、文件名可回退；`ProtectConfig.count_accept` 决定连接事件来源（**默认 `true`**，规范 4.1 修订）；`DEFAULT_PANEL_BIND = "127.0.0.1:58080"` |
| `observe` | `Observer`、`Observation`、`MAX_ENTRIES`、`direction_label` | 纯诊断的抓包观测表：按「方向 + 协议 + 本机端口 + 标志类别」计数，`observe` / `top` / `count_matching` / `clear` / `overflow` |
| `iprange` | `IpRange`、`IpSet`、`parse_ipv4`、`u32_to_ip` | 支持单 IP / 区间 / 末段通配 / CIDR / 多段通配；`IpSet::from_rules` 任一条非法即整体失败 |
| `tracker` | `TrackKey`、`TrackEntry`、`ConnectionTracker` | `record` 返回**累计**事件次数；`prune`（条目回收即计数归零）、`remove_ip`、`iter_entries` |
| `ban` | `RULE_PREFIX`、`ban_rule_name`、`is_own_rule`、`BanManager` | `make_record`、`ban`、`unban`、`take_expired`、`restore`、`snapshot` |
| `engine` | `RuleEngine`、`Outcome`、`EngineStats`、`ConnectionRow`、`FLAG_SYN` | `new`、`reload`、`set_local_ip`、`evaluate`、`connection_rows`、`prune`、`protected_port_count`、`set_count_accept` / `count_accept`；`EngineStats.ignored` 与 `Outcome::Ignored` 的 `reason` 一一对应 |
| `logging` | `Level`、`LogLine`、`LogBuffer` | `push`、`tail`、`render` |
| `api` | `PortGuardApi`（trait）、`StatusView`、`ConnectionView`、`BanView`、`AdapterView`、`EventView`、`ObservedPortView`、`BanSource`、`ProtectionSwitch`、`protocol_label`、`reason_label` | 表现层唯一依赖面，全部方法必须快速返回；`StatusView` 含 `geo_ready` / `geo_status` / `parse_errors` / `parse_samples` / `observed` / `count_accept`，`ConnectionView` / `BanView` 含 `location`（纯展示，规范 22） |
| `error` | `AppError`、`Result<T>` | 全项目统一错误类型 |
| `time` | `now_ms`、`format_ms`、`format_ms_with_offset`、`DEFAULT_UTC_OFFSET_MINUTES` | 纯整数民用历法换算，不引入 chrono |
| 顶层 | `VERSION`（取自 `CARGO_PKG_VERSION`） | — |

## 关键约束
- 禁止任何 Win32 / WinSock 调用（规范 3.1）；本 crate 依赖仅 `serde` / `toml` / `thiserror`，不含 `windows`。
- 生产代码禁止 `unwrap()` / `expect()`，统一 `Result<T, AppError>` 向上传播；`lib.rs` 以 `#![deny(clippy::unwrap_used, clippy::expect_used)]` 强制，测试经 `cfg_attr(test, allow(...))` 豁免（规范 27）。
- 判定顺序唯一权威实现在 `engine.rs`：白名单 → 黑名单 → 保护端口 → 累计次数阈值 → 封停（规范 5.1）。
- 阈值判定用**累计连接次数**，不做滑动窗口：`count >= max_attempts` 即封停。计数唯一的归零路径是条目空闲超保留期被 `prune` 回收（保留期由 `portguard-app` 的 `TRACK_RETENTION_MS` 决定，当前 10 分钟）。禁止重新引入按时间滑出的窗口计数：稀疏但反复的连接会因此永远够不到阈值，表现为「面板累计次数一直涨却从不封停」的漏封（规范 5.1 修订）。
- `ProtectionRule` 只有 `ports` 与 `max_attempts` 两个字段：`window_seconds` 已废弃，不得再以任何形式加回（旧 `config.toml` 里残留的该字段由 serde 静默忽略，不需要兼容分支）。
- 白名单优先最高，任何路径（threshold / blacklist / manual / restore）都不得封停白名单 IP（规范 26.2）；`BanManager::ban` 命中白名单必须返回 `Err`，不得假装成功。
- 白名单命中即返回，**不参与阈值判定**；但可计数的包（TCP 为 `SYN && !ACK`、UDP 任意报文）在端口属于某保护组时会经 `record_display_only` 写入跟踪表，仅用于面板展示 `WHITELIST` 状态，不得累加阈值、不得产生封停。
- 判定中每条丢弃路径都必须累加对应的 `IgnoreCounters`，禁止新增无计数的静默丢弃分支（否则面板无法区分抓包问题与判定问题）。
- `observe` 模块的观测表（`Observer`）绝不参与判定，也不得因判定结果而丢弃记录；它只回答「这个端口的包有没有被收到」，条目上限 256，超出只累加 `overflow`。
- 连接事件来源只有两种且互斥：`count_accept == true`（**默认**）时用本机发出的 `SYN+ACK`；为 `false` 时改用入站 `SYN && !ACK`（云主机混杂模式收不到入站包，默认走握手响应口径即可开箱即用，见 `docs/behavior-spec.md` 2.1.2 / 2.5）。不得两路同时累加，否则同一次连接会被计两次、阈值事实上折半。口径判定统一走 `RuleEngine::is_connection_event`，白名单的「仅展示记录」也必须复用同一判据，不得各写一份。
- `Config::validate` 必须拒绝「三组保护端口全空」的配置：这种配置下程序运行但零保护能力，属静默失效。
- 一切封停必须经 `BanManager`，UI 与引擎不得直接操作封停 Map（规范 7）。
- 防火墙规则归属靠 `RULE_PREFIX = "PortGuard-Ban-"` 前缀识别；`is_own_rule` 用于清理时精确筛选，绝不得按 IP 无条件删除系统或第三方规则（规范 8.4）。
- `Config::default()` 与 `Config::with_defaults()` 必须同源：`#[serde(default)]` 在局部配置或旧配置文件缺失字段时走的即是此默认值，若给空端口会静默失去保护能力。
- **面板默认端口唯一来源是 `DEFAULT_PANEL_BIND`（`127.0.0.1:58080`）**：`portguard-web` 的 `DEFAULT_BIND` 直接引用它，不得另写字面量。旧默认值 `127.0.0.1:18080` 由 `Config::migrate()` 迁移（结构版本 1 → 2，18080 是各类本地调试工具的常用端口，冲突概率高），迁移与 `normalize` **分开**：`migrate` 只改内存并返回中文说明清单，是否落盘由 `portguard-app` 在启动时决定（必须落盘，否则第二个实例会照文件里的旧端口去开面板）。凡是仍等于旧默认值的配置一律迁移，刻意保留 18080 的写法不再支持。
- `GeoConfig` 只控制「是否展示地理位置」与「库文件名」，**不得**参与任何判定；库文件缺失时程序必须照常工作（规范 22）。旧版数据文件（`config.dat` / `BanData.bin`）已永久放弃，不得在配置中留兼容字段或别名。
- IP 匹配比较阶段统一用 `u32`，禁止逐包做字符串切割（规范 21）；`IpSet::from_rules` 任一条非法即整体失败，避免静默丢规则。
- 时间不得用 `SystemTime` 直接参与逻辑，一律以调用方注入的 `now_ms` 表达，保证引擎与跟踪器可单测。


## 测试
- 位置：各源文件内联 `#[cfg(test)] mod tests`。
- 分布：`ban.rs` 11、`config.rs` 14、`engine.rs` 31、`iprange.rs` 11、`logging.rs` 5、`observe.rs` 5、`time.rs` 5、`tracker.rs` 9。
- 合计 `#[test]`：91 个。
- 关键用例：
  - `ban`：白名单地址手动封停同样被拒绝、永久封停不会被临时封停降级、恢复时丢弃白名单记录并可用到期回收清理防火墙、规则名前缀可识别归属。
  - `config`：空文件解析为默认值、只写面板段时保护端口不丢失、注释与空行在规范化时被剔除、三组保护端口全空被校验拒绝、旧默认面板端口被迁移到新端口（迁移幂等且会如实上报）。
  - `engine`：白名单优先于黑名单、累计达到阈值即封停、累计计数不因时间间隔归零、入站口径（`count_accept = false`）下握手响应不算新连接、默认配置下入站 SYN 不再计数、打开后出站 SYN+ACK 计一次、两种事件来源互斥不会重复计数（阈值不折半）、同端口同时属于两组时两组独立计数、非法白名单不会清空既有规则、五类忽略原因分别计数、白名单地址留下展示记录但绝不封停。
  - `observe`：入站与出站分别归类、同键累计次数、条目上限不会无限增长、可按条件统计服务端口、非本机流量归入端口零。
  - `iprange`：区间写反时自动纠正、多段通配、非尾部通配判定非法、规则集遇非法规则整体失败。
  - `tracker`：间隔很久仍继续累计、定期清理过期条目会重置计数、同地址不同端口分别计数、条目上限触发淘汰不会无限增长。
  - `time`：已知时间点换算正确、闰年二月正确处理、时区偏移可配置。

## 依赖关系
- 本 crate 依赖：`serde`、`toml`、`thiserror`（版本随工作区锁定，勿放宽）。
- 被依赖：`portguard-packet`、`portguard-firewall`、`portguard-storage`、`portguard-rdp`、`portguard-web`、`portguard-win`、`portguard-app`。
