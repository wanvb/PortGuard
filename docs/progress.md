# PortGuard 开发进度

> 最后更新：2026-10-14
> 测试规模：**264 项全部通过**（`cargo test --workspace`），`cargo clippy --workspace --all-targets` 零警告。

---

## 总体状态

| 模块 | 测试数 | 状态 |
| --- | --- | --- |
| `portguard-core` | 88 | 完成 |
| `portguard-packet` | 18 | 完成 |
| `portguard-firewall` | 10 | 完成 |
| `portguard-storage` | 19 | 完成 |
| `portguard-rdp` | 19 | 完成 |
| `portguard-win` | 27 | 完成 |
| `portguard-geo` | 18 | 完成 |
| `portguard-web` | 33 | 完成 |
| `portguard-app` | 32 | 完成 |
| **合计** | **264** | — |

---

## Phase 0 — 源码考古

### Completed

- 按旧版行为基线梳理需求（判定顺序、端口分组、封停语义、系统级保护）

### Known Issues

- **行为基线来自规范文本而非逆向原程序**：旧版源码 `PortGuard.txt` 不作为兼容目标，细节（窗口默认值、边界取舍）可能与原版存在出入
- **旧版数据文件已放弃**：`config.dat` / `BanData.bin` 永久不迁移，见 Phase 13

---

## Phase 1 — Rust 工程骨架

### Completed

- 9 个 crate 的 workspace（Phase 13 新增 `portguard-geo`），Rust 1.77.2 锁定，依赖精确锁定
- `Cargo.lock` 入库

---

## Phase 2 — Packet Parser

### Completed

- IPv4 / TCP / UDP 解析，按 IHL 与 data offset 处理变长头
- 以太网头自动识别与跳过
- TCP 标志位解码

### Tests

- `parser.rs` 13 项：畸形包不 panic、分片包跳过、头长变化、标志位全量覆盖

---

## Phase 3 — Windows Raw Socket

### Completed

- `WSAStartup → socket(AF_INET, SOCK_RAW, IPPROTO_IP) → bind → WSAIoctl(SIO_RCVALL) → recv` 循环
- 接收超时 500 ms，可响应停止请求
- 失败路径全部先 `closesocket` + `WSACleanup`，避免 Winsock 引用计数泄漏

### Tests

- 依赖真实网卡与管理员权限，无自动化测试；**已真机验证**：管理员启动后 45 秒捕获 12969 个包

---

## Phase 4 — 网卡管理

### Completed

- `GetAdaptersAddresses` 枚举 IPv4 网卡（描述、状态、接口类型、前缀长度）
- 虚拟网卡按关键字识别，是否展示由 `network.include_virtual` 决定
- 自动选网卡：物理优先、非 APIPA（169.254.x.x）优先

### Tests

- `adapter.rs` 5 项

---

## Phase 5 — Core Rule Engine

### Completed

- 判定顺序：白名单 → 黑名单 → 受保护端口 → 阈值 → 封停
- 滑动窗口跟踪，TCP 仅 `SYN && !ACK` 计为新连接，UDP 每包计数
- TCP / WEB / UDP 三组独立阈值，端口重合时两组各自计数
- 封停状态机：临时 / 永久、升级不降级、白名单硬校验、到期回收
- IP 规则解析：单地址 / 区间 / CIDR / 尾段通配 / 多段通配

### Tests

- `engine.rs` 22、`ban.rs` 11、`iprange.rs` 11、`tracker.rs` 10、`config.rs` 9、`logging.rs` 5、`time.rs` 5

---

## Phase 6 — Firewall

### Completed

- `FirewallBackend` trait + `NetshFirewall`（真实）与 `MockFirewall`（测试）
- 规则命名 `PortGuard-Ban-<ip>`，系统规则 `PortGuard-Protect-*` / `PortGuard-Block-ICMPv*`
- 归属校验：删除只按精确规则名，且必须是本程序前缀
- `block_ip` 建规则后复查 `rule_exists`，防「退出码 0 但规则未生效」

### Tests

- `mock.rs` 5、`netsh.rs` 4、`lib.rs` 1（孤儿规则清理）

---

## Phase 7 — Persistence

### Completed

- `config.toml` 首次运行生成带注释模板；损坏时备份为 `config.toml.broken-<毫秒>` 再回退默认
- `state/bans.json` 落盘；损坏直接报错，不当作空列表
- 日志：内存环形缓冲 + 后台批量落盘，16 MiB 滚动
- 原子写：统一 `write_atomic`（写 `.tmp` → rename）
- 配置默认值与 `#[serde(default)]` 同源，避免局部配置静默失去保护能力

### Tests

- `bans.rs` 6、`config_store.rs` 5、`logger.rs` 5、`paths.rs` 3

---

## Phase 8 — Web 控制面板

### Completed

- 五个页面（概览 / 当前连接 / 封停列表 / 设置 / 运行日志），深色工业风
- 纯 ES6 + `fetch`，无构建步骤、无第三方库，经 `include_str!` 内嵌
- 所有动态数据经 `textContent` 写入 DOM

---

## Phase 9 — 面板 + 核心打通

### Completed

- `PortGuardApi` 契约 + `Controller` 实现，路由层为纯函数
- 11 个只读接口 + 9 个变更接口
- 安全：仅回环、Host 校验（按**实际监听地址**比对）、Origin 校验、请求体上限 1 MiB

### Tests

- `assets.rs` 4、`router.rs` 6、`server.rs` 3、`testapi.rs` 7、`e2e.rs` 12（真实 TCP + 裸 HTTP）

---

## Phase 10 — RDP Guard

### Completed

- RDP 会话枚举与客户端计算机名白名单判定
- 每 15 秒巡检一次，仅在产生动作时写事件与日志

### Tests

- `policy.rs` 13、`session.rs` 6

---

## Phase 11 — Tray / Startup

### Completed

- 系统托盘：内嵌 ICO、右键菜单（打开面板 / 切换保护 / 退出）、tooltip 每秒刷新
- 单实例：命名互斥体，重复启动打开已有实例的面板
- 开机自启：计划任务（`schtasks`），服务模式 `--service` 不建托盘、不开浏览器
- 控制台：Ctrl+C 只置标志位，由主循环走完整收尾；UTF-8 代码页

### Tests

- `wide.rs` 6、`tray.rs` 5、`single_instance.rs` 4、`timezone.rs` 3、`autostart.rs` 2、`browser.rs` 2、`console.rs` 2、`winerr.rs` 2、`admin.rs` 1

---

## Phase 12 — 危险端口 / Ping 保护

### Completed

- 危险端口（135/137/138/139/445）TCP/UDP 入站阻断规则
- ICMP Echo Request 屏蔽（IPv4 + IPv6 各一条）

---

## Phase 13 — Legacy Migration

### Closed（已终止）

- **永久放弃旧版数据迁移**（用户决策）：`config.dat`、`BanData.bin`、`PortGuard.txt` 三者不再读取、不解析、不留兼容分支。仓库内既无格式样本，盲写解析器只会产生静默丢规则的假迁移。详见 `docs/legacy-mapping.md`
- 从旧版升级的用户需在新版面板中重新填写白名单 / 黑名单 / 端口阈值

### Completed（同批完成的 IP 地理位置）

- 新增 `portguard-geo` crate：`ip2region` xdb v3 格式解析 + 查询（向量索引 + 段索引二分）
- 配置新增 `[geo] enabled` / `[geo] db`（默认开启、默认 `ip2region_v4.xdb`），保存后立即重载
- 面板「当前连接」「封停列表」新增「地理位置」列，设置页新增「地理位置」卡片并显示库状态
- 严格遵循规范 22：只用于展示，判定路径零接触；查询失败一律「未知」

### Tests

- `db.rs` 8、`lib.rs` 5、`record.rs` 5（含真实 10.2 MiB 库的查询用例，库缺失时跳过）

---

## Phase 14 — 完整集成测试

### Completed

- `portguard-app` 覆盖：白名单拒绝封停、加白落盘、非法规则、幂等、统计一致、非法配置不覆盖文件、非法网卡、单实例只发放一次封停动作、抓包出错写事件
- **真机验证**（管理员权限）：
  - `POST /api/ban {"ip":"203.0.113.66","permanent":true}` → `netsh advfirewall firewall show rule name="PortGuard-Ban-203.0.113.66"` 显示「远端 IP: 203.0.113.66/32」「操作: 禁止」
  - `state/bans.json` 落盘 → `POST /api/unban` → 规则消失
  - 退出后系统中无 `PortGuard` 规则残留
  - 自动选网卡选到 `192.168.1.8`（跳过 APIPA 地址）
  - 配置模板端口正确（`[3389]` / `[3389]` / `[80, 443]`，`config_version = 1`）

---

## Phase 15 — Win7 / Server 2012 专项测试

### Next

- **未验证**：缺 Windows 7 SP1 / Server 2008 R2 / Server 2012 目标机
- 应验证：程序启动、抓包权限、netsh 规则创建与查询、托盘图标、计划任务、面板在现代浏览器中的显示

---

## Phase 16 — Release

### Completed

- `cargo build --release` 产物 `PortGuard.exe` 约 **1.0 MB**（1048064 字节），单文件、无外部资源（地理位置库是外部文件，未内嵌）
- release 版真机复验：
  - 面板可访问（首页 14169 字节，前端资源确认已内嵌）
  - 抓包就绪，3 秒捕获 1047 个包
  - 封停 `203.0.113.99` → `netsh` 规则远端 IP `203.0.113.99/32`、操作禁止 → `state/bans.json` 落盘
  - 解封 → 面板列表清空、防火墙规则删除
  - 端口被占用时面板自动顺延（实测占住 18080 后顺延到 18081）
  - 退出后系统中无 `PortGuard` 规则残留、无进程残留
- 局部配置健壮性：只写 `[panel]` 一段的 `config.toml`，其余字段走 `serde(default)`，
  保护端口仍为 4 个（未静默丢失）
- 地理位置（首次 release 复验）：`/api/status` 返回 `geo_ready=true` 且状态为实际库路径；
  手动封停 `203.0.113.9` → 封停列表显示「保留地址」且防火墙规则远端 IP 为 `203.0.113.9/32`；
  解封后规则删除、系统中 `PortGuard` 规则数为 0
- 地理位置开关即时生效：`POST /api/config` 关闭 → `geo_ready=false`，重新开启 → `geo_ready=true`，
  无需重启（日志分别为「地理位置不可用：地理位置展示已在配置中关闭」与「地理位置库已加载：<路径>」）

### Next

- 添加 exe 版本信息与图标资源（托盘图标已内嵌，但 exe 文件属性尚无版本信息）
- 确认目标机是否需要额外分发 VC++ 运行库
- 在 Windows 7 SP1 目标机上实测（见 Phase 15）

---

## Phase 17 — 端口无记录问题的可观测性修复

### Completed

- **忽略原因计数**：`IgnoreCounters`（非本机流量 / 本机外连 / 非新建连接 / 端口未保护 / ICMP）
  随 `status.stats.ignored` 下发，面板概览新增「判定明细」卡片；抓包数在涨而连接列表为空时，
  可直接看出被丢在哪一条判定上
- **封停后保留跟踪行**：不再在 `apply_ban` 中删除跟踪记录，面板显示 `BANNED` / `PERMANENT`，
  便于确认封停前该 IP 打的是哪个端口、累计多少次
- **白名单展示记录**：白名单 IP 访问受保护端口时写入跟踪表（仅展示 `WHITELIST` 状态，
  永不累加阈值、永不封停），修复「面板有 WHITELIST 状态却永远不可达」的自相矛盾
- **保护端口全空拒绝保存**：`Config::validate` 新增校验，三组全空时保存返回 400；
  历史遗留的空配置在启动时写入 `warn` 事件与日志，不再静默失效
- **面板可见性**：「受保护端口」卡片副标直接列出三组端口（`TCP 3389 · WEB 80,443 · UDP 3389`）

### Tests

- 新增 8 项：忽略计数分类、白名单展示记录（含非保护端口不留记录）、跟踪行封停后保留、
  保护端口全空告警、配置校验拒绝全空、e2e 判定明细下发与全空拒绝
- 合计 251 项全部通过

---

## Phase 18 — 抓包观测与连接事件来源自动回退

**背景**：新构建部署后，TCP 3389（该软件的主要用途）在客户端真实连接的情况下仍无任何连接记录。
判定层已确认无缺陷（配置正确、端口受保护），因此问题只可能在「包根本没到判定层」。
由于此前无法区分「没抓到」「抓到但解析器丢了」「抓到但被判定层丢掉」，本次先补齐可观测性，再给出可回退的事件来源。

### Completed

- **抓包观测表**（新增 `portguard-core/src/observe.rs`）：判定之前记录每个包，按「方向 + 协议 +
  本机端口 + TCP 标志类别」计数，面板概览新增「抓包观测」表格（Top 12）。
  条目上限 256，超出只累加溢出计数；换网卡与重新开始抓包时清空。观测**绝不参与判定**
- **解析诊断**：抓包层解析失败（非 IPv4 / 分片 / 畸形包）单独计数并保留最多 3 条十六进制样本，
  与观测表一起展示，用于区分「没抓到」与「解析器丢了」
- **连接事件来源**：`ProtectConfig.count_accept`（默认 `false`，规范 4.1 口径不变）。
  打开后 TCP 事件改由本机发出的 `SYN+ACK` 产生（旧版易语言程序正是这种口径），
  设置页新增对应开关
- **自动回退**：运行期每 5 秒检查，当「受保护 TCP 端口无入站 SYN」且「同端口有出站 SYN+ACK」
  同时成立时自动切换到握手响应口径，并写入 `warn` 事件与日志说明原因。
  只判定一次：用户显式改过该配置项即视为已决定，永不覆盖；只有自动判定出来的结果在换网卡时重新评估

### Tests

- 新增 13 项：观测表 5 项（入/出站归类、同键累计、条目上限、按条件统计端口、非本机流量归端口 0）、
  引擎 `count_accept` 口径 4 项、运行时 4 项（被判定层丢弃的包仍入观测表、入站不可见时自动切换并真正开始跟踪、
  入站可见时不切换、用户显式设置后不再自动改写）
- 合计 **264 项全部通过**

---

## 当前已知限制

| 项 | 说明 |
| --- | --- |
| 面板无认证 | 仅靠回环绑定与请求头校验，绑到非回环地址时需用户自行承担风险 |
| 旧版迁移 | 已永久放弃（非「缺失」），见 Phase 13 与 `docs/legacy-mapping.md` |
| IP 地理位置 | 已实现（`portguard-geo`）；需 `ip2region_v4.xdb` 随程序分发，库缺失时仅显示「未知」，不影响判定 |
| Win7 实测 | 未在目标系统上运行过 |
| 网卡与 NAT | 只统计「目的地址等于所选网卡地址」的入站包。云主机做 DNAT 时入站包的目的地址已是内网地址（用 `netstat` 的 Local Address 列可确认），必须选中该内网网卡；若把公网地址填成监听地址，所有入站包都会被判为「非本机流量」 |
| 混杂模式不可见入站包 | 部分云主机 / 网卡的 `SIO_RCVALL` 只放行本机发出的包，入站方向一条都收不到。此时必须依赖 `protect.count_accept`（运行期会自动启用并说明）。已观察到真实案例：同机的 3389 长期无记录（见 Phase 18） |
| IPv6 流量不参与统计 | 解析器只处理 IPv4，RDP 的 `[::]:3389` 监听产生的 IPv6 连接不会进入统计，只体现在解析失败计数中 |
| RDP 保护 | 依赖 Windows 会话枚举，未能覆盖所有远程桌面变体（如 RDP 网关中转） |
