# PortGuard 开发进度

> 最后更新：2026-10-15
> 测试规模：**295 项全部通过**（`cargo test --workspace`），`cargo clippy --workspace --all-targets` 零警告。

---

## 总体状态

| 模块 | 测试数 | 状态 |
| --- | --- | --- |
| `portguard-core` | 105 | 完成 |
| `portguard-packet` | 18 | 完成 |
| `portguard-firewall` | 10 | 完成 |
| `portguard-storage` | 20 | 完成 |
| `portguard-rdp` | 19 | 完成 |
| `portguard-win` | 32 | 完成 |
| `portguard-geo` | 18 | 完成 |
| `portguard-web` | 39 | 完成 |
| `portguard-app` | 34 | 完成 |
| **合计** | **295** | — |

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
- 累计计数跟踪（不做滑动窗口，空闲超保留期后归零），TCP 仅 `SYN && !ACK` 计为新连接，UDP 每包计数
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
- 开机自启：注册 Windows 系统服务（SCM 拉起），服务模式 `--service` 不建托盘、不开浏览器
- 控制台：Ctrl+C 只置标志位，由主循环走完整收尾；UTF-8 代码页

### Tests

- `wide.rs` 6、`tray.rs` 5、`single_instance.rs` 4、`timezone.rs` 3、`browser.rs` 2、`console.rs` 2、`winerr.rs` 2、`admin.rs` 1
  （原 `autostart.rs` 的计划任务逻辑在 Phase 20 被 `service.rs` 取代）

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
- 应验证：程序启动、抓包权限、netsh 规则创建与查询、托盘图标、系统服务注册与开机拉起、面板在现代浏览器中的显示

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
- **连接事件来源**：`ProtectConfig.count_accept`（当时默认 `false`，Phase 20 已改为默认 `true`）。
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

## Phase 19 — 隐藏控制台窗口与面板默认端口调整

**背景**：程序以「控制台 + 托盘」形态启动，任务栏长期挂着一个黑窗口，与托盘图标重复；
另外面板默认端口 18080 是各类本地调试工具的常用端口，冲突概率高。

### Completed

- **控制台窗口默认隐藏**（`portguard-win/console.rs`）：`hide_own_console_window()` 在
  `GetConsoleWindow` 有窗口且 `GetConsoleProcessList` 挂载进程数为 1（即**独占**控制台，双击启动的情形）
  时 `ShowWindow(SW_HIDE)`。从 cmd / PowerShell 启动或查询失败一律不动手 —— 否则会把用户自己的
  终端窗口一起藏掉。隐藏后托盘图标与右键菜单（打开面板 / 暂停保护 / 退出）完全不减，
  `Ctrl+C` / 注销 / 关机事件仍由 `SetConsoleCtrlHandler` 收到并走完整收尾
- **`--console` 开关**：显式保留窗口，便于排查启动期问题；`--help` 与启动横幅同步说明
- **隐藏后的错误呈现**（规范 26.1）：启动期致命错误（数据目录 / 配置 / 日志）改弹 `MessageBoxW`
  对话框，不允许「双击没反应」；启动期告警（非管理员、自动开始保护失败）在建好托盘后改用气泡重复一次
- **面板默认端口 58080**：`DEFAULT_PANEL_BIND` 成为唯一来源（`portguard-web::DEFAULT_BIND` 直接引用），
  配置模板、面板占位符、帮助文本、打包脚本与文档一并更新
- **旧配置迁移**：`Config::migrate()` 把仍等于旧默认值的 `127.0.0.1:18080` 迁移为 58080（结构版本 1 → 2），
  与 `normalize` 分开实现；主程序启动时**立即写回 `config.toml`**（否则第二个实例会拿文件里的旧端口
  去开面板，而运行中的实例已换到新端口）

### Tests

- 新增 4 项：`只在独占控制台时才隐藏窗口`（`should_hide` 纯函数，避免测试真去隐藏跑测试的终端）、
  `默认隐藏控制台窗口`、`旧默认面板端口被迁移到新端口`（含幂等与「自定义地址不动」）、
  `默认配置符合文档建议值` 增补端口断言
- 合计 **267 项全部通过**（含端到端实测：旧 `bind = "127.0.0.1:18080"` 的配置启动后自动改写为
  `config_version = 2` + `bind = "127.0.0.1:58080"`，面板在 58080 正常响应；`MainWindowHandle = 0`
  且 `ConsoleWindowClass` 窗口 `IsWindowVisible = False`，加 `--console` 时同窗口转为可见）

### Known Issues

- 迁移触发的写盘会按模板重写 `config.toml`，**用户手写的注释行会丢失**（仅发生一次，模板头部已说明格式）
- 58080 落在 Windows 默认动态端口区间（49152–65535）内，理论上可能被临时分配的出站端口占用；
  真发生时会走既有的端口顺延（最多向后试 10 个端口）并在日志中说明

---

## Phase 20 — 开机自启改用 Windows 系统服务 + 连接事件来源默认开启

**背景**：两处调整。① 开机自启此前注册的是计划任务（`schtasks /SC ONSTART`），
计划任务与程序本身没有隶属关系、也不在服务管理器里，运维无法用 `sc query` / `services.msc`
统一查看；② `protect.count_accept` 默认关闭，导致混杂模式收不到入站包的云主机开箱即用性差。

### Completed

- **`portguard-win::service`（新模块，取代 `autostart.rs`）**：
  - `Service::install(exe)`：`CreateServiceW(SERVICE_AUTO_START, SERVICE_WIN32_OWN_PROCESS, LocalSystem)`
    注册名为 `PortGuard` 的服务，命令行 `"<exe>" --service`；已存在则改走 `ChangeServiceConfigW`
    更新路径（程序挪目录后重新勾选仍有效），并写入中文服务描述；顺带删除旧版留下的同名计划任务，
    避免旧任务与新服务同时拉起两个实例
  - `Service::uninstall()`：`DeleteService` 前先判 `dwProcessId` —— 服务进程就是当前面板进程时
    **不停自己**（停掉会让这次 HTTP 响应发不出去），直接删服务项，进程退出后服务自动消失
  - `Service::run(body)`：`StartServiceCtrlDispatcherW` + `RegisterServiceCtrlHandlerExW`，
    上报 `SERVICE_START_PENDING` → `SERVICE_RUNNING` → `SERVICE_STOPPED`；
    `sc stop` / 关机事件转成 `console::request_exit()`，走与 Ctrl+C 完全一致的收尾流程
  - 手工执行 `PortGuard.exe --service`（非 SCM 拉起）回退为原地直接运行，保留既有含义
  - `ScHandle` 以 `Drop` 关闭 `SC_HANDLE`（`SC_HANDLE` 是 `Copy` 且无 Drop，不显式关闭会泄漏）
- **启动即分发**：`main.rs` 拆出 `run_app(opts)`，`--service` 在读配置、抢单实例**之前**
  就进入 SCM 分发 —— 否则「已有实例在运行」这条早退路径会让 SCM 等到 1053
  「服务没有及时响应启动或控制请求」；单实例早退在服务模式下不再尝试开浏览器（会话 0 无桌面）
- **`protect.count_accept` 默认改为 `true`**（面板「统计服务端应答」默认勾选），
  旧的 `config.toml` 不做迁移，仅改代码默认值
- **修掉一处与规格不符的实现**：`behavior-spec.md` 2.5 与 `portguard-core/CLAUDE.md` 都写明
  两种事件来源互斥，但 `engine.rs` 实为**叠加**（入站 `SYN` 永远计数，`count_accept` 只额外放行
  出站 `SYN+ACK`）。默认值一旦翻成 `true`，入站可见的常规主机每次连接会被计两次、阈值事实上折半。
  现抽出 `Engine::is_connection_event()` 强制互斥：`true` 只认本机发出的 `SYN+ACK`，
  `false` 只认入站 `SYN && !ACK`，白名单「仅展示记录」判定复用同一判据

### Tests

- 新增 4 项：`portguard-core` 的 `默认开启统计服务端应答`、`两种事件来源互斥不会重复计数`，
  `portguard-win` 的服务名 / 显示名与描述可读性、错误码提取
- 合计 **271 项全部通过**

### Known Issues

- 勾选后**只注册、不立即启动**，下次开机由 SCM 拉起；面板上的开关状态只代表「服务项是否已注册」
- 服务以 LocalSystem 在会话 0 运行，因此**没有托盘图标**，控制面板仍可正常访问
- 从旧版计划任务升级的用户：注册服务时会自动删除同名计划任务，无需手工清理

---

## Phase 21 — TCP-WEB 默认阈值放宽到 300

**背景**：TCP-WEB 组默认累计连接阈值为 10，而一次正常网页访问会连带 CSS、JS、图片、
接口等数十个连接，阈值 10 会在页面还没加载完时就把访客（或监控探针）封掉。

### Completed

- `DEFAULT_WEB_MAX_ATTEMPTS = 300` 成为 TCP-WEB 默认阈值的**唯一来源**
  （`ProtectConfig::default` 直接引用），普通 TCP / UDP 仍为 `5`——两者风险模型不同，
  不得一起放宽
- 结构版本 2 → 3；`Config::migrate()` 新增一条：仍等于旧默认值 `10` 的 `protect.http.max_attempts`
  放宽到 300，并如实上报中文说明（用户自定义过的阈值一律不动，想收紧回 10 在面板里改即可）
- 迁移判定按**值**而非结构版本（`normalize` 早于 `migrate` 执行并已把 `config_version` 抬到当前版本，
  按版本判定永远命中不了）——与既有的面板端口迁移同一做法，注释中已写明
- 面板 `PROTECT_GROUPS` 兜底默认值改为按分组给出（`http` 为 300），避免配置缺该分组时
  前端显示回落到 5
- 文档同步：`docs/开发文档.md` 4.2 与配置模板、`docs/behavior-spec.md` 8.2、
  `crates/portguard-core/CLAUDE.md`

### Tests

- 新增 1 项：`旧默认的_web_阈值被放宽`（迁移幂等、自定义阈值不动、TCP / UDP 组不受影响）；
  `默认配置符合文档建议值` 增补三组阈值断言
- 合计 **272 项全部通过**

### Known Issues

- 老配置想收紧回 10 的用户：迁移会把 10 当作「旧默认值」处理，需在面板里重新填入 10

---

## Phase 22 — 面板导航由侧边栏改为顶部横排

**背景**：面板此前是「左侧 252px 侧边栏 + 右侧内容」布局，在笔记本上浏览时横向空间被吃掉
四分之一，连接表 / 封停表列多，必须拖动横向滚动条才能看全，读表体验差。

### Completed

- **导航横排到顶部**（`assets/index.html`）：原 `.sidebar`（品牌 + 导航 + 版本页脚）整体移除，
  五个页面入口与「开始保护 / 停止保护 / 立即刷新」并排进 `.topbar` 第一行；
  状态 chips（状态 / 网卡 / 本机 IP / 权限 / 运行时长）与版本号、「仅监听本机回环地址」
  合并到第二行右侧。`.app` 由双列 grid 退化为纵向 flex，`main` 不再被侧边栏挤压
- **样式重做**（`assets/style.css`）：`.topbar` 改为两行纵向容器（`.topbar-main` / `.topbar-status`），
  导航项从竖排整宽按钮改为横排页签（`inline-flex` + 选中态底部 2px 强调色），
  操作按钮 `margin-left: auto` 始终靠右；页面内边距 20px → 16px 18px，
  表格滚动高扣除量随表头增高调整（`calc(100vh - 320px)`，日志 330px）
- **窄屏适配**（≤900px）：品牌与操作按钮留在第一行，导航 `flex-basis: 100%` 换到第二行并横向滚动，
  不再挤压按钮；该断点下表格与日志取消高度限制，交给整页滚动
- **不加宽表格**：列数与 `ConnectionView` / `BanView` 字段一一对应，本次只腾空间、不改口径
- 文档同步：`docs/web-ui-spec.md` 2. 页面结构（含改版原因）、`docs/开发文档.md` 46、
  `crates/portguard-web/CLAUDE.md`

### Tests

- 新增 1 项：`导航位于顶部横排且无侧边栏`（`index.html` 与 `style.css` 都不允许再出现 sidebar，
  且五个 `data-page` 入口齐全）；`首页包含关键挂载点` 补入 `foot-version`
- 合计 **273 项全部通过**（`portguard-web` 33 → 34）

### Known Issues

- 顶部两行表头占位比原单行状态条高约 30px，纵向可视区略减；换来的是整页宽度，
  笔记本（1366×768）下净收益明显，宽屏下收益更大

---

## Phase 23 — 数据表页高度自适应（去掉固定高度常量）

**背景**：当前连接页在 1366×768 下只能显示约 4 行数据，右侧就出现滚动条，页面底部还剩大片空白。
原因是表体高度用 `calc(100vh - 320px)` 估的——320px 这个常量按上一版表头高度写死，
顶栏实际更高时（导航换行、浏览器缩放、矮窗口）扣除量就不够，高度被严重低估。

### Completed

- **布局改为定高 + flex 透传**（`assets/style.css`）：`.app` 由 `min-height: 100vh` 改为
  `height: 100vh; overflow: hidden`，滚动职责下移给 `main`（`flex: 1 1 auto; min-height: 0;
  overflow-y: auto`），顶栏因此恒定在顶部
- **`fill` 页撑满**：`当前连接 / 封停列表 / 运行日志` 三页的 `section` 加 `fill` 类，
  `.page.active.fill` → `.page.fill > .card` → `.page.fill .table-wrap` / `.page.fill .logs`
  逐级 `min-height: 0` 传递高度约束，数据区正好填满顶栏以下的全部空间，滚动条落在数据区内部
- **删除两个魔法常量**：`.table-wrap` 的 `calc(100vh - 320px)` 与 `.logs` 的 `calc(100vh - 330px)`
  全部移除；概览页的观测表（最多 12 行）按内容排布，超出由 `main` 整页滚动
- **窄屏断点简化**：≤900px 不再取消高度限制（那会让表格无限变高、滚动条跑回页面级），
  仍按同一套 flex 规则撑满
- 实测（无头 Chrome，伪造 26 行数据）：1280×720 / 800×600 / 1366×480 三种窗口下，
  `main` 与 `.page.fill` 高度完全相等（无页面级滚动条），滚动条只出现在数据区；
  设置页（内容 1637px）仍由 `main` 正常滚动
- 文档同步：`docs/web-ui-spec.md` 2. 页面结构（新增「高度分配」）、`crates/portguard-web/CLAUDE.md`

### Tests

- 新增 1 项：`数据表页撑满视口高度`（三页必须带 `fill` 类、样式表必须有 `.page.active.fill` /
  `.page.fill > .card` / `.page.fill .table-wrap`，且全文不得再出现 `100vh - 320px`）
- 合计 **274 项全部通过**（`portguard-web` 34 → 35）

### Known Issues

- 极矮窗口（可视高度 < 400px）下表体随之变矮，属预期行为；如需保底高度可再加 `min-height` 下限

---

## Phase 24 — 端口与白/黑名单备注（标识说明）

**背景**：服务器上经 frp 穿透的端口较多，三组保护端口与白/黑名单规则只有一个裸值，
看不出某个端口属于哪个业务、某条规则是谁在用，排查连接与封停记录时要来回翻文档。

### Completed

- **存储形态：平行映射，不动判定输入**（`portguard-core/src/config.rs`）：
  `ProtectionRule.notes` 与 `ListsConfig.notes`（`BTreeMap<String,String>`）与 `ports` /
  `whitelist` / `blacklist` 并列存放，端口仍是 `Vec<u16>`、规则仍是 `Vec<String>`，
  判定链路（`engine.rs` / `ban.rs` / `iprange.rs`）零改动，旧 `config.toml` 零迁移
- **键必须是字符串**：TOML 的 map 键不支持整数（`toml_edit` 对整数键返回 `KeyNotString`），
  因此端口用十进制字符串、名单用规则原文；含 `.` `*` `/` 的键由写入器自动加引号，手改配置时需保留引号
- **新模块 `portguard-core/src/notes.rs`**：`clean`（去控制字符与首尾空白、按字符截断 64，
  不按字节切以免切碎中文）、`normalize`（清洗 → 丢空值 → **清除孤儿备注**）、`get`
- **孤儿清理只在 `Config::normalize` 一处**：端口 / 规则被删掉后其备注在下次保存时一并消失，
  面板增删名单（`/api/lists/remove`）、整体保存、手改配置三条路径都经 `ConfigStore::save` → `normalize`，
  各入口无需各写一份清理
- **视图与填充**：`ConnectionView` / `BanView` 新增 `port_note` / `ip_note`，
  由 `Controller::connections()` / `bans()` 在锁外查配置填充（与 `location` 同模式）；
  封停记录没有分组标签，端口备注按 TCP → WEB → UDP 取第一个命中
- **面板**：设置页三组端口与白/黑名单下方各有一张备注网格，随端口 / 规则输入实时重建，
  未保存内容靠客户端缓存保住；概览「受保护端口」脚注拼成 `3389(远程桌面)`；
  连接表与封停表内联灰字显示备注，一律 `textContent` 写入
- 配置模板 `TEMPLATE_HEADER` 说明 `notes` 段用途与引号规则
- 文档同步：`docs/web-ui-spec.md` 2.1 / 2.2 / 2.3 / 2.4、`docs/behavior-spec.md` 8.2 / 8.5 / 10、
  四个 crate 的 `CLAUDE.md`

### Tests

- 新增 14 项：`notes` 模块 5 项（清洗、截断不切碎中文、孤儿清除、空备注不留在表里、空串视为无备注）、
  `config` 5 项（含备注往返、端口删除后不残留、名单删除后不残留、旧配置缺字段仍可解析、按分组与按端口取备注）、
  `storage` 1 项（保存后重新加载内容一致）、`web` 2 项（设置页挂载点契约、备注随配置往返并可展示）、
  `app` 1 项（备注随端口与名单落盘并在删除后清除）
- 合计 **288 项全部通过**（`portguard-core` 92 → 102、`portguard-storage` 19 → 20、
  `portguard-web` 35 → 37、`portguard-app` 33 → 34）

### Known Issues

- 备注上限 64 字符（前端 `maxlength` 与后端 `clean` 双保险），超长内容静默截断
- 同一规则同时出现在白名单与黑名单时共用一条备注（`lists.notes` 的键是规则原文，不区分名单）
- 手改 `config.toml` 时若给 `[lists.notes]` 下含点的键漏写引号，会被解析成分层表导致整份配置
  解析失败（走既有的 `config.toml.broken-*` 备份 + 回退默认），面板保存的写法始终带引号

---

## Phase 25 — 面板中英双语（界面语言可跟随系统）

**背景**：面板只有中文一种界面，非中文系统上的使用者看不懂设置项与表头；
需要一个语言设置项，默认跟随服务器系统语言，也可固定成中文或英文。

### Completed

- **配置项 `panel.language`**（`portguard-core/src/config.rs`）：取值 `auto`（默认）/ `zh` / `en`；
  `PanelConfig::effective_language(system_default)` 负责解析，`LANGUAGE_AUTO/ZH/EN/LANGUAGES`
  是唯一取值来源，`Config::normalize` 用 `normalize_language` 清洗非法值（不在表内一律回落 `auto`）；
  旧配置缺该字段由 `#[serde(default)]` 补成 `auto`，不需要迁移分支
- **新模块 `portguard-win/src/locale.rs`**：`GetUserDefaultUILanguage` → 取不到再
  `GetSystemDefaultUILanguage` → 仍取不到按中文；`language_of(langid)` 只看主语言
  （`0x04` 中文，其余英文，故 0x0804 / 0x0404 都算中文），结论 `OnceLock` 缓存；
  Cargo 仅新增 `Win32_Globalization` feature
- **启动时探测一次、请求时解析**：`PanelMeta.system_language` 由主程序启动时填入，
  `/api/meta` 每次按**当前**配置解析并下发 `language` —— 改语言保存后即刻生效，无需重启
- **前端文案表 `assets/i18n.js`**（232 条，`键 → {zh, en}`）：`index.html` 静态文案带
  `data-i18n` / `data-i18n-ph` / `data-i18n-title`，动态内容一律经 `t(key, params)`
  （占位符用 split/join 替换，不用正则）；设置页新增「界面语言」下拉框 `#cfg-language`，
  未保存的选择即时预览（`state.langPreview`），保存成功或放弃修改时作废
- **切语言只改文案不重建表单**：新增 `retranslateSettings()` 原地刷新设置页里由脚本生成的文案
  （分组名、阈值说明、备注网格、系统开关、网卡下拉框），避免 `renderSettings()` 把用户
  还没保存的端口 / 名单 / 备注输入冲掉
- **范围明确**：英文只覆盖面板界面文案；后端产生的事件流消息、运行日志、`parse_samples`
  与错误说明保持中文（概览「最近事件」卡片有说明文字）
- 文档同步：四个 crate 的 `CLAUDE.md`、`docs/web-ui-spec.md` 2.4 与 3.1

### Tests

- 新增 7 项：`config` 3 项（默认跟随系统且非法值被清洗、旧配置缺字段跟随系统、随配置往返）、
  `locale` 2 项（LANGID 按主语言归类、探测结论自洽）、`web` 2 项
  （`界面语言资源内嵌且文案成对`：静态扫首页标记与脚本里所有 `t("…")` 字面量必须中英成对；
  `界面语言随设置切换且无需重启`：端到端断言 `auto` / 显式值 / 非法值的实际下发结果）
- 合计 **295 项全部通过**（`portguard-core` 102 → 105、`portguard-win` 30 → 32、
  `portguard-web` 37 → 39）

### Known Issues

- 英文界面不翻译后端文本：事件流消息、运行日志、解析样本仍是中文，同一屏上会中英混排
- 只区分中 / 英两类（其余语言一律按英文界面），且探测的是**服务器**系统语言，
  经浏览器从别的语言的机器访问时不会跟随浏览器语言

---

## 当前已知限制

| 项 | 说明 |
| --- | --- |
| 面板无认证 | 仅靠回环绑定与请求头校验，绑到非回环地址时需用户自行承担风险 |
| 旧版迁移 | 已永久放弃（非「缺失」），见 Phase 13 与 `docs/legacy-mapping.md` |
| IP 地理位置 | 已实现（`portguard-geo`）；需 `ip2region_v4.xdb` 随程序分发，库缺失时仅显示「未知」，不影响判定 |
| Win7 实测 | 未在目标系统上运行过 |
| 网卡与 NAT | 只统计「目的地址等于所选网卡地址」的入站包。云主机做 DNAT 时入站包的目的地址已是内网地址（用 `netstat` 的 Local Address 列可确认），必须选中该内网网卡；若把公网地址填成监听地址，所有入站包都会被判为「非本机流量」 |
| 混杂模式不可见入站包 | 部分云主机 / 网卡的 `SIO_RCVALL` 只放行本机发出的包，入站方向一条都收不到。此时依赖 `protect.count_accept`（**默认已开启**，旧配置为 `false` 时运行期仍会自动启用并说明）。已观察到真实案例：同机的 3389 长期无记录（见 Phase 18） |
| IPv6 流量不参与统计 | 解析器只处理 IPv4，RDP 的 `[::]:3389` 监听产生的 IPv6 连接不会进入统计，只体现在解析失败计数中 |
| RDP 保护 | 依赖 Windows 会话枚举，未能覆盖所有远程桌面变体（如 RDP 网关中转） |
