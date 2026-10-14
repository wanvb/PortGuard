# PortGuard — 项目最高约束

## 项目形态

- 目标：Windows 上的恶意连接识别与自动封停工具（Rust 重写自易语言版本）
- 交付形态：**单个 `PortGuard.exe`** —— 控制台 + 系统托盘 + 内嵌 Web 控制面板
- 目标系统：Windows 7 SP1 x64 / Server 2008 R2 / Server 2012 / Windows 10 / Windows 11
- 工具链：Rust **1.77.2**（最后一个官方支持 Win7 的版本）；依赖精确锁定，`Cargo.lock` 必须入库
- 前端资源经 `include_str!` 内嵌，运行时不读磁盘

## 语言策略（强制）

1. 所有输出必须使用中文（简体中文）
2. 所有新开发代码注释必须使用中文
3. 即使输入是英文，也必须用中文回答
4. 禁止默认使用英文解释
5. 仅在以下情况允许英文：
   - 代码本身
   - 专有名词（如 API / library 名称）
6. 如果违反以上规则，需要立即改为中文

## 文档处理规则
- 对 Markdown 文件进行总结时，必须用中文输出
- 保留技术术语英文，但解释用中文
- 在模块功能改动升级时需及时更新对应模块CLAUDE.md文件
- 新增加的功能模块分支请建立全新源码模块文件，尽量避免把不同模块源码都堆在同一个源码文件内
- 新增加的功能模块代码应使用尽量简洁的实现方案避免冗余代码出现
- 每一个功能版本更新后请自动操作git进行版本提交

## 模块划分

| crate | 职责 | 模块文档 |
| --- | --- | --- |
| `portguard-core` | 领域模型、配置、IP 规则、滑动窗口跟踪、封停状态机、规则引擎、`PortGuardApi` 契约 | `crates/portguard-core/CLAUDE.md` |
| `portguard-packet` | 网卡枚举（`GetAdaptersAddresses`）、raw socket 抓包（`SIO_RCVALL`）、IPv4/TCP/UDP 解析 | `crates/portguard-packet/CLAUDE.md` |
| `portguard-firewall` | 全部 Windows 防火墙操作（`netsh advfirewall`），对外只暴露 `FirewallBackend` | `crates/portguard-firewall/CLAUDE.md` |
| `portguard-storage` | `config.toml` / `bans.json` 读写、日志落盘、路径解析 | `crates/portguard-storage/CLAUDE.md` |
| `portguard-rdp` | RDP 客户端计算机名保护（会话枚举、策略判定） | `crates/portguard-rdp/CLAUDE.md` |
| `portguard-win` | Win32 系统集成：权限、单实例、托盘、时区、浏览器、自启动、控制台 | `crates/portguard-win/CLAUDE.md` |
| `portguard-web` | 内嵌 Web 面板：资源内嵌、纯函数路由、HTTP 服务与安全校验 | `crates/portguard-web/CLAUDE.md` |
| `portguard-app` | 主程序：启动编排、运行时回路、`PortGuardApi` 实现 | `crates/portguard-app/CLAUDE.md` |

## 硬性约束

- 禁止在 UI 与业务逻辑中调用 `Command::new("netsh")`，所有防火墙操作必须经 `portguard-firewall`
- 绝不允许按 `remoteip=xxx` 删除规则——只能按精确规则名删除，且仅限 `PortGuard-` 前缀
- 白名单永远优先于黑名单和自动封停，任何路径（含手动封停与重启恢复）都不得封停白名单 IP
- 禁止在以下场景使用 `unwrap()` / `expect()`：网络线程、防火墙、Win32 API、文件 I/O、配置加载、RDP 回调（测试代码豁免）
- 禁止命令注入：netsh 参数必须严格构造并经过解析后传入，不经 shell
- 防火墙操作失败时不得假装成功——必须上报错误、记录日志并显示差异
- 抓包线程只做「锁内判定 + 入队」，不得执行 netsh 调用或磁盘写入
- 面板无口令，安全完全依赖「仅监听回环 + Host 校验 + Origin 校验」，不得为调试关闭
- Git 提交信息需有意义（feat/fix/test 前缀；禁止 "update"/"test"/"fix"/"aaa"/"final"）

## 文档索引

- `docs/开发文档.md` —— 项目总控规范（架构、判定逻辑、线程模型、阶段路线图）
- `docs/behavior-spec.md` —— 行为规格：判定流水线、封停状态机、不变式清单
- `docs/web-ui-spec.md` —— 控制面板规格：页面结构、接口契约、安全边界
- `docs/progress.md` —— 各阶段完成度与测试数
- `docs/legacy-mapping.md` —— 旧版迁移映射与受阻说明

## 回复规范 (Style)
- **零废话**：严禁任何寒暄（如"好的"）、前言铺垫和末尾总结。
- **直奔结论**：无解释直接给出答案，多用列表（-），拒绝冗长叙述。
- **仅保留三要素**：必要时仅输出"结论"、"因果（技术原因）"和"关键风险/后续"，字数能少则少。
