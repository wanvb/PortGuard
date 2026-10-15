# PortGuard

**Windows 上的恶意连接识别与自动封停工具。** 单个 `PortGuard.exe`：控制台 + 系统托盘 + 内嵌 Web 控制面板。

它盯住你指定的几个端口（默认 RDP `3389`），把「同一个来源 IP 反复来连」的机器自动写进 Windows 防火墙规则，
在有效期内把这个 IP 关在门外。不装驱动、不做流量劫持，靠 raw socket 看本机网卡上的包。

---

## 它解决什么问题

### 1. 公网 3389 被穷举弱口令

RDP 一旦暴露在公网，每天都会被扫描器光顾：日志里成片的登录失败、来源 IP 各不相同，
但真正的问题是**同一个 IP 在几分钟内反复尝试连接**——这就是穷举爆破的典型形态。
弱口令一旦被猜中，接下来往往是勒索或挖矿。

PortGuard 的判据正是「反复尝试连接」：同一个「来源 IP + 服务端口」累计连接次数达到阈值
（默认 5 次）即封停，攻击者立刻被防火墙规则挡住，不需要你盯着日志。

### 2. frp 穿透出去的内网端口（22 / 3389 / 3306 / 80 / 443 …）

frp 把内网服务暴露到公网后，服务端看到的来源 IP 往往是 frps 的地址，
传统「按来源 IP 封停」的方案会直接封掉自己的隧道。
PortGuard 抓的是**网卡上的原始包**，看到的是真实来源 IP，因此能按真实攻击者封停。

更重要的是：**正常用户不会被误封**。
一次连上的长连接（SSH 会话、数据库连接池、远程桌面会话）不会产生新的连接请求，
也就不会累加计数；只有爆破工具才会在短时间内反复新建连接——反复尝试本身就说明有问题。

### 3. 谁在被封、封了多久，看得见

面板上「当前连接」列出每个来源 IP 的累计次数 / 阈值进度、「封停列表」记录封停原因、端口、到期时间，
并可选显示 IP 归属地（仅用于展示，不参与任何判定）。封停时长默认 1 小时，也可以设成永久。

---

## 判定机制

| 环节 | 做法 |
| --- | --- |
| 抓包 | raw socket `SIO_RCVALL` 抓本机入站 IPv4 包（TCP / UDP），无需驱动 |
| 计数 | 按「来源 IP + 服务端口」**累计**连接次数，`count >= max_attempts` 即封停 |
| 不是滑动窗口 | 计数只在条目空闲 10 分钟后回收归零。慢速爆破（间隔几十秒来一次）同样会被累计到阈值；窗口口径会漏掉这类来源 |
| 默认阈值 | RDP `3389` → 5 次；UDP `3389` → 5 次；Web `80/443` → 300 次（一次网页访问会开几十个连接，阈值低会秒封正常访客） |
| 白名单优先 | 白名单永远最高优先级，任何路径（自动封停、手动封停、重启恢复）都不会封停白名单 IP |
| 封停方式 | 写入 `PortGuard-Ban-<ip>` 防火墙规则；删除时只按精确规则名删自己的规则，**绝不**按 `remoteip` 批量删 |
| 失败不装成功 | 防火墙操作失败会上报错误、写日志并在面板显示差异，不会假装已封停 |

判定顺序固定为：**白名单 → 黑名单 → 保护端口 → 累计次数阈值 → 封停**。

---

## 功能一览

- **Web 控制面板**（`http://127.0.0.1:58080`，仅监听回环）：概览 / 当前连接 / 封停列表 / 设置 / 运行日志，支持中英双语界面（默认跟随服务器系统语言）
- **系统托盘**：打开面板、暂停保护、退出；控制台窗口默认隐藏
- **手动封停 / 解封**，白名单与黑名单（支持 `192.168.1.*`、`192.168.1.1-192.168.1.100`、CIDR）
- **端口与名单备注**：给每个端口 / 每条规则写一句「这是谁的」，封停记录里内联显示
- **抓包观测诊断**：面板直接告诉你某个端口到底有没有抓到包、包的标志是什么，用于分辨「没抓到」与「判定层丢掉了」
- **危险端口保护**（135 / 137 / 138 / 139 / 445）、**禁 Ping**、**开机自启**（注册为 Windows 服务）
- **RDP 客户端计算机名保护**：只放行白名单里的客户端名
- **IP 地理位置展示**（ip2region xdb），库缺失时显示「未知」，绝不影响判定
- **单文件部署**：前端资源经 `include_str!` 内嵌，运行时读不到磁盘资源也不影响；exe 内嵌 `requireAdministrator` 清单，双击即弹 UAC

---

## 快速开始

```bat
:: 1. 构建（自动使用 rust-toolchain.toml 里的 Rust 1.77.2）
build.bat            :: 菜单 [1] Release 构建，[8] 打包到 dist\（exe + 地理库）

:: 只出 64 位：target\release\PortGuard.exe
:: 只出 32 位：target\i686-pc-windows-msvc\release\PortGuard.exe
:: 两个一起出并改名（发布用）：dist\PortGuard.exe + dist\PortGuard_x32.exe
python tools\package_release.py

:: 2. 运行（需要管理员权限：raw socket 抓包与 netsh 防火墙都要求提权）
target\release\PortGuard.exe

:: 3. 打开面板
http://127.0.0.1:58080
```

exe 同目录即数据目录（绿色便携，不写注册表、不写系统目录）：

```text
config.toml                 # 配置
state/bans.json             # 封停记录（重启后恢复）
logs/portguard.log          # 运行日志
data/ip2region_v4.xdb       # IP 地理位置库（可选）
```

也可以在设置页改端口、阈值、白/黑名单后保存，配置立刻生效。

---

## 配置示例

```toml
# 普通 TCP 保护组：把 frp 穿透进来的内网 22 / 3306 也填在这里
[protect.tcp]
ports = [3389, 22, 3306]
max_attempts = 5

# 网页服务：阈值必须放宽，否则一次页面访问就会被误封
[protect.http]
ports = [80, 443]
max_attempts = 300

[protect.udp]
ports = [3389]
max_attempts = 5

[ban]
duration_seconds = 3600   # 封停 1 小时后自动解封
permanent = false         # 改 true 则永久封停

[lists]
whitelist = ["192.168.1.*", "1.2.3.4-1.2.3.10"]   # 永远不被封停
blacklist = []

[panel]
language = "auto"         # auto（跟随系统）/ zh / en
```

---

## 系统要求

| 项 | 说明 |
| --- | --- |
| 系统 | Windows 7 SP1 x64 / Server 2008 R2 / Server 2012 / Windows 10 / Windows 11 |
| 构建 | Rust **1.77.2**（最后一个官方支持 Win7 的版本），目标 `x86_64-pc-windows-msvc`（64 位）/ `i686-pc-windows-msvc`（32 位），两个目标都在 `rust-toolchain.toml` 里预声明 |
| 权限 | 管理员（抓包与防火墙操作都需要；非管理员时程序照常启动但不提供保护） |
| 运行库 | Win7 / 2008 R2 / 2012 若提示缺少 DLL，请安装 VC++ 2015-2022 运行库，或用 `build.bat` 菜单 [2] 静态 CRT 构建 |

---

## 安全与限制（如实说明）

- **面板无登录口令**：安全性完全依赖「只监听回环地址 + Host 校验 + Origin 校验」三道闸。
  不要把监听地址改成 `0.0.0.0`——那等于把封停权限开放给整个局域网。
- **判据是连接次数，不是登录失败次数**：PortGuard 在网络层看包，不解析业务协议，
  因此它不知道密码对不对。阈值要按业务常态设置：网页服务建议几百，RDP / SSH 用个位数。
- **云主机可能收不到入站包**：部分网卡 / 虚拟交换的混杂模式只放行本机发出的包。
  此时可让面板按「服务端应答（SYN+ACK）」统计连接（默认已开启），
  并用概览页的「抓包观测」确认到底收到了什么。
- **只统计 IPv4**：IPv6 连接不进统计。
- **只统计「目的地址是本机所选网卡」的入站包**：云主机做 DNAT 时要选中内网网卡
  （用 `netstat` 的 Local Address 列确认）。
- **旧版数据文件不再兼容**：`config.dat` / `BanData.bin` / `PortGuard.txt` 已永久放弃，
  程序不会读取或迁移它们。

---

## 项目结构

| crate | 职责 |
| --- | --- |
| `portguard-core` | 领域模型、配置、IP 规则、累计连接计数、封停状态机、规则引擎、`PortGuardApi` 契约 |
| `portguard-packet` | 网卡枚举（`GetAdaptersAddresses`）、raw socket 抓包（`SIO_RCVALL`）、IPv4/TCP/UDP 解析 |
| `portguard-firewall` | 全部 Windows 防火墙操作（`netsh advfirewall`），对外只暴露 `FirewallBackend` |
| `portguard-storage` | `config.toml` / `bans.json` 读写、日志落盘、路径解析 |
| `portguard-rdp` | RDP 客户端计算机名保护（会话枚举、策略判定） |
| `portguard-win` | Win32 系统集成：权限、单实例、托盘、时区、语言、浏览器、开机自启（Windows 服务）、控制台 |
| `portguard-geo` | IP 地理位置查询（ip2region xdb v3），**只用于展示** |
| `portguard-web` | 内嵌 Web 面板：资源内嵌、纯函数路由、HTTP 服务与安全校验 |
| `portguard-app` | 主程序：启动编排、运行时回路、`PortGuardApi` 实现 |

文档索引：

- [`docs/开发文档.md`](docs/开发文档.md) —— 项目总控规范（架构、判定逻辑、线程模型、阶段路线图）
- [`docs/behavior-spec.md`](docs/behavior-spec.md) —— 行为规格：判定流水线、封停状态机、不变式清单
- [`docs/web-ui-spec.md`](docs/web-ui-spec.md) —— 控制面板规格：页面结构、接口契约、安全边界
- [`docs/progress.md`](docs/progress.md) —— 各阶段完成度与测试数
- 各 crate 下的 `CLAUDE.md` —— 模块职责、对外接口、关键约束

---

## 开发

```bat
build.bat                      :: 交互菜单：构建 / 测试 / clippy / 格式化 / 打包
cargo test --workspace         :: 296 项测试（64 / 32 位目标下均通过）
cargo clippy --workspace --all-targets
python tools\package_release.py :: 一次产出 64 + 32 位 exe 到 dist\
```

## 使用
下载对应位数的exe文件后，再到`https://gitee.com/smartavs_01/ip2region/blob/master/data/ip2region_v4.xdb`下载数据库文件放到exe根目录运行即可，只需要`PortGuard.exe`和`ip2region_v4.xdb`两个文件即可正常运行。

32 位系统（或 32 位 Server 2008）请用 `PortGuard_x32.exe`；两种位数的 exe 功能完全一致，
差别只在进程位数（32 位版本同样能抓包、写防火墙规则）。

## 发布

发布产物由 `python tools\package_release.py` 生成到 `dist\`：`PortGuard.exe`（64 位）、
`PortGuard_x32.exe`（32 位）、`ip2region_v4.xdb`（可选）。上传到 GitHub Releases 的步骤如下：

1. 仓库页右侧 **Releases → Create a new release**（或 `https://github.com/wanvb/PortGuard/releases/new`）；
2. **Choose a tag** 填 `v0.1.0` → 点 **Create new tag: v0.1.0 on publish**；
3. 填 Release title（如 `PortGuard v0.1.0`），Description 里写清版本变更；
4. 把 `dist\PortGuard.exe` 与 `dist\PortGuard_x32.exe` **拖进**页面底部的
   "Attach binaries by dropping them here" 区域，等上传进度条走完（每个约 1 MB，很慢时重试）；
5. 点 **Publish release**。发布后每个文件的下载地址形如
   `https://github.com/wanvb/PortGuard/releases/download/v0.1.0/PortGuard.exe`。

后续版本重复上述步骤，只把 tag 换成 `v0.1.1`。注意：**Release 的附件是独立存储，
改完代码重新发布不会自动更新旧版本的附件**，必须新建 tag。

依赖精确锁定，`Cargo.lock` 入库；判定逻辑（白名单优先、累计次数口径、只删自己的防火墙规则）
都有对应测试守住，改动前请先读 `docs/behavior-spec.md` 与相关 crate 的 `CLAUDE.md`。
