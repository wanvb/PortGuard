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
:: 上传打开 https://github.com/wanvb/PortGuard/releases/new

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

---

## Linux 端同等防护（nftables，系统自带，无需装任何第三方软件）

Linux 上不需要 PortGuard：内核自带 `nf_tables`，用户态命令 `nft` 由发行版仓库提供。
下面这套规则用「同一来源 IP 每分钟新建连接数超限」判定爆破，超限即写入封禁集合、默认 72 小时后自动解封。
判定顺序与 Windows 版保持一致：**白名单 → 手动黑名单 → 自动封禁 → 保护端口计数 → 封停**。

| 项 | 要求 |
| --- | --- |
| 内核 | ≥ 4.10（用到动态集合 `flags dynamic` 与元素 `timeout`） |
| 发行版 | Debian 10+ / Ubuntu 20.04+ / CentOS 8+ / RHEL 8+ / Rocky / Alma |
| 命令 | `nft` ≥ 0.9.1（`nft --version` 查看），无需编译任何东西 |
| 不支持 | Debian 9 / Ubuntu 16.04 及更早（内核太老，动态集合不可用） |

### 步骤 1：安装 nftables

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install -y nftables

# CentOS / RHEL / Rocky / Alma
sudo dnf install -y nftables
```

### 步骤 2：写入配置文件

**动手前先做一件事**：把你现在远程管理用的 IP 填进下面 `whitelist` 里。
否则测试时可能把自己封在门外——被自己封掉只能上 IPMI / 云控制台 VNC 才能救回来。

```bash
sudo nano /etc/nftables.conf      # Debian / Ubuntu
sudo nano /etc/sysconfig/nftables.conf   # CentOS / RHEL 8+（该文件本身也是 nft 脚本）
```

整段复制下面的内容，**只需要改 `whitelist` 和 `protect_tcp_ports` 两处**：

```nft
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	# 用于短期统计新建连接次数
	set attempts {
		type ipv4_addr          # 定义集合元素的数据类型
		flags dynamic,timeout   # 设置集合的行为特性标志
		timeout 30s             # 设置集合元素的默认超时时间
	}

    # 手动封禁集合：支持网段 (interval)	auto-merge自动合并
	# sudo nft add element inet filter banned_manual { 1.2.3.0/24 timeout 1d }
	set banned_manual {
		type ipv4_addr
		flags interval, timeout
	}
	
	# 被封禁集合（可动态添加元素；元素可以带 timeout）
	set banned_auto {
		type ipv4_addr
		flags dynamic, timeout
		# 全局 timeout 不在这里设置（按需在 add element 时指定 timeout）
	}

	# 白名单集合：放在最前面，白名单 IP 直接 accept
	# 如果你希望白名单条目也能自动过期，可为其添加 flags dynamic, timeout
	set whitelist {
		type ipv4_addr
		# 如果想要白名单项自动过期，改为： flags dynamic, timeout
	}

	chain input {
		# 每秒只允许 2 个 ICMP 包，峰值（burst）允许 5 个
		icmp type echo-request limit rate 2/second burst 5 packets accept
		icmp type echo-request drop
		# 限制单IP对应端口同时连接数 每个IP同时发起的 HTTP(S) 连接不得超过 20 个
		#tcp dport { 80, 443 } add @conn_limit { ip saddr ct count over 20 } drop
		
		type filter hook input priority 0; policy accept;
		# 0. 白名单优先：在任何限速/封禁之前接受来自白名单的 IP
		ip saddr @whitelist accept
		# 丢弃手动封禁的 IP/网段
        ip saddr @banned_manual drop
		# 1. 丢弃已经在 banned_auto 集合中的 IP
		ip saddr @banned_auto drop
		# 2. 针对 SSH/自定义端口做限速新连接
		tcp dport {22,3306,5432,21868,21828,21859,21890,21891,21892,21528,21433} ct state new jump rate_limit_chain
		#21868 家里面HOME RDP端口
		#21528 笔记本RDP
		#21828 家里面工控机母鸡RDP
		#21859 家里广电堡垒虚拟机
		#21890 呼叫中心
		#21891 马超电脑
		#21892 马超电脑堡垒机虚拟机
		#21433 马超电脑虚拟机SQLSERVER
		#21432 pgsql
		
		#修改后重新加载规则命令sudo nft --check -f /etc/nftables.conf && sudo systemctl restart nftables.service
		
		# 3. 其他流量逻辑（按需调整） 示例：允许已建立/相关连接
		ct state established,related accept
		# 4. 默认（按策略改）
		# 例如：accept
	}

	chain rate_limit_chain {
		# 如果该IP在 attempts 集合中且超过每分钟3次连接，则加入 banned_auto（带 24h timeout）并丢弃 封24小时自动解封
		ip saddr @attempts limit rate over 3/minute add @banned_auto { ip saddr timeout 72h } drop

		# 否则更新 attempts 超时时间并接受连接
		update @attempts { ip saddr timeout 30s } accept
	}

	chain forward {
		type filter hook forward priority 0; policy accept; # 或将priority改为filter，但需明确策略
	}

	chain output {
		type filter hook output priority 0; policy accept; # 或将priority改为filter，但需明确策略
	}
}

```

### 步骤 3：校验语法并载入

```bash
# 只检查语法、不生效（有错会直接报行号）
sudo nft --check -f /etc/nftables.conf

# 检查通过后：立即载入 + 开机自启
sudo systemctl enable --now nftables
sudo nft -f /etc/nftables.conf
```

一条命令搞定（改完规则后每次都执行这句）：

```bash
sudo nft --check -f /etc/nftables.conf && sudo systemctl restart nftables
```

### 步骤 4：确认生效

```bash
sudo nft list ruleset                       # 完整规则
sudo nft list set inet filter banned_auto   # 当前被封的 IP
sudo nft list set inet filter whitelist     # 白名单
```

验证：**换一台机器**（不要用你刚加进白名单的管理机）连 10 次受保护端口：

```bash
for i in $(seq 1 10); do timeout 1 bash -c "</dev/tcp/目标IP/22"; done
```

回到服务器执行 `sudo nft list set inet filter banned_auto`，应能看到该来源 IP，并且它已连不上；
到达 timeout 后元素自动消失，无需人工解封。

### 步骤 5：日常运维命令

| 操作 | 命令 |
| --- | --- |
| 看谁被封了 | `sudo nft list table inet filter` |
| 解封一个 IP | `sudo nft delete element inet filter banned_auto { 58.16.16.162 }` |
| 手动封一个 IP（72h） | `sudo nft add element inet filter banned_auto { 1.2.3.4 }` |
| 手动封、1 小时后自动解 | `sudo nft add element inet filter banned_auto { 5.6.7.8 timeout 1h }` |
| 按网段封（长期） | `sudo nft add element inet filter banned_manual { 113.108.96.0/24 }` |
| 解封网段 | `sudo nft delete element inet filter banned_manual { 113.108.96.0/24 }` |
| 加白名单（永久） | `sudo nft add element inet filter whitelist { 1.2.3.4 }` |
| 加临时白名单（24h） | `sudo nft add element inet filter whitelist { 1.2.3.4 timeout 24h }` |
| 删白名单 | `sudo nft delete element inet filter whitelist { 1.2.3.4 }` |
| 全量回滚 | `sudo nft flush ruleset && sudo systemctl disable nftables` |

> `nft` 命令加的元素是**运行时**的，重启后只保留 `/etc/nftables.conf` 里写的那些。
> 需要长期生效的手动封禁，写进配置文件的 `elements = { ... }` 里。

### 步骤 6：可选加固

**① SYN cookies（防 SYN 半连接打爆服务器）**

```bash
sysctl -w net.ipv4.tcp_syncookies=1                                  # 立即生效
echo "net.ipv4.tcp_syncookies = 1" | sudo tee -a /etc/sysctl.conf    # 永久生效
```

**② ICMP 限速 / 禁 Ping**（粘到 input 链 `ip saddr @whitelist accept` 之后）

```nft
# 每秒只放行 2 个 ping、突发 5 个，超出的丢弃
ip protocol icmp icmp type echo-request limit rate 2/second burst 5 packets accept
ip protocol icmp icmp type echo-request drop

# 想彻底禁 Ping，只留下面这一行
# ip protocol icmp icmp type echo-request drop
```

**③ 单 IP 并发连接数上限**（防连接数耗尽，内核 ≥ 4.12；部分发行版该写法不生效，先注释保留）

```nft
# 集合区加：
# set conn_limit {
#     type ipv4_addr
#     flags dynamic
#     size 65536
# }
# input 链加：单 IP 对 80/443 的并发连接超过 50 就丢弃
# tcp dport { 80, 443 } ct state new add @conn_limit { ip saddr ct count over 50 } drop
```

**④ 全端口 SYN 洪水监控脚本（按 C 段封禁）**

```bash
sudo cat > /usr/local/bin/syn_block.sh <<'EOF'
#!/bin/bash
# 全端口 SYN 洪水监控：同一 C 段(/24)的 SYN_RECV 半连接数超过阈值，就封整个 /24
THRESHOLD=10         # 同一 C 段的半连接数阈值
BAN_TIME="12h"       # 封禁时长，到期由 nftables 自动解封
INTERVAL=120         # 检查间隔（秒）
SET="banned_manual"  # 封进手动封禁集合（支持网段）

while true; do
    mapfile -t NETS < <(ss -tan state syn-recv 2>/dev/null \
        | awk 'NR>1 {print $5}' | cut -d: -f1 | grep -E '^[0-9]+\.' \
        | cut -d. -f1,2,3 | sort | uniq -c \
        | awk -v t="$THRESHOLD" '$1 > t {print $2}')

    for P in "${NETS[@]}"; do
        [[ $P =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        NET="$P.0/24"
        if ! nft list set inet filter "$SET" 2>/dev/null | grep -q "$NET"; then
            logger -t syn_block "封禁 $NET $BAN_TIME（SYN 半连接数超过 $THRESHOLD）"
            echo "[$(date '+%F %T')] 封禁 $NET，时长 $BAN_TIME"
            nft add element inet filter "$SET" "{ $NET timeout $BAN_TIME }"
        fi
    done
    sleep "$INTERVAL"
done
EOF
sudo chmod +x /usr/local/bin/syn_block.sh
```

用 systemd 常驻（推荐）：

```bash
sudo cat > /etc/systemd/system/syn_block.service <<'EOF'
[Unit]
Description=SYN flood monitor (nftables C-segment ban)
After=nftables.service

[Service]
Type=simple
ExecStart=/usr/local/bin/syn_block.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now syn_block
```

临时跑一次也可以：`sudo nohup /usr/local/bin/syn_block.sh > /var/log/syn_block.log 2>&1 &`

### 注意事项与回滚

- **`flush ruleset` 是全局的**：会一并清掉 Docker / firewalld / K8s 写进去的规则，容器会瞬间断网。
  跑容器的机器请把表名 `inet filter` 改成你自己独有的 `table inet portguard`，并删掉 `flush ruleset` 那一行
  （后续所有命令里的 `filter` 同步改成 `portguard`）。
- **只保护 IPv4**：要管 IPv6 得再建一套 `type ipv6_addr` 的集合并用 `ip6 saddr` 匹配。
- **看的是到达本机的入站包**：服务经 DNAT / 端口映射（Docker `-p`、frp 服务端）进来时，
  `protect_tcp_ports` 里要填**主机侧映射后的端口**。
- **判定口径与 Windows 版不同**：这里是**速率窗口**（每分钟新建连接数），PortGuard 是**累计次数**。
  慢速爆破（每隔几十秒连一次、始终不触发每分钟 3 次）不会触发本规则——这类来源靠步骤 6 的
  C 段 SYN 脚本兜底，或把 `limit rate over 3/minute` 调得更严。
- **被自己锁在门外时的救法**：本地控制台 / IPMI / 云控制台 VNC 登录后执行
  `sudo nft flush ruleset && sudo systemctl disable nftables` 即可恢复。
- **Linux 版没有的东西**：没有 Web 面板、没有 IP 归属地展示、不看 RDP 客户端计算机名，
  它只做「按来源 IP 的连接速率封禁」这一件事。


